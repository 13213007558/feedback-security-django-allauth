from http import HTTPStatus
from unittest.mock import ANY

from django.contrib.sessions.backends.db import SessionStore
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import include, path, reverse

import pytest
from pytest_django.asserts import assertTemplateUsed

from allauth import app_settings as allauth_settings
from allauth.account.adapter import DefaultAccountAdapter, get_adapter
from allauth.account.authentication import get_authentication_records
from allauth.account.decorators import reauthentication_required
from allauth.account.internal.flows import reauthentication
from allauth.account.internal.flows.reauthentication import STATE_SESSION_KEY
from allauth.account.models import EmailAddress
from allauth.core.exceptions import ReauthenticationRequired


class ReauthenticationRequiredAdapter(DefaultAccountAdapter):
    def is_reauthentication_required(self, *, app, **kwargs):
        return app == "allauth.account"


resumed_actions = []


@reauthentication_required
def protected_view(request):
    resumed_actions.append((request.user, dict(request.POST)))
    return HttpResponse("protected-ok")


urlpatterns = [
    path("protected/", protected_view),
    path("accounts/", include("allauth.urls")),
]


def resume_callback(request, state):
    resumed_actions.append((request.user, state))
    return HttpResponseRedirect("/done/")


@pytest.mark.parametrize(
    "with_totp,with_password,expected_method_urlnames",
    [
        (False, True, ["account_reauthenticate"]),
        (True, True, ["account_reauthenticate", "mfa_reauthenticate"]),
        (True, False, ["mfa_reauthenticate"]),
    ],
)
def test_user_with_mfa_only(
    user_factory, with_totp, with_password, expected_method_urlnames, client
):
    if not allauth_settings.MFA_ENABLED and with_totp:
        return
    user = user_factory(with_totp=with_totp, password=None if with_password else "!")
    assert user.has_usable_password() == with_password
    client.force_login(user)
    methods = get_adapter().get_reauthentication_methods(user)
    assert len(methods) == len(expected_method_urlnames)
    assert {m["url"] for m in methods} == set(map(reverse, expected_method_urlnames))
    for urlname in ["account_reauthenticate", "mfa_reauthenticate"]:
        if urlname == "mfa_reauthenticate" and not allauth_settings.MFA_ENABLED:
            continue
        resp = client.get(f"{reverse(urlname)}?next=/foo")
        if urlname in expected_method_urlnames:
            assert resp.status_code == HTTPStatus.OK
        else:
            assert resp.status_code == HTTPStatus.FOUND
            assert "next=%2Ffoo" in resp["location"]


def test_reauthentication(settings, auth_client, user, user_password):
    settings.ACCOUNT_REAUTHENTICATION_REQUIRED = True
    resp = auth_client.post(
        reverse("account_email"),
        {"action_add": "", "email": "john3@example.org"},
    )
    assert resp["location"].startswith(reverse("account_reauthenticate"))
    resp = auth_client.get(reverse("account_reauthenticate"))
    assertTemplateUsed(resp, "account/reauthenticate.html")
    resp = auth_client.post(
        reverse("account_reauthenticate"), data={"password": user_password}
    )
    assert resp.status_code == HTTPStatus.FOUND
    resp = auth_client.post(
        reverse("account_email"),
        {"action_add": "", "email": "john3@example.org"},
    )
    assert resp["location"].startswith(reverse("account_email"))
    methods = get_authentication_records(resp.wsgi_request, user)
    assert methods[-1] == {
        "method": "password",
        "at": ANY,
        "reauthenticated": True,
    }


def test_reauthentication_required_decorator_is_enabled_by_default(settings, rf, user):
    settings.ACCOUNT_REAUTHENTICATION_REQUIRED = False
    request = rf.post("/")
    request.user = user
    request.session = {}

    @reauthentication_required
    def view(request):
        raise AssertionError("The protected view must not be called")

    with pytest.raises(ReauthenticationRequired):
        view(request)


def test_adapter_can_require_reauthentication(settings, auth_client):
    settings.ACCOUNT_REAUTHENTICATION_REQUIRED = False
    settings.ACCOUNT_ADAPTER = (
        "tests.apps.account.test_reauthentication." "ReauthenticationRequiredAdapter"
    )

    resp = auth_client.post(
        reverse("account_email"),
        {"action_add": "", "email": "reauthenticate@example.org"},
    )

    assert not EmailAddress.objects.filter(email="reauthenticate@example.org").exists()
    assert resp["location"].startswith(reverse("account_reauthenticate"))


def test_failed_reauthentication_keeps_action_pending(
    settings, auth_client, user_password
):
    settings.ACCOUNT_REAUTHENTICATION_REQUIRED = True
    resp = auth_client.post(
        reverse("account_email"),
        {"action_add": "", "email": "pending@example.org"},
    )
    assert resp["location"].startswith(reverse("account_reauthenticate"))
    resp = auth_client.post(resp["location"], {"password": "wrong-password"})
    assert resp.status_code == HTTPStatus.OK
    assert not EmailAddress.objects.filter(email="pending@example.org").exists()
    # The stashed action is retained so the user can retry.
    assert STATE_SESSION_KEY in auth_client.session
    resp = auth_client.post(
        f"{reverse('account_reauthenticate')}?next=/accounts/email/",
        {"password": user_password},
    )
    assert resp.status_code == HTTPStatus.FOUND
    assert EmailAddress.objects.filter(email="pending@example.org").exists()


def test_suspended_request_not_resumed_for_other_user(
    settings, client, user_factory, user_password
):
    """Tab A stashes a sensitive action; in another tab the user logs out and
    logs in as a different user. Resuming must not execute the old action."""
    settings.ACCOUNT_REAUTHENTICATION_REQUIRED = True
    user_a = user_factory()
    user_b = user_factory()
    client.force_login(user_a)
    resp = client.post(
        reverse("account_email"),
        {"action_add": "", "email": "suspended@example.org"},
    )
    assert resp["location"].startswith(reverse("account_reauthenticate"))
    assert STATE_SESSION_KEY in client.session

    client.post(reverse("account_logout"))
    client.force_login(user_b)
    resp = client.post(reverse("account_reauthenticate"), {"password": user_password})
    assert resp.status_code == HTTPStatus.FOUND
    assert not EmailAddress.objects.filter(email="suspended@example.org").exists()


def test_suspended_request_from_anonymous_session_not_resumed_after_login(
    settings, client, user_factory, user_password
):
    """An anonymous POST is stashed by the middleware. The session is cycled
    (not flushed) on login, so the stash carries over. Resuming after
    reauthentication must not replay the anonymous action under the now
    logged-in user."""
    settings.ROOT_URLCONF = "tests.apps.account.test_reauthentication"
    resumed_actions.clear()
    user = user_factory()
    resp = client.post("/protected/", {"field": "value"})
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"].startswith(reverse("account_login"))
    assert STATE_SESSION_KEY in client.session

    client.force_login(user)
    resp = client.post(
        f"{reverse('account_reauthenticate')}?next=/protected/",
        {"password": user_password},
    )
    assert resp.status_code == HTTPStatus.FOUND
    assert resumed_actions == []


def test_suspended_request_resumed_for_same_user(settings, client, user, user_password):
    settings.ROOT_URLCONF = "tests.apps.account.test_reauthentication"
    resumed_actions.clear()
    client.force_login(user)
    resp = client.post("/protected/", {"field": "value"})
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"].startswith(reverse("account_reauthenticate"))
    resp = client.post(resp["location"], {"password": user_password})
    assert resumed_actions == [(user, {"field": ["value"]})]


def test_suspended_request_resumed_after_session_rotation(
    settings, client, user, user_password
):
    """Session key rotation (e.g. on login) retains session data; resuming
    must still work for the same user."""
    settings.ROOT_URLCONF = "tests.apps.account.test_reauthentication"
    resumed_actions.clear()
    client.force_login(user)
    resp = client.post("/protected/", {"field": "value"})
    assert STATE_SESSION_KEY in client.session
    session = client.session
    session.cycle_key()
    session.save()
    client.cookies[settings.SESSION_COOKIE_NAME] = session.session_key
    resp = client.post(
        f"{reverse('account_reauthenticate')}?next=/protected/",
        {"password": user_password},
    )
    assert resumed_actions == [(user, {"field": ["value"]})]


def test_duplicate_resume_submission_executes_action_once(
    settings, auth_client, user, user_password
):
    settings.ACCOUNT_REAUTHENTICATION_REQUIRED = True
    resp = auth_client.post(
        reverse("account_email"),
        {"action_add": "", "email": "once@example.org"},
    )
    assert resp["location"].startswith(reverse("account_reauthenticate"))
    reauthenticate_url = resp["location"]
    for _ in range(2):
        resp = auth_client.post(reauthenticate_url, {"password": user_password})
        assert resp.status_code == HTTPStatus.FOUND
    assert (
        EmailAddress.objects.filter(email="once@example.org", user=user).count() == 1
    )


def test_stashed_callback_is_bound_to_initiating_user(
    request_factory, user_factory, db
):
    resumed_actions.clear()
    user_a = user_factory()
    user_b = user_factory()
    request = request_factory.get("/")
    request.session = SessionStore()

    request.user = user_a
    reauthentication.stash_and_reauthenticate(
        request,
        {"some": "state"},
        "tests.apps.account.test_reauthentication.resume_callback",
    )
    response = reauthentication.resume_request(request)
    assert response["location"] == "/done/"
    assert resumed_actions == [(user_a, {"some": "state"})]

    # The session (and its stash) survives, but the principal changed.
    resumed_actions.clear()
    request.user = user_a
    reauthentication.stash_and_reauthenticate(
        request,
        {"some": "state"},
        "tests.apps.account.test_reauthentication.resume_callback",
    )
    request.user = user_b
    response = reauthentication.resume_request(request)
    assert response is None
    assert resumed_actions == []
