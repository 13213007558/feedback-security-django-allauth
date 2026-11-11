from contextlib import contextmanager
from http import HTTPStatus
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.urls import reverse

import pytest
from pytest_django.asserts import assertTemplateUsed

from allauth.account.models import EmailAddress
from allauth.core import context
from allauth.socialaccount import signals
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.forms import DisconnectForm
from allauth.socialaccount.internal import flows
from allauth.socialaccount.models import SocialAccount
from allauth.socialaccount.providers.base.constants import AuthProcess


@pytest.mark.parametrize("reauthentication_required", [False, True])
def test_disconnect(
    auth_client,
    user,
    settings,
    mailoutbox,
    reauthentication_required,
    django_capture_on_commit_callbacks,
):
    settings.ACCOUNT_EMAIL_NOTIFICATIONS = True
    settings.ACCOUNT_REAUTHENTICATION_REQUIRED = reauthentication_required
    account_to_del = SocialAccount.objects.create(
        uid="123", provider="other-server", user=user
    )
    account_to_keep = SocialAccount.objects.create(
        uid="456", provider="other-server", user=user
    )
    resp = auth_client.get(reverse("socialaccount_connections"))
    assertTemplateUsed(resp, "socialaccount/connections.html")
    with django_capture_on_commit_callbacks(execute=True):
        resp = auth_client.post(
            reverse("socialaccount_connections"), {"account": account_to_del.pk}
        )
    if reauthentication_required:
        assert SocialAccount.objects.filter(pk=account_to_del.pk).exists()
        assert SocialAccount.objects.filter(pk=account_to_keep.pk).exists()
    else:
        assert not SocialAccount.objects.filter(pk=account_to_del.pk).exists()
        assert SocialAccount.objects.filter(pk=account_to_keep.pk).exists()
        assert len(mailoutbox) == 1
        assert mailoutbox[0].subject == "[example.com] Third-Party Account Disconnected"


def test_connect_with_reauthentication(
    auth_client, user, provider_callback_response, settings, user_password
):
    settings.ACCOUNT_REAUTHENTICATION_REQUIRED = True
    resp = provider_callback_response(auth_client, process="connect")
    assert not SocialAccount.objects.filter(user=user).exists()
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == reverse("account_reauthenticate")
    resp = auth_client.post(resp["location"], {"password": user_password})
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == reverse("socialaccount_connections")
    assert SocialAccount.objects.filter(user=user).exists()


def test_connect(
    auth_client, user, provider_callback_response, settings, user_password, mailoutbox
):
    settings.ACCOUNT_EMAIL_NOTIFICATIONS = True
    settings.ACCOUNT_REAUTHENTICATION_REQUIRED = False
    resp = provider_callback_response(auth_client, process="connect")
    assert resp.status_code == HTTPStatus.FOUND
    assert SocialAccount.objects.filter(user=user).exists()
    assert resp["location"] == reverse("socialaccount_connections")
    assert len(mailoutbox) == 1
    assert mailoutbox[0].subject == "[example.com] Third-Party Account Connected"


@pytest.mark.parametrize(
    "email_authentication,account_exists, expected_action",
    [
        (False, False, "added"),
        (False, True, "updated"),
        (True, False, "added"),
        (True, True, "updated"),
    ],
)
def test_connect_vs_email_authentication(
    request_factory,
    sociallogin_factory,
    user,
    settings,
    email_authentication,
    account_exists,
    expected_action,
):
    settings.SOCIALACCOUNT_EMAIL_AUTHENTICATION = email_authentication
    sociallogin = sociallogin_factory(email=user.email, provider="unittest-server")
    if account_exists:
        account = sociallogin.account
        account.user = user
        account.save()

    sociallogin.state["process"] = AuthProcess.CONNECT
    request = request_factory.get("/")
    request.user = user
    with patch(
        "allauth.account.adapter.DefaultAccountAdapter.add_message"
    ) as add_message:
        flows.login.complete_login(request, sociallogin)
        assert add_message.call_args[1]["message_context"]["action"] == expected_action
    assert SocialAccount.objects.filter(user=user, uid=sociallogin.account.uid).exists()


def disconnect_form(rf, user, account):
    request = rf.post(reverse("socialaccount_connections"))
    request.user = user
    return DisconnectForm(data={"account": account.pk}, request=request)


@contextmanager
def record_removed():
    removed = []

    def on_removed(sender, **kwargs):
        removed.append(kwargs["socialaccount"])

    signals.social_account_removed.connect(on_removed)
    try:
        yield removed
    finally:
        signals.social_account_removed.disconnect(on_removed)


def test_disconnect_race_cannot_lock_out_user(
    rf, user, settings, mailoutbox, django_capture_on_commit_callbacks
):
    """
    A user with two social accounts, no usable password and no verified email
    address issues two concurrent disconnect requests. Both pass the initial
    validation, as each still sees the other account. The locked re-validation
    at delete time must ensure only one request wins, so that the user keeps
    at least one usable login method.
    """
    settings.ACCOUNT_EMAIL_NOTIFICATIONS = True
    settings.ACCOUNT_EMAIL_VERIFICATION = "mandatory"
    user.set_unusable_password()
    user.save()
    EmailAddress.objects.filter(user=user).update(verified=False)
    account_to_del = SocialAccount.objects.create(
        uid="123", provider="other-server", user=user
    )
    account_to_keep = SocialAccount.objects.create(
        uid="456", provider="other-server", user=user
    )
    form1 = disconnect_form(rf, user, account_to_del)
    form2 = disconnect_form(rf, user, account_to_keep)
    # Controlled interleaving: both requests validate before either deletes.
    assert form1.is_valid()
    assert form2.is_valid()
    with record_removed() as removed:
        with patch("allauth.account.adapter.DefaultAccountAdapter.add_message"):
            with context.request_context(form1.request):
                with django_capture_on_commit_callbacks(execute=True):
                    form1.save()
                    with pytest.raises(ValidationError):
                        form2.save()
    assert not SocialAccount.objects.filter(pk=account_to_del.pk).exists()
    assert SocialAccount.objects.filter(pk=account_to_keep.pk).exists()
    # The losing request did not emit a success signal or notification.
    assert len(removed) == 1
    assert len(mailoutbox) == 1


@pytest.mark.parametrize(
    "usable_password,verified_email",
    [
        # A usable password is a remaining login method.
        (True, False),
        # A verified email address allows recovery via password reset.
        (False, True),
    ],
)
def test_disconnect_race_allowed_when_login_or_recovery_remains(
    rf,
    user,
    settings,
    mailoutbox,
    django_capture_on_commit_callbacks,
    usable_password,
    verified_email,
):
    settings.ACCOUNT_EMAIL_NOTIFICATIONS = True
    if not usable_password:
        user.set_unusable_password()
        user.save()
    EmailAddress.objects.filter(user=user).update(verified=verified_email)
    account1 = SocialAccount.objects.create(
        uid="123", provider="other-server", user=user
    )
    account2 = SocialAccount.objects.create(
        uid="456", provider="other-server", user=user
    )
    form1 = disconnect_form(rf, user, account1)
    form2 = disconnect_form(rf, user, account2)
    assert form1.is_valid()
    assert form2.is_valid()
    with record_removed() as removed:
        with patch("allauth.account.adapter.DefaultAccountAdapter.add_message"):
            with context.request_context(form1.request):
                with django_capture_on_commit_callbacks(execute=True):
                    form1.save()
                    form2.save()
    assert not SocialAccount.objects.filter(user=user).exists()
    assert len(removed) == 2
    assert len(mailoutbox) == 2


def test_disconnect_respects_adapter_validation_at_delete_time(
    rf, user, settings, mailoutbox, django_capture_on_commit_callbacks
):
    """
    Custom adapter validation must run against the locked database state at
    delete time, not only during form validation. If the adapter vetoes the
    disconnect there, no success signal or notification may be emitted.
    """
    settings.ACCOUNT_EMAIL_NOTIFICATIONS = True
    account1 = SocialAccount.objects.create(
        uid="123", provider="other-server", user=user
    )
    SocialAccount.objects.create(uid="456", provider="other-server", user=user)
    form = disconnect_form(rf, user, account1)
    calls = 0

    def veto_at_delete_time(self, account, accounts):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise ValidationError("vetoed")

    with record_removed() as removed:
        with patch.object(
            DefaultSocialAccountAdapter,
            "validate_disconnect",
            veto_at_delete_time,
        ):
            assert form.is_valid()
            with django_capture_on_commit_callbacks(execute=True):
                with pytest.raises(ValidationError):
                    form.save()
    assert calls == 2
    assert SocialAccount.objects.filter(pk=account1.pk).exists()
    assert removed == []
    assert len(mailoutbox) == 0


def test_disconnect_view_handles_delete_time_validation_failure(
    auth_client, user, settings
):
    account_to_del = SocialAccount.objects.create(
        uid="123", provider="other-server", user=user
    )
    SocialAccount.objects.create(uid="456", provider="other-server", user=user)
    with patch(
        "allauth.socialaccount.internal.flows.connect.disconnect",
        side_effect=ValidationError("raced"),
    ):
        resp = auth_client.post(
            reverse("socialaccount_connections"), {"account": account_to_del.pk}
        )
    assert resp.status_code == HTTPStatus.OK
    assert resp.context["form"].errors
    assert SocialAccount.objects.filter(pk=account_to_del.pk).exists()
