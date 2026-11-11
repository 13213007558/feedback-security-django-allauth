import copy
from unittest.mock import patch

from django.contrib.auth import get_user, get_user_model
from django.contrib.auth.models import AnonymousUser
from django.urls import reverse

import pytest

from allauth.account.models import EmailAddress
from allauth.core import context
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.helpers import complete_social_login
from allauth.socialaccount.models import SocialAccount


@pytest.fixture
def email_auth_settings(settings):
    settings.ACCOUNT_EMAIL_REQUIRED = True
    settings.ACCOUNT_UNIQUE_EMAIL = True
    settings.ACCOUNT_USERNAME_REQUIRED = False
    settings.ACCOUNT_LOGIN_METHODS = {"email"}
    settings.ACCOUNT_EMAIL_VERIFICATION = "mandatory"
    settings.SOCIALACCOUNT_AUTO_SIGNUP = True
    settings.SOCIALACCOUNT_STORE_TOKENS = True
    return settings


def enable_email_authentication(settings, scope, provider_id="unittest-server"):
    """Grants trust at the given scope: "off", "app", "provider" or "global"."""
    settings.SOCIALACCOUNT_EMAIL_AUTHENTICATION = False
    if scope == "off":
        return
    if scope == "global":
        settings.SOCIALACCOUNT_EMAIL_AUTHENTICATION = True
        return
    providers = copy.deepcopy(settings.SOCIALACCOUNT_PROVIDERS)
    if scope == "provider":
        providers["openid_connect"]["EMAIL_AUTHENTICATION"] = True
    elif scope == "app":
        for app in providers["openid_connect"]["APPS"]:
            if app["provider_id"] == provider_id:
                app["settings"]["email_authentication"] = True
    else:
        raise ValueError(scope)
    settings.SOCIALACCOUNT_PROVIDERS = providers


def complete_login_capture_signals(request, sociallogin):
    with context.request_context(request):
        with patch(
            "allauth.socialaccount.signals.social_account_added.send"
        ) as added_signal:
            with patch(
                "allauth.socialaccount.signals.social_account_updated.send"
            ) as updated_signal:
                response = complete_social_login(request, sociallogin)
    return response, added_signal, updated_signal


@pytest.mark.parametrize("auto_connect", [False, True])
@pytest.mark.parametrize("provider_email_verified", [False, True])
@pytest.mark.parametrize("scope", ["off", "app", "provider", "global"])
def test_email_authentication_trust_matrix(
    db,
    email_auth_settings,
    user_factory,
    sociallogin_factory,
    request_factory,
    mailoutbox,
    scope,
    provider_email_verified,
    auto_connect,
):
    """Matrix over (trust scope) x (provider email claim) x (auto connect).

    A login into the existing local account is only expected when the site
    explicitly trusts the provider's email claim (scope != "off") AND the
    provider actually claims the email is verified.
    """
    enable_email_authentication(email_auth_settings, scope)
    email_auth_settings.SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = auto_connect

    user = user_factory()
    sociallogin = sociallogin_factory(
        email=user.email,
        provider="unittest-server",
        email_verified=provider_email_verified,
        with_token=True,
    )
    request = request_factory.get("/")
    request.user = AnonymousUser()
    resp, added_signal, updated_signal = complete_login_capture_signals(
        request, sociallogin
    )

    authenticated = scope != "off" and provider_email_verified
    connected = authenticated and auto_connect
    if authenticated:
        assert get_user(request) == user
        assert resp["location"] == "/accounts/profile/"
    else:
        assert not get_user(request).is_authenticated
        assert resp["location"] == reverse("account_email_verification_sent")
    assert get_user_model().objects.count() == 1
    assert SocialAccount.objects.filter(user=user).exists() == connected
    assert added_signal.called == connected
    assert not updated_signal.called


@pytest.mark.parametrize(
    "provider_id,authenticated",
    [("unittest-server", True), ("other-server", False)],
)
def test_email_authentication_is_scoped_per_app(
    db,
    email_auth_settings,
    user_factory,
    sociallogin_factory,
    request_factory,
    mailoutbox,
    provider_id,
    authenticated,
):
    """Both apps belong to the same provider and hand over the same verified
    email claim, yet only the app explicitly marked with
    ``email_authentication`` is trusted.
    """
    enable_email_authentication(email_auth_settings, "app")
    email_auth_settings.SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = True

    user = user_factory()
    sociallogin = sociallogin_factory(
        email=user.email,
        provider=provider_id,
        email_verified=True,
    )
    request = request_factory.get("/")
    request.user = AnonymousUser()
    resp, added_signal, updated_signal = complete_login_capture_signals(
        request, sociallogin
    )

    assert (get_user(request) == user) == authenticated
    assert SocialAccount.objects.filter(user=user).exists() == authenticated
    assert added_signal.called == authenticated
    assert not updated_signal.called


class VetoingAdapter(DefaultSocialAccountAdapter):
    """Settings grant trust, the adapter vetoes it."""

    def can_authenticate_by_email(self, login, email):
        return False


class GrantingAdapter(DefaultSocialAccountAdapter):
    """Settings grant no trust at all, the adapter does."""

    def can_authenticate_by_email(self, login, email):
        return True


@pytest.mark.parametrize(
    "adapter_class,authenticated",
    [
        (VetoingAdapter, False),
        (GrantingAdapter, True),
    ],
)
def test_email_authentication_adapter_override(
    db,
    email_auth_settings,
    user_factory,
    sociallogin_factory,
    request_factory,
    mailoutbox,
    adapter_class,
    authenticated,
):
    """The adapter has the final say, in both directions."""
    email_auth_settings.SOCIALACCOUNT_EMAIL_AUTHENTICATION = True
    email_auth_settings.SOCIALACCOUNT_ADAPTER = f"{__name__}.{adapter_class.__name__}"
    email_auth_settings.SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = True

    user = user_factory()
    sociallogin = sociallogin_factory(
        email=user.email,
        provider="unittest-server",
        email_verified=True,
    )
    request = request_factory.get("/")
    request.user = AnonymousUser()
    resp, added_signal, updated_signal = complete_login_capture_signals(
        request, sociallogin
    )

    assert (get_user(request) == user) == authenticated
    assert SocialAccount.objects.filter(user=user).exists() == authenticated
    assert added_signal.called == authenticated
    assert not updated_signal.called


def test_email_authentication_matches_secondary_email(
    db,
    email_auth_settings,
    user_factory,
    email_factory,
    sociallogin_factory,
    request_factory,
    mailoutbox,
):
    """The provider returns the secondary (non-primary) email of an existing
    user; that user is logged in.
    """
    enable_email_authentication(email_auth_settings, "global")
    email_auth_settings.SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = True

    user = user_factory()
    secondary_email = email_factory(username="secondary")
    EmailAddress.objects.create(
        user=user, email=secondary_email, verified=True, primary=False
    )
    sociallogin = sociallogin_factory(
        email=secondary_email,
        provider="unittest-server",
        email_verified=True,
    )
    request = request_factory.get("/")
    request.user = AnonymousUser()
    resp, added_signal, updated_signal = complete_login_capture_signals(
        request, sociallogin
    )

    assert get_user(request) == user
    assert SocialAccount.objects.filter(user=user).exists()
    assert added_signal.called
    assert not updated_signal.called
    # The primary email address is left untouched.
    user.refresh_from_db()
    assert EmailAddress.objects.get(user=user, primary=True).email == user.email


def test_email_authentication_to_unverified_local_address_wipes_password(
    db,
    email_auth_settings,
    user_factory,
    email_factory,
    sociallogin_factory,
    request_factory,
    mailoutbox,
):
    """The provider's verified claim matches a local email address that was
    never verified locally: the login proceeds, but the pre-existing password
    (potentially set by an attacker) is wiped.
    """
    enable_email_authentication(email_auth_settings, "global")

    user = user_factory()
    secondary_email = email_factory(username="secondary")
    EmailAddress.objects.create(
        user=user, email=secondary_email, verified=False, primary=False
    )
    assert user.has_usable_password()
    sociallogin = sociallogin_factory(
        email=secondary_email,
        provider="unittest-server",
        email_verified=True,
    )
    request = request_factory.get("/")
    request.user = AnonymousUser()
    resp, added_signal, updated_signal = complete_login_capture_signals(
        request, sociallogin
    )

    assert get_user(request) == user
    user.refresh_from_db()
    assert not user.has_usable_password()


def test_email_authentication_skips_unverified_provider_emails(
    db,
    email_auth_settings,
    user_factory,
    email_factory,
    sociallogin_factory,
    request_factory,
    mailoutbox,
):
    """The provider hands over multiple emails; only the ones it marks as
    verified are consulted for authentication.
    """
    enable_email_authentication(email_auth_settings, "global")
    email_auth_settings.SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = True

    user = user_factory()
    unverified_claim = email_factory(username="unverified")
    sociallogin = sociallogin_factory(
        email=unverified_claim,
        provider="unittest-server",
        email_verified=False,
    )
    sociallogin.email_addresses.append(
        EmailAddress(email=user.email, verified=True, primary=False)
    )
    request = request_factory.get("/")
    request.user = AnonymousUser()
    resp, added_signal, updated_signal = complete_login_capture_signals(
        request, sociallogin
    )

    assert get_user(request) == user
    assert SocialAccount.objects.filter(user=user).exists()
    assert added_signal.called
    assert not updated_signal.called
