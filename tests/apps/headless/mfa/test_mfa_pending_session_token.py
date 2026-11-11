"""
End-to-end verification of what the headless ``session_token`` is actually
worth while a password login is stuck in the MFA stage.

Scenario under test
====================
The frontend receives ``meta.session_token`` from the password login response
and might mistake "having a session token" for "login is complete". These tests
pin down, over real HTTP roundtrips through the headless API, that:

* the session token handed out mid-flow only identifies an *anonymous* session
  holding a pending ``mfa_authenticate`` stage;
* it cannot reach any authenticated endpoint and no access token is ever
  issued for it (both the default session strategy and the JWT strategy);
* the MFA confirm endpoint cannot be advanced by repeating it without a valid
  code, nor by presenting another session's token;
* expired / destroyed challenges and unknown tokens fail deterministically;
* only the final successful MFA confirm produces an authenticated session.

Only the ``app`` client is exercised: session tokens are an app-client concept
(``Client.APP``), see ``sessionkit.expose_session_token``.
"""

from http import HTTPStatus

import pytest

from allauth.account.internal.stagekit import LOGIN_SESSION_KEY
from allauth.headless.constants import Flow
from allauth.headless.internal import sessionkit


@pytest.fixture(autouse=True)
def app_only(headless_client):
    if headless_client != "app":
        pytest.skip("session tokens are only exposed to the app client")


pytestmark = pytest.mark.django_db


LOGIN = "headless:account:login"
CURRENT_SESSION = "headless:account:current_session"
CHANGE_PASSWORD = "headless:account:change_password"
MANAGE_TOTP = "headless:mfa:manage_totp"
MFA_AUTHENTICATE = "headless:mfa:authenticate"
TOKEN_REFRESH = "headless:tokens:refresh"


def _login_with_password(client, headless_reverse, user, password):
    return client.post(
        headless_reverse(LOGIN),
        data={"username": user.username, "password": password},
        content_type="application/json",
    )


def _mfa_confirm(client, headless_reverse, code="bad"):
    return client.post(
        headless_reverse(MFA_AUTHENTICATE),
        data={"code": code},
        content_type="application/json",
    )


def _pending_flow(resp):
    flows = resp.json()["data"]["flows"]
    pending = [f for f in flows if f.get("is_pending")]
    assert len(pending) == 1
    return pending[0]


def _assert_anonymous(resp):
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    body = resp.json()
    assert body["meta"]["is_authenticated"] is False
    assert "user" not in body["data"]
    assert "access_token" not in body["meta"]
    return body


@pytest.fixture
def mfa_pending(app_client, headless_reverse, user_with_totp, user_password):
    """Password verified, MFA not completed. Returns (client, login_response)."""
    resp = _login_with_password(
        app_client, headless_reverse, user_with_totp, user_password
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert app_client.session_token, "login response must expose a session token"
    return app_client, resp


# ---------------------------------------------------------------------------
# 1. Login response: password OK, MFA pending
# ---------------------------------------------------------------------------
def test_login_response_is_pending_not_authenticated(
    mfa_pending, headless_reverse
):
    client, resp = mfa_pending
    body = resp.json()

    # The frontend gets a session token, but NOT an access token and no user.
    assert body["status"] == HTTPStatus.UNAUTHORIZED
    assert body["meta"] == {
        "is_authenticated": False,
        "session_token": client.session_token,
    }
    assert "access_token" not in body["meta"]
    assert "user" not in body["data"]

    flow = _pending_flow(resp)
    assert flow == {"id": Flow.MFA_AUTHENTICATE, "is_pending": True, "types": ["totp"]}

    # The session behind the token really is anonymous: no SESSION_KEY, only the
    # stashed, not-yet-completed Login object.
    session = sessionkit.session_store(client.session_token)
    assert "_auth_user_id" not in session
    assert LOGIN_SESSION_KEY in session


def test_session_token_alone_cannot_reach_protected_endpoints(
    mfa_pending, headless_reverse
):
    """The mid-flow token must not be accepted as a completed login anywhere."""
    client, _ = mfa_pending

    # GET /auth/session -> anonymous AuthenticationResponse (401), still pending
    resp = client.get(headless_reverse(CURRENT_SESSION))
    body = _assert_anonymous(resp)
    assert _pending_flow(resp)["id"] == Flow.MFA_AUTHENTICATE

    # AuthenticatedAPIView with a mutating method -> same anonymous response
    resp = client.get(headless_reverse(MANAGE_TOTP))
    _assert_anonymous(resp)

    # ChangePasswordView is an AuthenticatedAPIView: must reject, never execute.
    resp = client.post(
        headless_reverse(CHANGE_PASSWORD),
        data={"current_password": "x", "new_password": "y"},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert "access_token" not in resp.json()["meta"]


# ---------------------------------------------------------------------------
# 2. Wrong MFA code: stage stays pending, cannot be skipped by repetition
# ---------------------------------------------------------------------------
def test_wrong_mfa_code_keeps_stage_pending(mfa_pending, headless_reverse):
    client, _ = mfa_pending
    token_before = client.session_token

    resp = _mfa_confirm(client, headless_reverse, code="wrong")
    assert resp.status_code == HTTPStatus.BAD_REQUEST
    assert resp.json()["errors"] == [
        {"message": "Incorrect code.", "code": "incorrect_code", "param": "code"}
    ]
    # Error responses carry no session/access token at all.
    assert "meta" not in resp.json()
    assert "access_token" not in resp.json()

    # Repeating the confirm endpoint does not advance anything.
    resp = _mfa_confirm(client, headless_reverse, code="wrong")
    assert resp.status_code == HTTPStatus.BAD_REQUEST
    resp = _mfa_confirm(client, headless_reverse, code="also-wrong")
    assert resp.status_code == HTTPStatus.BAD_REQUEST

    # The challenge is still pending and the token has not changed.
    resp = client.get(headless_reverse(CURRENT_SESSION))
    _assert_anonymous(resp)
    assert _pending_flow(resp)["id"] == Flow.MFA_AUTHENTICATE
    assert client.session_token == token_before
    assert "_auth_user_id" not in sessionkit.session_store(client.session_token)


def test_confirm_without_any_pending_stage_is_unauthorized(
    app_client, headless_reverse
):
    """A fresh session (no login at all) cannot drive the confirm endpoint."""
    resp = _mfa_confirm(app_client, headless_reverse, code="whatever")
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.json()["meta"]["is_authenticated"] is None


# ---------------------------------------------------------------------------
# 3. Another session cannot answer this session's challenge
# ---------------------------------------------------------------------------
def test_other_session_cannot_consume_challenge(
    app_client, headless_reverse, user_with_totp, user_password, totp_validation_bypass
):
    # Session A: password OK, challenge pending.
    resp_a = _login_with_password(
        app_client, headless_reverse, user_with_totp, user_password
    )
    assert resp_a.status_code == HTTPStatus.UNAUTHORIZED
    token_a = app_client.session_token

    # Session B: brand new app client, no login, no pending stage.
    from tests.apps.headless.conftest import AppClient

    client_b = AppClient()
    resp_b = _mfa_confirm(client_b, headless_reverse, code="000000")
    assert resp_b.status_code == HTTPStatus.UNAUTHORIZED
    assert resp_b.json()["meta"]["is_authenticated"] is None

    # Session B presenting A's token verbatim still cannot confirm: the token
    # resolves to A's anonymous session and the stage lookup is per-session, so
    # a client that never logged in has no stage to enter.
    client_b.session_token = token_a
    resp_b = _mfa_confirm(client_b, headless_reverse, code="000000")
    assert resp_b.status_code == HTTPStatus.BAD_REQUEST
    assert resp_b.json()["errors"][0]["code"] == "incorrect_code"

    # A's challenge survives untouched.
    resp_a = app_client.get(headless_reverse(CURRENT_SESSION))
    _assert_anonymous(resp_a)
    assert _pending_flow(resp_a)["id"] == Flow.MFA_AUTHENTICATE

    # And the legitimate session A is the only one that can finish it.
    with totp_validation_bypass():
        resp_a = _mfa_confirm(app_client, headless_reverse, code="000000")
    assert resp_a.status_code == HTTPStatus.OK
    assert resp_a.json()["meta"]["is_authenticated"] is True


# ---------------------------------------------------------------------------
# 4. Expired / destroyed challenge and unknown token
# ---------------------------------------------------------------------------
def test_destroyed_session_token_returns_410(mfa_pending, headless_reverse):
    client, _ = mfa_pending
    token = client.session_token

    # Server-side destruction of the session (logout elsewhere, expiry purge).
    session = sessionkit.session_store(token)
    session.delete()

    resp = client.get(headless_reverse(CURRENT_SESSION))
    assert resp.status_code == HTTPStatus.GONE
    body = resp.json()
    assert body["meta"]["is_authenticated"] is None
    assert "user" not in body["data"]


def test_never_known_token_returns_410(app_client, headless_reverse):
    app_client.session_token = "does-not-exist"
    resp = app_client.get(headless_reverse(CURRENT_SESSION))
    assert resp.status_code == HTTPStatus.GONE
    assert resp.json()["meta"]["is_authenticated"] is None


def test_login_timeout_expires_challenge(
    app_client, headless_reverse, user_with_totp, user_password, settings
):
    settings.ACCOUNT_LOGIN_TIMEOUT = 0
    resp = _login_with_password(
        app_client, headless_reverse, user_with_totp, user_password
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED

    # The stashed Login is older than LOGIN_TIMEOUT on the next request:
    # unstash_login clears it, so there is no stage to enter anymore.
    resp = _mfa_confirm(app_client, headless_reverse, code="000000")
    assert resp.status_code == HTTPStatus.UNAUTHORIZED

    resp = app_client.get(headless_reverse(CURRENT_SESSION))
    body = resp.json()
    assert body["meta"]["is_authenticated"] is False
    assert all(not f.get("is_pending") for f in body["data"]["flows"])
    assert "_auth_user_id" not in sessionkit.session_store(app_client.session_token)


# ---------------------------------------------------------------------------
# 5. Successful MFA confirm: only now an authenticated session exists
# ---------------------------------------------------------------------------
def test_successful_mfa_completes_login(
    mfa_pending, headless_reverse, user_with_totp, totp_validation_bypass
):
    client, pending_resp = mfa_pending
    pending_token = client.session_token

    with totp_validation_bypass():
        resp = _mfa_confirm(client, headless_reverse, code="000000")

    assert resp.status_code == HTTPStatus.OK
    body = resp.json()
    assert body["meta"]["is_authenticated"] is True
    assert body["data"]["user"]["username"] == user_with_totp.username
    assert "flows" not in body["data"]
    # No access token with the default session strategy.
    assert "access_token" not in body["meta"]

    # Django rotates the session key on login: the old mid-flow token is dead.
    final_token = client.session_token
    assert final_token != pending_token

    # The new session is genuinely authenticated server-side.
    session = sessionkit.session_store(final_token)
    assert str(user_with_totp.pk) == session["_auth_user_id"]
    assert LOGIN_SESSION_KEY not in session

    # Old token can no longer be used to impersonate the completed login.
    from tests.apps.headless.conftest import AppClient

    stale = AppClient()
    stale.session_token = pending_token
    resp = stale.get(headless_reverse(CURRENT_SESSION))
    assert resp.status_code == HTTPStatus.GONE

    # Protected endpoints now work with the new token.
    resp = client.get(headless_reverse(MANAGE_TOTP))
    assert resp.status_code == HTTPStatus.OK


# ---------------------------------------------------------------------------
# 6. JWT token strategy: no access token is minted for the pending state
# ---------------------------------------------------------------------------
@pytest.fixture
def jwt_strategy(settings):
    settings.HEADLESS_TOKEN_STRATEGY = (
        "allauth.headless.tokens.strategies.jwt.JWTTokenStrategy"
    )
    settings.HEADLESS_JWT_STATEFUL_VALIDATION_ENABLED = True


def test_jwt_pending_state_issues_no_access_token(
    app_client,
    headless_reverse,
    user_with_totp,
    user_password,
    jwt_strategy,
):
    resp = _login_with_password(
        app_client, headless_reverse, user_with_totp, user_password
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    meta = resp.json()["meta"]
    assert meta["is_authenticated"] is False
    # A session token is exposed to continue the flow, but never an access
    # token / refresh token for the unauthenticated session.
    assert meta.get("session_token")
    assert "access_token" not in meta
    assert "refresh_token" not in meta

    # The refresh endpoint cannot conjure a token out of the pending state.
    resp = app_client.post(
        headless_reverse(TOKEN_REFRESH),
        data={"refresh_token": "nonexistent"},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.BAD_REQUEST


def test_jwt_access_token_only_after_completed_mfa(
    app_client,
    headless_reverse,
    user_with_totp,
    user_password,
    jwt_strategy,
    totp_validation_bypass,
):
    _login_with_password(app_client, headless_reverse, user_with_totp, user_password)
    pending_token = app_client.session_token

    with totp_validation_bypass():
        resp = _mfa_confirm(app_client, headless_reverse, code="000000")
    assert resp.status_code == HTTPStatus.OK
    meta = resp.json()["meta"]
    assert meta["is_authenticated"] is True

    access_token = meta.get("access_token")
    refresh_token = meta.get("refresh_token")
    assert access_token, "access token must only be minted on completed login"
    assert refresh_token
    assert meta["session_token"] != pending_token

    # The access token is a bearer credential that now reaches protected APIs.
    from django.test.client import Client

    bearer = Client(HTTP_AUTHORIZATION=f"Bearer {access_token}")
    resp = bearer.get(headless_reverse(CURRENT_SESSION))
    assert resp.status_code == HTTPStatus.OK
    assert resp.json()["meta"]["is_authenticated"] is True

    # The pre-MFA session token is worthless as a bearer / session credential.
    stale = Client(HTTP_X_SESSION_TOKEN=pending_token)
    resp = stale.get(headless_reverse(CURRENT_SESSION))
    assert resp.status_code == HTTPStatus.GONE
