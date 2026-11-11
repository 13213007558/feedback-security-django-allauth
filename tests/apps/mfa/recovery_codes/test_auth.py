from django.db import transaction

import pytest

from allauth.core import context
from allauth.mfa import app_settings, signals
from allauth.mfa.models import Authenticator
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from allauth.mfa.recovery_codes.internal.flows import generate_recovery_codes


def test_flow(user):
    rc = RecoveryCodes.activate(user)
    codes = rc.generate_codes()
    assert len(set(codes)) == app_settings.RECOVERY_CODE_COUNT
    for code in codes:
        assert len(code) == app_settings.RECOVERY_CODE_DIGITS
    for i in range(app_settings.RECOVERY_CODE_COUNT):
        assert not rc._is_code_used(i)
    idx = 3
    assert rc.validate_code(codes[idx])
    for i in range(app_settings.RECOVERY_CODE_COUNT):
        assert rc._is_code_used(i) == (i == idx)
    assert not rc.validate_code(codes[idx])

    unused_codes = rc.get_unused_codes()
    assert codes[idx] not in unused_codes
    assert len(unused_codes) == app_settings.RECOVERY_CODE_COUNT - 1


def test_migrated_codes(db, user):
    auth = Authenticator(user=user, data={"migrated_codes": ["abc", "def"]})
    rc = RecoveryCodes(auth)
    assert rc.generate_codes() == ["abc", "def"]
    assert rc.get_unused_codes() == ["abc", "def"]
    assert not rc.validate_code("bad")
    assert rc.validate_code("abc")
    auth.refresh_from_db()
    rc = RecoveryCodes(auth)
    assert rc.generate_codes() == ["def"]
    assert rc.get_unused_codes() == ["def"]
    rc.validate_code("def")
    assert rc.instance.data["migrated_codes"] == []


def test_validate_code_on_stale_instance(user):
    rc = RecoveryCodes.activate(user)
    code = rc.generate_codes()[0]
    stale_rc = Authenticator.objects.get(pk=rc.instance.pk).wrap()
    assert rc.validate_code(code)
    assert not stale_rc.validate_code(code)


def test_validate_non_ascii_code(user):
    rc = RecoveryCodes.activate(user)
    assert not rc.validate_code("€#")


def test_stale_instances_interleaved_consumption(user):
    rc1 = RecoveryCodes.activate(user)
    rc2 = Authenticator.objects.get(pk=rc1.instance.pk).wrap()
    codes = rc1.generate_codes()
    assert rc1.validate_code(codes[0])
    # rc2 is stale, yet re-reads the row: the consumed code is rejected...
    assert not rc2.validate_code(codes[0])
    # ...but it is not detached either, an unused code still validates.
    assert rc2.validate_code(codes[1])
    # Now rc1 is the stale one with respect to codes[1].
    assert not rc1.validate_code(codes[1])


def test_stale_instance_after_regeneration(
    user, request_factory, reauthentication_bypass
):
    rc_old = RecoveryCodes.activate(user)
    old_code = rc_old.generate_codes()[0]
    stale = Authenticator.objects.get(pk=rc_old.instance.pk).wrap()
    request = request_factory.get("/")
    request.user = user
    with context.request_context(request):
        with reauthentication_bypass():
            generate_recovery_codes(request)
    rc_new = Authenticator.objects.get(
        user=user, type=Authenticator.Type.RECOVERY_CODES
    ).wrap()
    assert rc_new.instance.pk != rc_old.instance.pk
    new_code = rc_new.generate_codes()[0]
    # The old batch does not authenticate against the rotated authenticator.
    assert not rc_new.validate_code(old_code)
    # The preloaded wrapper points at a deleted row: it cannot authenticate
    # either batch, it errors out instead.
    with pytest.raises(Authenticator.DoesNotExist):
        stale.validate_code(old_code)
    with pytest.raises(Authenticator.DoesNotExist):
        stale.validate_code(new_code)
    # The new batch works, each code exactly once.
    assert rc_new.validate_code(new_code)
    assert not rc_new.validate_code(new_code)


def test_stale_instance_after_delete(user):
    rc = RecoveryCodes.activate(user)
    code = rc.generate_codes()[0]
    stale = Authenticator.objects.get(pk=rc.instance.pk).wrap()
    rc.instance.delete()
    with pytest.raises(Authenticator.DoesNotExist):
        stale.validate_code(code)
    # Re-activating starts a fresh batch, the old code stays invalid.
    rc2 = RecoveryCodes.activate(user)
    assert rc2.instance.data["seed"] != rc.instance.data["seed"]
    assert not rc2.validate_code(code)


def test_validate_code_rollback(user):
    rc = RecoveryCodes.activate(user)
    code = rc.generate_codes()[0]
    with pytest.raises(RuntimeError):
        with transaction.atomic():
            assert rc.validate_code(code)
            raise RuntimeError("rollback")
    # The consumption was rolled back, the code is not marked as used...
    fresh = Authenticator.objects.get(pk=rc.instance.pk).wrap()
    assert fresh.validate_code(code)
    # ...and now it genuinely is.
    assert not Authenticator.objects.get(pk=rc.instance.pk).wrap().validate_code(code)


def test_generate_recovery_codes_notification_on_commit(
    user,
    request_factory,
    reauthentication_bypass,
    settings,
    mailoutbox,
    django_capture_on_commit_callbacks,
):
    settings.ACCOUNT_EMAIL_NOTIFICATIONS = True
    RecoveryCodes.activate(user)
    request = request_factory.get("/")
    request.user = user
    resets = []

    def on_reset(sender, **kwargs):
        resets.append(kwargs)

    signals.authenticator_reset.connect(on_reset)
    try:
        with context.request_context(request):
            with reauthentication_bypass():
                with django_capture_on_commit_callbacks(execute=True):
                    generate_recovery_codes(request)
    finally:
        signals.authenticator_reset.disconnect(on_reset)
    assert len(resets) == 1
    assert len(mailoutbox) == 1


def test_generate_recovery_codes_rollback(
    user, request_factory, reauthentication_bypass, settings, mailoutbox
):
    settings.ACCOUNT_EMAIL_NOTIFICATIONS = True
    rc_old = RecoveryCodes.activate(user)
    old_pk = rc_old.instance.pk
    old_code = rc_old.generate_codes()[0]
    request = request_factory.get("/")
    request.user = user
    resets = []

    def on_reset(sender, **kwargs):
        resets.append(kwargs)

    signals.authenticator_reset.connect(on_reset)
    try:
        with context.request_context(request):
            with reauthentication_bypass():
                with pytest.raises(RuntimeError):
                    with transaction.atomic():
                        generate_recovery_codes(request)
                        raise RuntimeError("rollback")
    finally:
        signals.authenticator_reset.disconnect(on_reset)
    # The old authenticator is untouched, the old batch still validates.
    rc = Authenticator.objects.get(pk=old_pk).wrap()
    assert rc.validate_code(old_code)
    # No success notification escaped the failed transaction.
    assert resets == []
    assert len(mailoutbox) == 0
