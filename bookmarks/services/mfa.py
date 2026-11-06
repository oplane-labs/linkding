import enum
import hashlib
import hmac
import re
import secrets
from datetime import timedelta

import pyotp
import segno
from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone

from bookmarks.models import MfaRecoveryCode, UserMfa

MAX_FAILED_ATTEMPTS = 5
LOCK_DURATION = timedelta(minutes=15)
RECOVERY_CODE_COUNT = 10

_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_TOTP_PATTERN = re.compile(r"^[0-9]{6}$")
_RECOVERY_CODE_PATTERN = re.compile(r"^[A-Z2-7]{5}-[A-Z2-7]{5}$")


class VerifyResult(enum.Enum):
    OK = "ok"
    INVALID = "invalid"
    LOCKED = "locked"
    # MFA was removed or not enabled, for example by a concurrent reset
    MISSING = "missing"


def is_enabled(user: User) -> bool:
    return UserMfa.objects.filter(user=user, enabled=True).exists()


def start_enrollment(user: User) -> UserMfa:
    """Idempotent, returns the existing secret if there is one."""
    mfa, _ = UserMfa.objects.get_or_create(
        user=user, defaults={"secret": pyotp.random_base32()}
    )
    return mfa


def qr_code_svg(user: User, mfa: UserMfa) -> str:
    # The username is only part of the URI encoded in the QR code, the SVG
    # itself contains no text. It is rendered unescaped in the template.
    uri = pyotp.TOTP(mfa.secret).provisioning_uri(
        name=user.username, issuer_name="linkding"
    )
    return segno.make(uri, error="m").svg_inline(scale=4)


def confirm_enrollment(user: User, code: str) -> list[str] | None:
    """Returns the plaintext recovery codes. This is the only time they exist."""
    code = code.strip()
    if not _TOTP_PATTERN.match(code):
        return None

    with transaction.atomic():
        mfa = (
            UserMfa.objects.select_for_update().filter(user=user, enabled=False).first()
        )
        if mfa is None or not _check_totp(mfa, code):
            return None

        mfa.enabled = True
        mfa.confirmed_at = timezone.now()
        mfa.save(update_fields=["enabled", "confirmed_at", "last_used_step"])

        codes = [_generate_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
        MfaRecoveryCode.objects.filter(user=user).delete()
        MfaRecoveryCode.objects.bulk_create(
            MfaRecoveryCode(user=user, code_hash=_hash_recovery_code(c)) for c in codes
        )
        return codes


def verify(user: User, code: str) -> VerifyResult:
    """
    Check a TOTP or recovery code for a user with MFA enabled. Failed attempts
    count towards a per-user lock.

    The row lock serializes concurrent attempts on PostgreSQL. On SQLite,
    select_for_update is a no-op, but a concurrent writer fails with "database
    is locked" instead of overwriting the counter, so the attempt fails closed.
    """
    with transaction.atomic():
        mfa = (
            UserMfa.objects.select_for_update().filter(user=user, enabled=True).first()
        )
        if mfa is None:
            return VerifyResult.MISSING
        return _verify(mfa, code)


def disable(user: User, code: str) -> VerifyResult:
    """
    Remove MFA if the code is valid. An unconfirmed enrollment protects nothing
    and is removed without a code. The decision and the removal happen under
    the same row lock, so an enrollment confirmed concurrently is not removed
    without a code.
    """
    with transaction.atomic():
        mfa = UserMfa.objects.select_for_update().filter(user=user).first()
        if mfa is None:
            return VerifyResult.MISSING
        if mfa.enabled:
            result = _verify(mfa, code)
            if result != VerifyResult.OK:
                return result
        _delete(user)
        return VerifyResult.OK


def remove(user: User) -> bool:
    """Administrative reset without a code. Returns whether MFA existed."""
    with transaction.atomic():
        if not UserMfa.objects.select_for_update().filter(user=user).exists():
            return False
        _delete(user)
        return True


def _delete(user: User):
    MfaRecoveryCode.objects.filter(user=user).delete()
    UserMfa.objects.filter(user=user).delete()


def _verify(mfa: UserMfa, code: str) -> VerifyResult:
    """Must run in a transaction that holds the lock on the MFA row."""
    code = code.strip().upper()
    now = timezone.now()
    if mfa.locked_until and mfa.locked_until > now:
        return VerifyResult.LOCKED

    if _TOTP_PATTERN.match(code):
        valid = _check_totp(mfa, code)
    elif _RECOVERY_CODE_PATTERN.match(code):
        valid = _use_recovery_code(mfa.user_id, code, now)
    else:
        valid = False

    if valid:
        mfa.failed_attempts = 0
        mfa.save(update_fields=["failed_attempts", "last_used_step"])
        return VerifyResult.OK

    mfa.failed_attempts += 1
    if mfa.failed_attempts >= MAX_FAILED_ATTEMPTS:
        mfa.failed_attempts = 0
        mfa.locked_until = now + LOCK_DURATION
        mfa.save(update_fields=["failed_attempts", "locked_until"])
        return VerifyResult.LOCKED

    mfa.save(update_fields=["failed_attempts"])
    return VerifyResult.INVALID


def _check_totp(mfa: UserMfa, code: str) -> bool:
    """
    The ±1 step window tolerates clock skew between server and authenticator.
    Only steps later than the last accepted one are valid, so a code can not
    be replayed, also not an older code from the window.
    """
    totp = pyotp.TOTP(mfa.secret)
    current = totp.timecode(timezone.now())
    for step in (current - 1, current, current + 1):
        if step > mfa.last_used_step and hmac.compare_digest(
            totp.generate_otp(step), code
        ):
            mfa.last_used_step = step
            return True
    return False


def _use_recovery_code(user_id: int, code: str, now) -> bool:
    # The conditional update consumes the code at most once
    used = MfaRecoveryCode.objects.filter(
        user_id=user_id, code_hash=_hash_recovery_code(code), used_at__isnull=True
    ).update(used_at=now)
    return used > 0


def _hash_recovery_code(code: str) -> str:
    # The codes are 50 random bits, so a slow password hash adds no protection
    # against online guessing. It would not help after a database leak either,
    # because the TOTP secret is stored in plaintext next to them.
    return hashlib.sha256(code.encode()).hexdigest()


def _generate_recovery_code() -> str:
    chars = "".join(secrets.choice(_BASE32_ALPHABET) for _ in range(10))
    return f"{chars[:5]}-{chars[5:]}"
