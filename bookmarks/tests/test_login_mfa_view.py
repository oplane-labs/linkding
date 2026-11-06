import time
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pyotp
from django.conf import settings
from django.test import TestCase, override_settings
from django.utils import timezone

from bookmarks.models import UserMfa
from bookmarks.services import mfa
from bookmarks.tests.helpers import BookmarkFactoryMixin

FAST_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
# 15 seconds into a TOTP step, so tests do not cross a step boundary
FROZEN_NOW = datetime(2026, 1, 1, 0, 0, 15, tzinfo=UTC)


@override_settings(PASSWORD_HASHERS=FAST_HASHERS)
class LoginMfaViewTestCase(TestCase, BookmarkFactoryMixin):
    def setUp(self):
        patcher = patch("bookmarks.services.mfa.timezone.now", return_value=FROZEN_NOW)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.user = self.setup_user(name="test")
        self.user.set_password("test")
        self.user.save()
        self.user_mfa = UserMfa.objects.create(
            user=self.user, secret=pyotp.random_base32(), enabled=True
        )

    def code(self, offset=0):
        totp = pyotp.TOTP(self.user_mfa.secret)
        return totp.generate_otp(totp.timecode(timezone.now()) + offset)

    def login_password(self, next_url=None):
        data = {"username": "test", "password": "test"}
        if next_url is not None:
            data["next"] = next_url
        return self.client.post("/login/", data)

    def submit_code(self, code):
        return self.client.post("/login/mfa/", {"code": code})

    def assertLoggedIn(self):
        self.assertEqual(str(self.user.pk), self.client.session.get("_auth_user_id"))

    def assertNotLoggedIn(self):
        self.assertIsNone(self.client.session.get("_auth_user_id"))

    def test_password_step_does_not_create_session(self):
        response = self.login_password()

        self.assertRedirects(response, "/login/mfa/", fetch_redirect_response=False)
        self.assertNotLoggedIn()
        self.assertEqual(302, self.client.get("/bookmarks").status_code)

    def test_password_step_rotates_session_key(self):
        self.client.get("/login/")
        self.client.session.save()
        key_before = self.client.session.session_key

        self.login_password()

        self.assertNotEqual(key_before, self.client.session.session_key)

    def test_unconfirmed_mfa_does_not_require_code(self):
        self.user_mfa.enabled = False
        self.user_mfa.save()

        response = self.login_password()

        self.assertRedirects(
            response, settings.LOGIN_REDIRECT_URL, fetch_redirect_response=False
        )
        self.assertLoggedIn()

    def test_valid_code_logs_in(self):
        self.login_password()
        key_before = self.client.session.session_key

        response = self.submit_code(self.code())

        self.assertRedirects(
            response, settings.LOGIN_REDIRECT_URL, fetch_redirect_response=False
        )
        self.assertLoggedIn()
        self.assertNotEqual(key_before, self.client.session.session_key)
        self.assertNotIn("mfa_pending_user_id", self.client.session)

    def test_code_from_adjacent_steps_is_accepted(self):
        self.login_password()
        self.submit_code(self.code(offset=-1))
        self.assertLoggedIn()

    def test_code_outside_window_is_rejected(self):
        self.login_password()
        response = self.submit_code(self.code(offset=-2))
        self.assertEqual(401, response.status_code)
        self.assertNotLoggedIn()

    def test_invalid_code_returns_401(self):
        self.login_password()

        accepted = {self.code(offset) for offset in (-1, 0, 1)}
        invalid = next(c for c in ("000000", "111111", "222222") if c not in accepted)
        response = self.submit_code(invalid)

        self.assertEqual(401, response.status_code)
        self.assertNotLoggedIn()
        self.user_mfa.refresh_from_db()
        self.assertEqual(1, self.user_mfa.failed_attempts)

    def test_malformed_code_counts_as_failure(self):
        self.login_password()

        for code in ["12345", "1234567", "abcdef", "ABCDE-ABCD1", ""]:
            response = self.submit_code(code)
            self.assertEqual(401, response.status_code)

        self.assertNotLoggedIn()
        self.user_mfa.refresh_from_db()
        self.assertIsNotNone(self.user_mfa.locked_until)

    def test_replayed_code_is_rejected(self):
        code = self.code()
        self.login_password()
        self.submit_code(code)
        self.assertLoggedIn()
        self.client.post("/logout/")

        self.login_password()
        response = self.submit_code(code)

        self.assertEqual(401, response.status_code)
        self.assertNotLoggedIn()

    def test_no_pending_login_redirects_to_login(self):
        response = self.submit_code(self.code())

        self.assertRedirects(
            response, settings.LOGIN_URL, fetch_redirect_response=False
        )
        self.assertNotLoggedIn()

    def test_expired_pending_login_is_rejected(self):
        self.login_password()

        with patch(
            "bookmarks.views.auth.time.time", return_value=time.time() + 5 * 60 + 1
        ):
            response = self.submit_code(self.code())

        self.assertRedirects(
            response, settings.LOGIN_URL, fetch_redirect_response=False
        )
        self.assertNotLoggedIn()
        self.assertNotIn("mfa_pending_user_id", self.client.session)

    def test_pending_login_is_rejected_after_mfa_reset(self):
        self.login_password()
        mfa.remove(self.user)

        response = self.submit_code(self.code())

        self.assertRedirects(
            response, settings.LOGIN_URL, fetch_redirect_response=False
        )
        self.assertNotLoggedIn()

    def test_pending_login_is_rejected_after_password_change(self):
        self.login_password()
        self.user.set_password("changed")
        self.user.save()

        response = self.submit_code(self.code())

        self.assertRedirects(
            response, settings.LOGIN_URL, fetch_redirect_response=False
        )
        self.assertNotLoggedIn()
        self.assertNotIn("mfa_pending_user_id", self.client.session)

    def test_mfa_reset_during_verification_redirects_to_login(self):
        self.login_password()
        verify = mfa.verify

        def reset_then_verify(user, code):
            mfa.remove(user)
            return verify(user, code)

        with patch("bookmarks.views.auth.mfa.verify", side_effect=reset_then_verify):
            response = self.submit_code(self.code())

        self.assertRedirects(
            response, settings.LOGIN_URL, fetch_redirect_response=False
        )
        self.assertNotLoggedIn()
        self.assertNotIn("mfa_pending_user_id", self.client.session)

    def test_attempt_limit_locks_user(self):
        self.login_password()
        for _ in range(mfa.MAX_FAILED_ATTEMPTS - 1):
            response = self.submit_code("ABCDE-FGHIJ")
            self.assertContains(response, "The code is not valid", status_code=401)

        response = self.submit_code("ABCDE-FGHIJ")

        self.assertContains(response, "Too many failed attempts", status_code=401)
        self.assertNotIn("mfa_pending_user_id", self.client.session)
        self.user_mfa.refresh_from_db()
        self.assertIsNotNone(self.user_mfa.locked_until)
        self.assertEqual(0, self.user_mfa.failed_attempts)

    def test_locked_user_is_rejected_with_valid_code(self):
        self.user_mfa.locked_until = timezone.now() + timedelta(minutes=10)
        self.user_mfa.save()
        self.login_password()

        response = self.submit_code(self.code())

        self.assertContains(response, "Too many failed attempts", status_code=401)
        self.assertNotLoggedIn()
        self.user_mfa.refresh_from_db()
        self.assertEqual(0, self.user_mfa.last_used_step)

    def test_lock_expires(self):
        self.user_mfa.locked_until = timezone.now() - timedelta(seconds=1)
        self.user_mfa.save()
        self.login_password()

        self.submit_code(self.code())

        self.assertLoggedIn()

    def test_attempt_counter_survives_restarted_login(self):
        self.login_password()
        for _ in range(mfa.MAX_FAILED_ATTEMPTS - 1):
            self.submit_code("ABCDE-FGHIJ")

        self.client.logout()
        self.login_password()
        response = self.submit_code("ABCDE-FGHIJ")

        self.assertContains(response, "Too many failed attempts", status_code=401)

    def test_successful_code_resets_counter(self):
        self.login_password()
        self.submit_code("ABCDE-FGHIJ")
        self.submit_code(self.code())

        self.user_mfa.refresh_from_db()
        self.assertEqual(0, self.user_mfa.failed_attempts)

    def test_recovery_code_is_single_use(self):
        self.user_mfa.enabled = False
        self.user_mfa.save()
        codes = mfa.confirm_enrollment(self.user, self.code())
        self.assertIsNotNone(codes)

        self.login_password()
        self.submit_code(codes[0].lower())
        self.assertLoggedIn()
        self.client.post("/logout/")

        self.login_password()
        response = self.submit_code(codes[0])
        self.assertEqual(401, response.status_code)
        self.assertNotLoggedIn()

        self.submit_code(codes[1])
        self.assertLoggedIn()

    def test_keeps_next_url(self):
        self.login_password(next_url="/bookmarks?q=test")

        response = self.submit_code(self.code())

        self.assertRedirects(
            response, "/bookmarks?q=test", fetch_redirect_response=False
        )

    def test_rejects_open_redirect(self):
        self.login_password(next_url="https://example.com/phish")

        response = self.submit_code(self.code())

        self.assertRedirects(
            response, settings.LOGIN_REDIRECT_URL, fetch_redirect_response=False
        )

    def test_get_shows_code_form(self):
        self.login_password()

        response = self.client.get("/login/mfa/")

        self.assertContains(response, 'name="code"')

    @override_settings(LD_DISABLE_LOGIN_FORM=True)
    def test_rejected_when_login_form_disabled(self):
        response = self.submit_code(self.code())
        self.assertEqual(403, response.status_code)
