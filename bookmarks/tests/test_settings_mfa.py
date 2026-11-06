import pyotp
from django.contrib.auth.hashers import identify_hasher
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from bookmarks.models import MfaRecoveryCode, UserMfa
from bookmarks.services import mfa
from bookmarks.tests.helpers import BookmarkFactoryMixin

FAST_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]


def current_code(user_mfa):
    totp = pyotp.TOTP(user_mfa.secret)
    return totp.generate_otp(totp.timecode(timezone.now()))


@override_settings(PASSWORD_HASHERS=FAST_HASHERS)
class SettingsMfaTestCase(TestCase, BookmarkFactoryMixin):
    def setUp(self):
        self.user = self.get_or_create_test_user()
        self.client.force_login(self.user)

    def enable(self):
        return self.client.post(reverse("linkding:settings.mfa.enable"))

    def confirm(self, code):
        return self.client.post(
            reverse("linkding:settings.mfa.confirm"), {"code": code}
        )

    def disable(self, code=""):
        return self.client.post(
            reverse("linkding:settings.mfa.disable"), {"code": code}
        )

    def enroll(self):
        self.enable()
        user_mfa = UserMfa.objects.get(user=self.user)
        self.confirm(current_code(user_mfa))
        user_mfa.refresh_from_db()
        return user_mfa

    def test_section_shows_enable_button(self):
        response = self.client.get(reverse("linkding:settings.general"))

        self.assertContains(response, "Two-factor authentication")
        self.assertContains(response, 'value="Enable"')

    def test_enable_creates_unconfirmed_secret(self):
        self.enable()

        user_mfa = UserMfa.objects.get(user=self.user)
        self.assertFalse(user_mfa.enabled)
        response = self.client.get(reverse("linkding:settings.general"))
        self.assertContains(response, user_mfa.secret)
        self.assertContains(response, 'class="segno"')

    def test_enable_twice_keeps_secret(self):
        self.enable()
        secret = UserMfa.objects.get(user=self.user).secret

        self.enable()

        self.assertEqual(secret, UserMfa.objects.get(user=self.user).secret)

    def test_enable_requires_post(self):
        response = self.client.get(reverse("linkding:settings.mfa.enable"))
        self.assertEqual(403, response.status_code)
        self.assertFalse(UserMfa.objects.exists())

    def test_confirm_with_valid_code_enables_mfa(self):
        self.enable()
        user_mfa = UserMfa.objects.get(user=self.user)

        response = self.confirm(current_code(user_mfa))

        user_mfa.refresh_from_db()
        self.assertTrue(user_mfa.enabled)
        self.assertIsNotNone(user_mfa.confirmed_at)
        self.assertTrue(mfa.is_enabled(self.user))
        # The confirm code can not be used again for login
        self.assertGreater(user_mfa.last_used_step, 0)

        codes = response.context["mfa_recovery_codes"]
        self.assertEqual(mfa.RECOVERY_CODE_COUNT, len(codes))
        for code in codes:
            self.assertContains(response, code)
            self.assertRegex(code, r"^[A-Z2-7]{5}-[A-Z2-7]{5}$")

        stored = MfaRecoveryCode.objects.filter(user=self.user)
        self.assertEqual(mfa.RECOVERY_CODE_COUNT, stored.count())
        for recovery_code in stored:
            self.assertNotIn(recovery_code.code_hash, codes)
            identify_hasher(recovery_code.code_hash)

    def test_confirm_with_invalid_code_does_not_enable(self):
        self.enable()

        self.confirm("ABCDEF")
        self.confirm("")

        self.assertFalse(UserMfa.objects.get(user=self.user).enabled)
        self.assertFalse(MfaRecoveryCode.objects.exists())

    def test_secret_not_rendered_after_activation(self):
        user_mfa = self.enroll()

        response = self.client.get(reverse("linkding:settings.general"))

        self.assertNotContains(response, user_mfa.secret)
        self.assertNotContains(response, 'class="segno"')
        self.assertContains(response, "Two-factor authentication is enabled")
        # Recovery codes are only shown once
        self.assertNotIn("mfa_recovery_codes", response.context)

    def test_qr_code_does_not_contain_username(self):
        user = self.setup_user(name="<script>alert(1)</script>")
        user_mfa = mfa.start_enrollment(user)

        svg = mfa.qr_code_svg(user, user_mfa)

        self.assertNotIn("script", svg)
        self.assertNotIn(user_mfa.secret, svg)

    def test_disable_requires_valid_code(self):
        self.enroll()

        self.disable("ABCDE-FGHIJ")
        self.disable("")

        self.assertTrue(mfa.is_enabled(self.user))

    def test_disable_with_valid_code(self):
        user_mfa = self.enroll()

        # The confirm step consumed the current step, use the next one
        totp = pyotp.TOTP(user_mfa.secret)
        self.disable(totp.generate_otp(totp.timecode(timezone.now()) + 1))

        self.assertFalse(UserMfa.objects.filter(user=self.user).exists())
        self.assertFalse(MfaRecoveryCode.objects.filter(user=self.user).exists())

    def test_disable_with_recovery_code(self):
        self.enable()
        user_mfa = UserMfa.objects.get(user=self.user)
        codes = self.confirm(current_code(user_mfa)).context["mfa_recovery_codes"]

        self.disable(codes[0])

        self.assertFalse(UserMfa.objects.filter(user=self.user).exists())

    def test_disable_attempts_count_toward_lockout(self):
        user_mfa = self.enroll()

        for _ in range(mfa.MAX_FAILED_ATTEMPTS):
            self.disable("ABCDE-FGHIJ")

        user_mfa.refresh_from_db()
        self.assertIsNotNone(user_mfa.locked_until)
        # A valid code is rejected while locked
        totp = pyotp.TOTP(user_mfa.secret)
        self.disable(totp.generate_otp(totp.timecode(timezone.now()) + 1))
        self.assertTrue(mfa.is_enabled(self.user))

    def test_cancel_unconfirmed_enrollment_without_code(self):
        self.enable()

        self.disable()

        self.assertFalse(UserMfa.objects.filter(user=self.user).exists())

    def test_user_cannot_access_other_users_mfa(self):
        other_user = self.setup_user()
        other_mfa = mfa.start_enrollment(other_user)
        self.assertIsNotNone(
            mfa.confirm_enrollment(other_user, current_code(other_mfa))
        )

        # The endpoints only act on the logged in user
        response = self.client.get(reverse("linkding:settings.general"))
        self.assertNotContains(response, other_mfa.secret)
        self.disable("ABCDE-FGHIJ")
        self.enable()
        self.confirm(current_code(other_mfa))

        other_mfa.refresh_from_db()
        self.assertTrue(other_mfa.enabled)
        self.assertEqual(0, other_mfa.failed_attempts)
        self.assertEqual(
            mfa.RECOVERY_CODE_COUNT,
            MfaRecoveryCode.objects.filter(user=other_user).count(),
        )
        self.assertNotEqual(
            other_mfa.secret, UserMfa.objects.get(user=self.user).secret
        )

    def test_endpoints_require_login(self):
        self.client.logout()

        for name in ["enable", "confirm", "disable"]:
            response = self.client.post(reverse(f"linkding:settings.mfa.{name}"))
            self.assertEqual(302, response.status_code)
            self.assertIn("/login", response["Location"])
        self.assertFalse(UserMfa.objects.exists())

    @override_settings(LD_DISABLE_LOGIN_FORM=True)
    def test_hidden_when_login_form_disabled(self):
        response = self.client.get(reverse("linkding:settings.general"))
        self.assertNotContains(response, "Two-factor authentication")

        response = self.enable()
        self.assertEqual(403, response.status_code)
        self.assertFalse(UserMfa.objects.exists())
