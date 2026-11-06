from io import StringIO

import pyotp
from django.core.management import CommandError, call_command
from django.test import TestCase

from bookmarks.models import MfaRecoveryCode, UserMfa
from bookmarks.tests.helpers import BookmarkFactoryMixin


class ResetMfaCommandTestCase(TestCase, BookmarkFactoryMixin):
    def test_removes_mfa(self):
        user = self.setup_user(name="john")
        other_user = self.setup_user(name="jane")
        for u in (user, other_user):
            UserMfa.objects.create(user=u, secret=pyotp.random_base32(), enabled=True)
            MfaRecoveryCode.objects.create(user=u, code_hash="x")
        out = StringIO()

        call_command("reset_mfa", "john", stdout=out)

        self.assertIn(
            'Removed two-factor authentication for user "john"', out.getvalue()
        )
        self.assertFalse(UserMfa.objects.filter(user=user).exists())
        self.assertFalse(MfaRecoveryCode.objects.filter(user=user).exists())
        self.assertTrue(UserMfa.objects.filter(user=other_user).exists())
        self.assertTrue(MfaRecoveryCode.objects.filter(user=other_user).exists())

    def test_user_without_mfa(self):
        self.setup_user(name="john")
        out = StringIO()

        call_command("reset_mfa", "john", stdout=out)

        self.assertIn('User "john" has no two-factor authentication', out.getvalue())

    def test_unknown_user(self):
        with self.assertRaisesMessage(CommandError, 'User "nobody" does not exist'):
            call_command("reset_mfa", "nobody")
