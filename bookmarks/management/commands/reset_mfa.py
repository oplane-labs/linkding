from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError

from bookmarks.services import mfa


class Command(BaseCommand):
    help = "Removes two-factor authentication for a user, for example when the user lost access to the authenticator app and all recovery codes"

    def add_arguments(self, parser):
        parser.add_argument("username")

    def handle(self, *args, **options):
        username = options["username"]
        user = User.objects.filter(username=username).first()
        if user is None:
            raise CommandError(f'User "{username}" does not exist')

        if mfa.remove(user):
            self.stdout.write(
                f'Removed two-factor authentication for user "{user.username}"'
            )
        else:
            self.stdout.write(
                f'User "{user.username}" has no two-factor authentication'
            )
