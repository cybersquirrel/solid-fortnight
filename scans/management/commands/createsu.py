from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
import os

class Command(BaseCommand):
    def handle(self, *args, **options):
        if not User.objects.filter(username="admin").exists():
            pw = os.environ.get("INITIAL_PW", "admin")
            email = os.environ.get("INITIAL_EMAIL", "admin@example.com")
            user = os.environ.get("INITIAL_USER", "admin")
            User.objects.create_superuser(user, email, pw)
