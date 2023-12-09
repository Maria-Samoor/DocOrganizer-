from django.contrib.auth.backends import ModelBackend
from .models import UserProfile

class CustomModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        # Check if the provided username is an email address
        if '@' in username:
            # If it's an email address, use the email field for authentication
            user = UserProfile.objects.filter(email__iexact=username).first()
        else:
            # If it's not an email address, assume it's a full name and use the full_name field
            user = UserProfile.objects.filter(full_name__iexact=username).first()

        # Check the password if a user was found
        if user and user.check_password(password):
            return user

        return None
