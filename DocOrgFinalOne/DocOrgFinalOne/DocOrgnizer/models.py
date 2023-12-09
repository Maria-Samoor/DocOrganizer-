from cgi import FieldStorage
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import RegexValidator
import uuid
import re
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User, AbstractBaseUser, BaseUserManager,PermissionsMixin

# Create your models here.
# class User(AbstractUser):
#     username = models.CharField(max_length=30, unique=True)
#     email = models.EmailField(unique=True)  # Added email field
#     national_id = models.CharField(max_length=9, unique=True)
#     image_url = models.URLField(blank=True, null=True)
#     # REQUIRED_FIELDS = ('user',)

#     # user = models.OneToOneField(User, related_name='profile', unique=True)
#     def __str__(self):
#         return self.get_username()


# class CustomUser(models.Model):
#     user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)

#     def __str__(self):
#         return self.user.get_username()

# models.py
# from django.db import models

# models.py
from django.db import models
from django.utils.crypto import get_random_string

# models.py


class UserProfile(AbstractUser):
    full_name = models.CharField(max_length=255, unique=True)
    national_id = models.PositiveIntegerField(unique=True)
    email = models.EmailField(unique=True)
    national_id_photo = models.ImageField(upload_to='national_id_photos/')
    # is_active = models.BooleanField(default=False) 
    # confirmation_token = models.CharField(max_length=32, null=True, blank=True)   
    # Remove unwanted fields
    username=None
    first_name = None
    last_name = None
    USERNAME_FIELD = 'full_name'
    REQUIRED_FIELDS = ['national_id','email']
    
    # def save(self, *args, **kwargs):
    #     if not self.confirmation_token:
    #         self.confirmation_token = get_random_string(length=32)
    #     super().save(*args, **kwargs)

    def __str__(self):
        return self.full_name


