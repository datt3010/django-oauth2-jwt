from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils.translation import gettext_lazy as _


# Create your models here.
class CustomAccountManager(BaseUserManager):
    def create_user(self, email, password, **other_fields):
        if not email:
            raise ValueError(_('Please pro  vide an email address'))
        email = self.normalize_email(email)
        user = self.model(email=email, **other_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **other_fields):
        other_fields.setdefault('is_staff', True)
        other_fields.setdefault('is_superuser', True)
        other_fields.setdefault('is_active', True)
        if other_fields.get('is_staff') is not True:
            raise ValueError(_('Please assign is_staff = True for superuser'))
        if other_fields.get('is_superuser') is not True:
            raise ValueError(_('Please assign is_superuser= True for superuser'))
        return self.create_user(email, password, **other_fields)


class User(AbstractBaseUser, PermissionsMixin):
    username = None
    last_login = None
    is_staff = None
    is_superuser = None
    password = models.CharField(max_length=100)
    email = models.EmailField(max_length=100, unique=True)
    objects = CustomAccountManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email


