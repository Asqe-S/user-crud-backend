
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
# Create your models here.


class UserManager(BaseUserManager):
    def _create_user(self, username, email, password, **extra_fields):
        if not username or not email:
            raise ValueError("Username and email can't be empty")

        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username, email=None, password=None, **extra_fields):
        extra_fields["is_staff"] = extra_fields.get("is_staff", False)
        extra_fields["is_superuser"] = extra_fields.get("is_superuser", False)
        return self._create_user(username, email, password, **extra_fields)

    def create_superuser(self, username, email=None, password=None, **extra_fields):
        extra_fields["is_staff"] = True
        extra_fields["is_superuser"] = True
        extra_fields["is_verified"] = True
        return self._create_user(username, email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(unique=True)
    profile_picture = models.ImageField(
        upload_to='profile_picture/', blank=True)

    is_verified = models.BooleanField(default=False)
    is_blocked = models.BooleanField(default=False)

    is_merchant = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    date_joined = models.DateTimeField(auto_now_add=True)

    objects = UserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ['email']

    class Meta:
        ordering = ['-id']
        verbose_name = "user"
        verbose_name_plural = "users"

    def __str__(self):
        return self.username
