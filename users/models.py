from django.db import models
import uuid
from django.conf import settings
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
import os


class UserManager(BaseUserManager):

    def create_user(self, email, password=None):
        if not email:
            raise ValueError("User must have an email address")
        user = self.model(
            email=self.normalize_email(email)
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        if password is None:
            raise TypeError('Superusers must have a password.')
        user = self.create_user(email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


class User(AbstractBaseUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4(), editable=False)
    email = models.EmailField(verbose_name='email_address', max_length=255, unique=True)
    is_active = models.BooleanField(default=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    objects = UserManager()

    def __str__(self):
        return self.email

    class Meta:
        db_table = "login"

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }


class Districts(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    district = models.CharField(max_length=50)

    class Meta:
        db_table = "districts"


class Courses(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    course = models.CharField(max_length=50)

    class Meta:
        db_table = "courses"


class Branches(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    branch = models.CharField(max_length=50)

    class Meta:
        db_table = "branches"


class Colleges(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    college = models.CharField(max_length=50)

    class Meta:
        db_table = "colleges"


def upload_to(instance, filename):
    now = timezone.now()
    base, extension = os.path.splitext(filename.lower())
    milliseconds = now.microsecond // 1000
    return f"users/{instance.pk}/{now:%Y%m%d%H%M%S}{milliseconds}{extension}"


class UserProfile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile')
    name = models.CharField(max_length=50)
    district = models.CharField(max_length=50)
    course = models.CharField(max_length=50)
    branch = models.CharField(max_length=50)
    sem = models.CharField(max_length=2)
    college = models.CharField(max_length=50)
    avatar = models.ImageField(upload_to='avatars/', blank=True)

    class Meta:
        db_table = "profile"


class Image(models.Model):
    # Define fields like below
    image = models.ImageField(upload_to='images/%Y/%m/%d/')
    # auto_now_add set to true makes this field filled with the date of entry creation
    timestamp = models.DateTimeField(auto_now_add=True)

    # we will add more fields here later

    # Django is using this method to display an object in the Django admin site
    def __str__(self):
        return self.image
