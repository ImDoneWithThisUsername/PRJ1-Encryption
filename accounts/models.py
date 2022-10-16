from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError(_('Email không được để trống'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractUser):
    username = None
    email = models.EmailField(_('email address'), unique=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    name = models.CharField(max_length=200)
    birth = models.DateField(null=True)
    phone = models.CharField(max_length=200)
    address = models.CharField(max_length=200, blank=True)
    passphrase = models.CharField(max_length=200, null=False, blank=False)
    private_key = models.BinaryField(null=True, blank=True)
    public_key = models.BinaryField(null=True, blank=True)

    objects = CustomUserManager()
        
    def __str__(self):
        return self.email

def user_directory_path(instance, filename):
    # file will be uploaded to MEDIA_ROOT/user_<id>/<filename>
    return 'user_{0}/{1}'.format(instance.user.id, filename)

class Document(models.Model):
    document = models.FileField(upload_to=user_directory_path)
    sender = models.ForeignKey(CustomUser, null=True, on_delete=models.SET_NULL, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)