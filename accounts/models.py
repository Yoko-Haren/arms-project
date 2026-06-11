from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
import hashlib
import os
import secrets
from django.conf import settings


class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        return self.create_user(email, username, password, **extra_fields)

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    is_deped_employee = models.BooleanField(default=False)
    department = models.CharField(max_length=100, blank=True)
    position = models.CharField(max_length=100, blank=True)
    
    # Fields for pepper implementation
    salt = models.CharField(max_length=128, blank=True)
    pepper_version = models.CharField(max_length=10, default='v1')
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    objects = CustomUserManager()
    
    def __str__(self):
        return self.email
    
    def set_password_with_pepper(self, raw_password):
        """Custom password setting with pepper"""
        # Generate a random salt
        self.salt = secrets.token_hex(32)
        
        # Get the secret pepper from environment or settings
        pepper = get_secret_pepper()
        
        # Combine password, salt, and pepper
        peppered_password = f"{raw_password}{self.salt}{pepper}"
        
        # Hash using Django's default hasher (PBKDF2)
        self.set_password(peppered_password)
        
    def check_password_with_pepper(self, raw_password):
        """Custom password checking with pepper"""
        pepper = get_secret_pepper()
        peppered_password = f"{raw_password}{self.salt}{pepper}"
        return self.check_password(peppered_password)

def get_secret_pepper():
    """Get the secret pepper value from settings or environment"""
    return getattr(settings, 'PASSWORD_PEPPER', os.environ.get('PASSWORD_PEPPER', 'default-pepper'))
