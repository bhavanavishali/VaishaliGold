# authenticationapp/models.py

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone

class MyAccountManager(BaseUserManager):  # Custom manager for user creation(how users are created.)
    def create_user(self, first_name, last_name, username, email, phone_number, password=None):   # for regular user
        if not email:
            raise ValueError('User must have an email address')  # Ensures email is provided
        if not username:
            raise ValueError('User must have a username')  # Ensures username is provided
        
        user = self.model(
            email=self.normalize_email(email),  # Converts email to lowercase for consistency
            username=username,
            first_name=first_name,
            last_name=last_name,
            phone_number=phone_number,
        )
        user.set_password(password)  # Hashes the password before saving
        user.is_active = False  # User is inactive until OTP verification
        user.save(using=self._db)  # Saves the user in the database
        return user  # Returns the created user object
    
    def create_superuser(self, first_name, last_name, email, username, password, phone_number=None): # super user
        user = self.create_user(
            email=self.normalize_email(email),  # Normalizes email
            username=username,
            password=password,  # Password is required for superuser
            first_name=first_name,
            last_name=last_name,
            phone_number=phone_number or "0000000000",  
        )
        user.is_admin = True  
        user.is_active = True  
        user.is_staff = True  
        user.is_superadmin = True 
        user.save(using=self._db)  # Saves the superuser in the database
        return user  # Returns the created superuser object


class User(AbstractBaseUser):  #(how they authenticate.)


    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(max_length=100, unique=True)
    phone_number = models.CharField(max_length=50, blank=True)
    google_id = models.CharField(max_length=100, blank=True, null=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)  # Updated on login
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)  # Changed to False for OTP
    is_superadmin = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'  # Authentication will be based on email instead of username
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']  # Fields required when creating a user

    objects = MyAccountManager()  # Custom user manager for handling user creation

    def __str__(self):
        return self.email  # Returns email when the object is printed
    
    def has_perm(self, perm, obj=None):
        return self.is_admin  # Admin users have all permissions
    
    def has_module_perms(self, app_label):
        return True  # Grants module permissions to all admin users

class UserProfile(models.Model):  # Model for storing additional user profile details
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='user')  # Links to a User instance
    profile_picture = models.ImageField(upload_to='user/profile_pic/', null=True, blank=True)  # Optional profile picture field

    def __str__(self):
        return str(self.user.first_name)  # Returns the first name when printed