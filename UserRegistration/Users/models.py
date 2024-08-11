from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from .managers import UserManager 


class User(AbstractUser):
    phone = models.CharField(max_length=12, unique=True)
    username = models.CharField(max_length=150, unique=True, blank=True, null=True) 


    USERNAME_FIELD = 'phone'  
    REQUIRED_FIELDS = []  

    objects = UserManager()  


    def __str__(self):
        return '{}'.format(self.username)

