from rest_framework import serializers
from .models import User
from django.core.exceptions import ValidationError

from django.core.cache import cache

from datetime import timedelta
from django.utils import timezone

import random
from .tasks import send_verification_code

from .utils import generate_temp_password

VERIFY_CODE_CACHE_PREFIX = 'verify_code_'
VERIFY_CODE_EXPIRATION = 5*60


GENERATE_CODE_ATTEMPTS_KEY_PREFIX = 'generate_code_attempts_'
LOGIN_ATTEMPTS_KEY_PREFIX = 'login_attempts_'
LOCKOUT_TIME = 300  
MAX_ATTEMPTS = 3


# Decorator for phone number validation
def validate_phone(value):
    if not value.isdigit() or len(value) != 12:
        raise ValidationError("Phone number must be 10 digits.")
    return value

def validate_code(value):
    if not value.isdigit() or len(value) != 6:
        raise serializers.ValidationError("OTP code must be exactly 6 digits.")
    return value

def validate_user_existence(self, value):
        if User.objects.filter(phone=value).exists():
            raise serializers.ValidationError("A user with this phone number already exists.")
        return value


# Public auxiliary function
# ------------------------------------------------

def get_or_create_cache_attempt_key(cache_key, phone):
    attempts = cache.get(f'{cache_key}{phone}')
    if attempts == None:
        attempts = {'count': 0, 'lockout_until': None}
    return attempts


def reach_three_attempts(cache_key, phone, max_attempts, attempts, lockout_time):
    attempts['count'] += 1
    if attempts['count'] >= max_attempts:
        attempts['lockout_until'] = timezone.now() + timedelta(seconds=lockout_time)

    cache.set(f'{cache_key}{phone}', attempts)

    if attempts['lockout_until'] and (timezone.now() < attempts['lockout_until']):
        return True
    return False

# ------------------------------------------------

class GenerateCodeSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=12, validators=[validate_phone])

    def save(self):
        phone = self.validated_data['phone']
        code = generate_temp_password()  
        cache.set(f'{VERIFY_CODE_CACHE_PREFIX}{phone}', {'code': code}, VERIFY_CODE_EXPIRATION)
        
        # Trigger the Celery task to send the code
        send_verification_code.delay(phone, code)

        return code

    

class VerificationSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=12, validators=[validate_phone])
    code = serializers.CharField(max_length=6, validators=[validate_code])


    
class RegisterUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True) 
    phone = serializers.CharField(validators=[validate_phone, validate_user_existence])

    class Meta:
        model = User
        fields = ['id', 'phone', 'first_name', 'last_name', 'password' ]

        read_only_fields = ['id', 'password']  


    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = super().create(validated_data)
        if password:
            # Hash the password
            user.set_password(password)  
            user.save()
        return user


    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        user = super().update(instance, validated_data)
        if password:
            # Hash the password
            user.set_password(password)  
            user.save()
        return user
    



class LoginUserSerializer(serializers.ModelSerializer):
    phone = serializers.CharField(required=True, validators=[validate_phone])
    password = serializers.CharField(required=True) 

    class Meta:
        model = User
        fields = ['id', 'phone', 'password']




class LogoutUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = []
