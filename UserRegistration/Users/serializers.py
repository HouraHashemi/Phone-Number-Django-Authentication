from .models import User

from rest_framework import serializers

from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate

from .tasks import send_verification_code
from .utils import *
from .messages import *




VERIFY_CODE_CACHE_PREFIX = 'verify_code_'
VERIFY_CODE_EXPIRATION = 5*60

CODE_ATTEMPTS_KEY_PREFIX = 'generate_code_attempts_'
LOGIN_ATTEMPTS_KEY_PREFIX = 'login_attempts_'
LOCKOUT_TIME = 300  
MAX_ATTEMPTS = 3


def validate_phone(value):
    if not value.isdigit() or len(value) <= 10:
        raise ValidationError("Phone number must be 10 digits.")
    return value


def validate_code(value):
    if not value.isdigit() or len(value) != 6:
        raise serializers.ValidationError("OTP code must be exactly 6 digits.")
    return value


def validate_user_existence(value):
    if User.objects.filter(phone=value).exists():
        raise serializers.ValidationError("A user with this phone number already verified and exists.")
    return value


# ------------------------------------------------
class GenerateCodeSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=12, validators=[validate_phone, validate_user_existence])

    def save(self):
        phone = self.validated_data['phone']
        code = generate_temp_password()  

        key = VERIFY_CODE_CACHE_PREFIX
        data = {'code': code}
        set_verification_code_to_cache(key, phone, data, VERIFY_CODE_EXPIRATION)
        
        # Trigger the Celery task to send the code
        send_verification_code.delay(phone, code)

        return code

    

class VerificationSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=12, validators=[validate_phone, validate_user_existence])
    code = serializers.CharField(max_length=6, validators=[validate_code])

    def validate(self, data):
        phone = data.get('phone')
        code = data.get('code')

        key = VERIFY_CODE_CACHE_PREFIX
        attemp_key = CODE_ATTEMPTS_KEY_PREFIX
        
        # Fetch the cached verification code
        verification_code = get_verification_code_from_cache(key, phone)
        if verification_code is None:
            raise serializers.ValidationError(code_expiration_message())

        attempts = get_or_create_cache_attempt_key(attemp_key, phone)

        # Check for max attempts 
        if reach_three_attempts(attemp_key, phone, MAX_ATTEMPTS, attempts, LOCKOUT_TIME):
            raise serializers.ValidationError(locked_account_message(attempts))

        expected_code = verification_code['code']

        # Validate the provided code only if the account is not locked
        if not is_expected_code(code, expected_code):
            raise serializers.ValidationError(invalid_code_message(attempts))

        # Validation passed, clear the attempts cache and the verification code
        delete_generated_code_from_cache(attemp_key, phone)

        return data



class RegisterUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True) 
    phone = serializers.CharField(validators=[validate_phone, validate_user_existence])

    class Meta:
        model = User
        fields = ['id', 'phone', 'first_name', 'last_name', 'password' ]

        read_only_fields = ['id', 'password'] 


    def validate(self, data):
        phone = data.get('phone')
        
        key = VERIFY_CODE_CACHE_PREFIX
        
        # Check if verification code exists in cache
        verification_code = get_verification_code_from_cache(key, phone)
        if verification_code is None:
            raise serializers.ValidationError(code_expiration_message())
        
        return data 


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
    


class LoginUserSerializer(serializers.Serializer):
    phone = serializers.CharField(validators=[validate_phone])
    password = serializers.CharField() 

    class Meta:
        model = User
        fields = ['id', 'phone', 'password']


    def validate(self, data):

        request = self.context.get('request')
        if not request:
            raise serializers.ValidationError(missing_request)

        phone = data.get('phone')
        password = data.get('password')

        attemp_key = LOGIN_ATTEMPTS_KEY_PREFIX
        attempts = get_or_create_cache_attempt_key(attemp_key, phone)

        if reach_three_attempts(attemp_key, phone, MAX_ATTEMPTS, attempts, LOCKOUT_TIME):
            raise serializers.ValidationError(locked_account_message(attempts))
        
        user = authenticate(request=request, username=phone, password=password)
        
        if user is None:
            raise serializers.ValidationError(invalid_user_message(attempts))

        if user.is_authenticated and (request.user == user) :
            raise serializers.ValidationError(already_logged_in_message())
        
        delete_generated_code_from_cache(attempts, phone)

        return data 


class LogoutUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = []
