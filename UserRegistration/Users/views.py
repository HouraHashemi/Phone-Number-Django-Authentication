from .models import User

from .serializers import RegisterUserSerializer
from .serializers import LoginUserSerializer
from .serializers import VerificationSerializer
from .serializers import GenerateCodeSerializer
from .serializers import LogoutUserSerializer

from rest_framework import viewsets
from rest_framework.response import Response, status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated

from django.contrib.auth import authenticate
from django.contrib.auth import authenticate, login 
from django.contrib.auth import logout
from django.utils import timezone
from django.core.cache import cache

from .permissions import IsAdminOrSelf

from datetime import timedelta
import random

# Public auxiliary function
# ------------------------------------------------
VERIFY_CODE_CACHE_PREFIX = 'verify_code_'
VERIFY_CODE_EXPIRATION = 5*60


GENERATE_CODE_ATTEMPTS_KEY_PREFIX = 'generate_code_attempts_'
LOGIN_ATTEMPTS_KEY_PREFIX = 'login_attempts_'
LOCKOUT_TIME = 300  
MAX_ATTEMPTS = 3


# Public auxiliary function
# ------------------------------------------------
def generate_temp_password():
    return random.randint(100000, 999999)


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
class GenerateCodeViewSet(viewsets.ViewSet):

    serializer_class = GenerateCodeSerializer

    def get_permissions(self):
        if self.request.method in ['GET', 'POST']:
            return super().get_permissions()
        self.permission_denied(self.request, message="Method not allowed")


    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            phone = serializer.validated_data.get('phone')
        
        user = User.objects.filter(phone=phone).first()
        if user:
            return Response(self.user_already_verified_message(), status=status.HTTP_409_CONFLICT)
 
        # If user doesn't exist, send verification code | SMS service
        code = generate_temp_password()
        cache.set(f'{VERIFY_CODE_CACHE_PREFIX}{phone}', {'code': code}, VERIFY_CODE_EXPIRATION)

        return Response(self.code_sent_message(code), status=status.HTTP_200_OK)


    ### Private auxiliary functions ----------
    def user_already_verified_message(self):
        response = {
            "message": "User is verified. Proceed to login.",
        }
        return response

    def code_sent_message(self, code):
        response = {
            "verification_code": code,
        }
        return response


# ------------------------------------------------
class UserVerificationViewSet(viewsets.ViewSet):

    serializer_class = VerificationSerializer

    def get_permissions(self):
        if self.request.method in ['GET', 'POST']:
            return super().get_permissions()
        self.permission_denied(self.request, message="Method not allowed")


    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            code = serializer.validated_data.get('code')
            phone = serializer.validated_data.get('phone')
            
            verification_code = cache.get(f'{VERIFY_CODE_CACHE_PREFIX}{phone}')
            if verification_code == None:
                return Response(self.code_expiration_message(), status=status.HTTP_410_GONE)
            
            expected_code = verification_code['code']
            attempts = get_or_create_cache_attempt_key(GENERATE_CODE_ATTEMPTS_KEY_PREFIX, phone)

            if reach_three_attempts( GENERATE_CODE_ATTEMPTS_KEY_PREFIX, phone, MAX_ATTEMPTS, attempts, LOCKOUT_TIME):
                return Response(self.locked_account_message(attempts), status=status.HTTP_423_LOCKED)
            
            if (not self.is_expected_code(code, expected_code)):
                raise ValidationError(self.invalid_code_message(attempts))
            
            cache.delete(f'{GENERATE_CODE_ATTEMPTS_KEY_PREFIX}{phone}')

            return Response(self.valid_code_message(), status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

    ### Private auxiliary functions ----------
    def is_expected_code(self, code, expected_code):
        if (str(code) == str(expected_code)):
            return True
        return False


    def valid_code_message(self):
        response = {
            "message": "Code verified. Proceed to registration.",
        }
        return response
    
    def code_expiration_message(self):
        response = {
            "message": "Verification code is expired.",
        }
        return response
    
    def invalid_code_message(self, attempts):
        response = {
            "error": "Invalid verification code.",
            "attempts": attempts
        }
        return response

    def locked_account_message(self, attempts):
        response = {
            "error": "Account is locked. Please try again later.",
            "attempts": attempts
        }
        return response


# ------------------------------------------------
class UserRegisterViewSet(viewsets.ModelViewSet):

    queryset = User.objects.all()
    serializer_class = RegisterUserSerializer

    # permission_classes = [IsAdminOrSelf]

    def get_permissions(self):
        if self.request.method in ['GET', 'POST']:
            return super().get_permissions()
        self.permission_denied(self.request, message="Method not allowed")


    def get_queryset(self):
        queryset = super().get_queryset()
        phone = self.request.query_params.get('phone')
        if phone:
            queryset = queryset.filter(phone=phone)
        return queryset
    

    def create(self, request, *args, **kwargs):
        # Fetch the phone number from the request data
        phone = request.data.get('phone')
        code = cache.get(f'{VERIFY_CODE_CACHE_PREFIX}{phone}')
        if code == None:
            return Response(self.code_expiration_message(), status=status.HTTP_410_GONE)

        if not phone:
            return Response(self.phone_required_message(), status=status.HTTP_400_BAD_REQUEST)
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)
    

    def perform_create(self, serializer):
        serializer.save()


    ### Private auxiliary functions ----------
    def code_expiration_message(self):
        response = {
            "message": "Verification code is expired.",
        }
        return response
     
    def phone_required_message(self):
        response = {
            "error": "Phone number is required."
        }
        return response
    

# ------------------------------------------------
class UserLoginViewSet(viewsets.ViewSet):

    serializer_class = LoginUserSerializer

    def get_permissions(self):
        if self.request.method in ['GET', 'POST']:
            return super().get_permissions()
        self.permission_denied(self.request, message="Method not allowed")


    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone = serializer.validated_data.get('phone')
        password = serializer.validated_data.get('password')
        
        attempts = get_or_create_cache_attempt_key(LOGIN_ATTEMPTS_KEY_PREFIX, phone)

        if reach_three_attempts( LOGIN_ATTEMPTS_KEY_PREFIX, phone, MAX_ATTEMPTS, attempts, LOCKOUT_TIME):
            return Response(self.locked_account_message(attempts), status=status.HTTP_423_LOCKED)

        user = authenticate(request, phone=phone, password=password)

        if user == request.user:
            return Response(self.already_logged_in_message(), status=status.HTTP_409_CONFLICT)

        if (not self.is_user_authenticated(user)):
            return Response(self.invalid_user_message(attempts), status=status.HTTP_401_UNAUTHORIZED)

        cache.delete(f'{LOGIN_ATTEMPTS_KEY_PREFIX}{phone}')
        login(request, user)

        return Response(self.login_successful_message(), status=status.HTTP_200_OK)
    

    ### Private auxiliary functions ----------
    def is_user_authenticated(self, user):
        if user is not None:
            return True
        return False
    

    def locked_account_message(self, attempts):
        response = {
            "error": "Account is locked. Please try again later.",
            "attempts": attempts
        }
        return response

    def invalid_user_message(self, attempts):
        response = {
            "error": "Invalid phone number or password.",
            "attempts": attempts
        }
        return response

    def login_successful_message(self):
        response = {
                "message": "Login successful.",
        }
        return response
    
    def already_logged_in_message(self):
        response = {
            "error": "This user is already logged in."
        }
        return response


# ------------------------------------------------
class UserLogoutViewSet(viewsets.ViewSet):
    serializer_class = LogoutUserSerializer

    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method in ['GET', 'POST']:
            return super().get_permissions()
        self.permission_denied(self.request, message="Method not allowed")


    def create(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response(self.user_not_auth_message(), status=status.HTTP_401_UNAUTHORIZED)

        logout(request)
        return Response(self.user_logout_message(), status=status.HTTP_200_OK)
    

    ### Private auxiliary functions ----------
    def user_logout_message(self):
        response = {
            "message": "Logout successful",
        }
        return response
    
    def user_not_auth_message(self):
        response = {
            "error": "User does not authenticated.",
        }
        return response


       