from .models import User
from .serializers import RegisterUserSerializer
from .serializers import LoginUserSerializer
from .serializers import VerificationSerializer
from .serializers import GenerateCodeSerializer
from .serializers import LogoutUserSerializer
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from datetime import timedelta

from rest_framework.exceptions import ValidationError
import random

from rest_framework.permissions import IsAuthenticated

from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import authenticate, login 
from django.contrib.auth import logout

from django.core.cache import cache
from .permissions import IsAdminOrSelf

from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator


# ------------------------------------------------
VERIFY_CODE_CACHE_PREFIX = 'verify_code_'
VERIFY_CODE_EXPIRATION = 5*60


GENERATE_CODE_ATTEMPTS_KEY_PREFIX = 'generate_code_attempts_'
LOGIN_ATTEMPTS_KEY_PREFIX = 'login_attempts_'
LOCKOUT_TIME = 300  
MAX_ATTEMPTS = 3


# ------------------------------------------------
def generate_temp_password():
    return random.randint(100000, 999999)


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
        # if user verified
        user = User.objects.filter(phone=phone).first()
        if user:
            response = {
                "message": "User is verified. Proceed to login.",
            }
            return Response(response, status=status.HTTP_200_OK)
 
        # If user doesn't exist, send verification code | SMS service
        code = generate_temp_password()
        cache.set(f'{VERIFY_CODE_CACHE_PREFIX}{phone}', {'code': code}, VERIFY_CODE_EXPIRATION)

        response = {
            "verification_code": code,
        }
        return Response(response, status=status.HTTP_200_OK)


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
                response = {
                    "message": "Code is expired.",
                }
                return Response(response, status=status.HTTP_403_FORBIDDEN)
            expected_code = verification_code['code']


            # Cache key based on phone number
            attempts = cache.get(f'{GENERATE_CODE_ATTEMPTS_KEY_PREFIX}{phone}')
            if attempts == None:
                attempts = {'count': 0, 'lockout_until': None}


            if attempts['lockout_until'] and (timezone.now() < attempts['lockout_until']):
                response = {
                    "error": "Account is locked. Please try again later.",
                    "attempts": attempts
                }
                return Response(response, status=status.HTTP_403_FORBIDDEN)


            attempts['count'] += 1
            if attempts['count'] >= MAX_ATTEMPTS:
                attempts['lockout_until'] = timezone.now() + timedelta(seconds=LOCKOUT_TIME)
            cache.set(f'{GENERATE_CODE_ATTEMPTS_KEY_PREFIX}{phone}', attempts)

            if not expected_code:
                response = {
                    "error": "Session expired. Please start again.",
                    "attempts": attempts
                }
                raise ValidationError(response)
            
            if (str(code) != str(expected_code)):
                response = {
                    "error": "Invalid verification code.",
                    "attempts": attempts
                }
                raise ValidationError(response)
            
            cache.delete(f'{GENERATE_CODE_ATTEMPTS_KEY_PREFIX}{phone}')

            response = {
                "message": "Code verified. Proceed to registration.",
             }
            return Response(response, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
            response = {
                "error": "Verification code is expired."
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

        if not phone:
            response = {
                "error": "Phone number is required."
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)
    

    def perform_create(self, serializer):
        serializer.save()


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

        
        # Cache key based on phone number
        attempts = cache.get(f'{LOGIN_ATTEMPTS_KEY_PREFIX}{phone}')
        if attempts == None:
            attempts = {'count': 0, 'lockout_until': None}


        # Check if the account is locked out
        if attempts['lockout_until'] and (timezone.now() < attempts['lockout_until']):
            response = {
                "error": "Account is locked. Please try again later.",
                "attempts": attempts

            }
            return Response(response, status=status.HTTP_403_FORBIDDEN)

        # Authenticate the user
        user = authenticate(request, phone=phone, password=password)
        if user == request.user:
            response = {
                "error": "This user is already logged in."
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)

        # Incrising loggin attempts
        if user is None:
            attempts['count'] += 1
            if attempts['count'] >= MAX_ATTEMPTS:
                attempts['lockout_until'] = timezone.now() + timedelta(seconds=LOCKOUT_TIME)
            cache.set(f'{LOGIN_ATTEMPTS_KEY_PREFIX}{phone}', attempts)
            response = {
                "error": "Invalid phone number or password.",
                "attempts": attempts
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)


        cache.delete(f'{LOGIN_ATTEMPTS_KEY_PREFIX}{phone}')
        login(request, user)

        response = {
                "message": "Login successful.",
        }
        return Response(response, status=status.HTTP_200_OK)
    

# ------------------------------------------------
# @method_decorator(csrf_exempt, name='dispatch')
class UserLogoutViewSet(viewsets.ViewSet):
    serializer_class = LogoutUserSerializer

    permission_classes = [IsAuthenticated]


    def get_permissions(self):
        if self.request.method in ['GET', 'POST']:
            return super().get_permissions()
        self.permission_denied(self.request, message="Method not allowed")


    def create(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            response = {
                "error": "User does not authenticated.",
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

        logout(request)

        response = {
            "message": "Logout successful",
        }
        return Response(response, status=status.HTTP_200_OK)


       