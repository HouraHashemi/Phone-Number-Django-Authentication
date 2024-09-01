from .models import User

from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle

from django.contrib.auth import authenticate
from django.contrib.auth import authenticate, login 
from django.contrib.auth import logout

from .serializers import RegisterUserSerializer
from .serializers import LoginUserSerializer
from .serializers import VerificationSerializer
from .serializers import GenerateCodeSerializer
from .serializers import LogoutUserSerializer

from .permissions import IsAdminOrSelf
from .utils import *
from .messages import *


import logging
logger = logging.getLogger(__name__)


class GenerateCodeViewSet(viewsets.ViewSet):

    serializer_class = GenerateCodeSerializer

    throttle_classes = [AnonRateThrottle]


    def get_permissions(self):
        if self.request.method in ['GET', 'POST']:
            return super().get_permissions()
        self.permission_denied(self.request, message="Method not allowed")


    # @handle_server_exceptions
    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        code = serializer.save()  # The code is generated and sent in the serializer
        return Response(code_sent_message(code), status=status.HTTP_200_OK)




# ------------------------------------------------
class UserVerificationViewSet(viewsets.ViewSet):

    serializer_class = VerificationSerializer
    throttle_classes = [AnonRateThrottle]


    def get_permissions(self):
        if self.request.method in ['GET', 'POST']:
            return super().get_permissions()
        self.permission_denied(self.request, message="Method not allowed")


    # @handle_server_exceptions
    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(valid_code_message(), status=status.HTTP_200_OK)
 

# ------------------------------------------------
class UserRegisterViewSet(viewsets.ModelViewSet):

    queryset = User.objects.all()
    serializer_class = RegisterUserSerializer

    throttle_classes = [AnonRateThrottle]
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
    

    # @handle_server_exceptions
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


    def perform_create(self, serializer):
        serializer.save()

    

# ------------------------------------------------
class UserLoginViewSet(viewsets.ViewSet):

    serializer_class = LoginUserSerializer
    # UserRateThrottle: This throttle class is used to limit the rate of requests from authenticated users.
    # AnonRateThrottle: This throttle class is used to limit the rate of requests from anonymous (unauthenticated) users.

    throttle_classes = [AnonRateThrottle, UserRateThrottle]


    def get_permissions(self):
        if self.request.method in ['GET', 'POST']:
            return super().get_permissions()
        self.permission_denied(self.request, message="Method not allowed")


    # @handle_server_exceptions
    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        phone = serializer.validated_data.get('phone')
        password = serializer.validated_data.get('password')
       
        user = authenticate(request=request, username=phone, password=password)
        login(request, user)
        return Response(login_successful_message(), status=status.HTTP_200_OK)
        



# ------------------------------------------------
class UserLogoutViewSet(viewsets.ViewSet):
    serializer_class = LogoutUserSerializer

    throttle_classes = [AnonRateThrottle]
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method in ['GET', 'POST']:
            return super().get_permissions()
        self.permission_denied(self.request, message="Method not allowed")


    # @handle_server_exceptions
    def create(self, request, *args, **kwargs):      
        if not request.user.is_authenticated:
            return Response(user_not_auth_message(), status=status.HTTP_401_UNAUTHORIZED)

        logout(request)
        return Response(user_logout_message(), status=status.HTTP_200_OK)
    

       