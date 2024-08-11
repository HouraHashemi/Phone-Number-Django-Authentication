# myartsite/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
# from .views import ArtworkViewSet, CategoryViewSet
from . import views

router = DefaultRouter()
router.register(r'generate-code', views.GenerateCodeViewSet, basename='generate-code')
router.register(r'user-verification', views.UserVerificationViewSet, basename='user-verification')
router.register(r'user-register', views.UserRegisterViewSet, basename='user-register')
router.register(r'user-login', views.UserLoginViewSet, basename='user-login')
router.register(r'user-logout', views.UserLogoutViewSet, basename='user-logout')


urlpatterns = [
    path('', include(router.urls)),
] 
