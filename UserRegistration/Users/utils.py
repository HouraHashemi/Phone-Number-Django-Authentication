
from datetime import timedelta
from django.utils import timezone

import random
from django.core.cache import cache
from functools import wraps

from rest_framework.response import Response
from rest_framework import status

VERIFY_CODE_CACHE_PREFIX = 'verify_code_'
 


#==========================
# decorators 
#==========================
def handle_server_exceptions(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        try:
            return view_func(request, *args, **kwargs)
        except Exception as e:
            return Response(unavailable_server(), status=status.HTTP_503_SERVICE_UNAVAILABLE)

    return _wrapped_view


#==========================
# utils functions
#==========================
def generate_temp_password():
    return random.randint(100000, 999999)


def get_or_create_cache_attempt_key(cache_key, phone):
    attempts = cache.get(f'{cache_key}{phone}')
    if attempts == None:
        attempts = {'count': 0, 'lockout_until': None}
    return attempts


def reach_three_attempts(cache_key, phone, max_attempts, attempts, lockout_time):
    if attempts['count'] == 3:
        return True
    attempts['count'] += 1
    if attempts['count'] >= max_attempts:
        attempts['lockout_until'] = timezone.now() + timedelta(seconds=lockout_time)

    cache.set(f'{cache_key}{phone}', attempts)

    if attempts['lockout_until'] and (timezone.now() < attempts['lockout_until']):
        return True
    return False


def set_verification_code_to_cache(key, phone, data, expiration_time):
    cache.set(f'{key}{phone}', data, expiration_time)
    return cache



def get_verification_code_from_cache(key, phone):
    return cache.get(f'{key}{phone}')


def delete_generated_code_from_cache(key, phone):    
    cache.delete(f'{key}{phone}')
    

#==========================
# Responses
#==========================

# Generate Code
# ------------------------
def code_sent_message(code):
    return {
        "verification_code": code,
    }


def unavailable_server():
    return {"error": "Service is temporarily unavailable, please try again later."}
    # (check redis-celery-docker or Invalid input(cache is empty.)
    
#==========================

# User Verification 
# ------------------------
def is_expected_code(code, expected_code):
    return (str(code) == str(expected_code))


def valid_code_message():
    return{"message": "Code verified. Proceed to registration."}


def code_expiration_message():
    return {"message": "Verification code is expired."}


def invalid_code_message(attempts):
    return {
        "error": "Invalid verification code.",
        "attempts": attempts
    }


def locked_account_message(attempts):
    return {
        "error": "Account is locked. Please try again later.",
        "attempts": attempts
    }
#==========================

# User Registration 
# ------------------------
def code_expiration_message():
    return {"message": "Verification code is expired.",}

    
def phone_required_message():
    return {"error": "Phone number is required."}

#==========================

# User Login 
# ------------------------
def is_user_authenticated(user):
    return (user is not None)


def invalid_user_message(attempts):
    return {
        "error": "Invalid phone number or password.",
        "attempts": attempts
    }


def login_successful_message():
    return {"message": "Login successful."}
    

def already_logged_in_message():
    return {"error": "This user is already logged in."}


def missing_request():
    return {"error":"Request context is missing."}


def authentication_failed():
    return {"detail": "Authentication failed."}

#==========================

# User logout 
# ------------------------
def user_logout_message():
    return {"message": "Logout successful"}


def user_not_auth_message():
    return {"error": "User does not authenticated."}
