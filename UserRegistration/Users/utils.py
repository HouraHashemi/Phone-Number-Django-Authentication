
from datetime import timedelta
from django.utils import timezone

import random
from django.core.cache import cache
from functools import wraps

from rest_framework.response import Response
from rest_framework import status

from .messages import *

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
    
