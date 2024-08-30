from celery import shared_task


from django.core.cache import cache

from datetime import timedelta
from django.utils import timezone

from .utils import generate_temp_password


@shared_task
def send_verification_code(phone, code):
    message = "This is SMS of OTP: {} | {}".format(phone, code) 
    # send_sms(phone, message)  # Implement this function with SMS service
