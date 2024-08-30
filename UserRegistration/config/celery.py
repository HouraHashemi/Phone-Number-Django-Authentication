import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

celery = Celery('config')
celery.config_from_object('django.conf:settings', namespace='CELERY')
celery.autodiscover_tasks()


celery.conf.update(
    broker_connection_retry_on_startup=True,  # Set to True to retain the existing behavior
    # other Celery settings...
)