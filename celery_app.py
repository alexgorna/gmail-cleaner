import os
from celery import Celery

def make_celery():
    redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    app = Celery('gmail_cleaner', broker=redis_url, backend=redis_url)
    app.conf.update(
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        task_soft_time_limit=1800,   # 30 min — raises SoftTimeLimitExceeded
        task_time_limit=2100,         # 35 min — hard kill
        worker_prefetch_multiplier=1, # One job at a time per worker process
    )
    return app

celery_app = make_celery()
