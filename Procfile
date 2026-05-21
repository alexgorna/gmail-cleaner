web: gunicorn app:app --timeout 600 --log-level info
worker: celery -A tasks worker --loglevel=info --concurrency=2