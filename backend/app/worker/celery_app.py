from celery import Celery
from celery.signals import worker_ready
from app.core.config import settings

# Initialize Celery
celery_app = Celery(
    "vuln4_worker",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.worker.tasks"],
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    worker_max_tasks_per_child=100,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_track_started=True,
)

# Create database tables on worker startup
@worker_ready.connect
def on_worker_ready(**_):
    from app.db.session import init_db
    init_db()

if __name__ == "__main__":
    celery_app.start()
