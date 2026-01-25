import logging
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

from app.core.config import settings
from app.db.session import init_db
from app.api.v1.api import api_router
from app.core.security import get_password_hash
from app.models.user import User, UserRole

# Configure logging
logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    ""
    Lifespan context manager for startup and shutdown events.
    """
    # Startup
    logger.info("Starting up...")
    
    # Initialize database
    logger.info("Initializing database...")
    init_db()
    
    # Create default admin user if it doesn't exist
    await create_default_admin()
    
    yield
    
    # Shutdown
    logger.info("Shutting down...")

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="vuln4 - Web-based Recon & Vulnerability Automation Platform",
    version=settings.VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)

# Set up CORS
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Include API router
app.include_router(api_router, prefix=settings.API_V1_STR)

# Exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    ""
    Handle validation errors and return a clean error response.
    """
    errors = []
    for error in exc.errors():
        field = ".".join(str(loc) for loc in error["loc"] if loc != "body")
        errors.append({
            "field": field if field else "request body",
            "message": error["msg"],
            "type": error["type"],
        })
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Validation error",
            "errors": errors,
        },
    )

# Health check endpoint
@app.get("/health")
async def health_check():
    ""
    Health check endpoint for load balancers and monitoring.
    """
    return {"status": "ok", "service": settings.PROJECT_NAME}

async def create_default_admin():
    ""
    Create a default admin user if no users exist in the database.
    """
    from sqlalchemy import select
    from app.db.session import SessionLocal
    
    db = SessionLocal()
    try:
        # Check if any admin user exists
        stmt = select(User).where(User.role == UserRole.ADMIN)
        admin_user = db.execute(stmt).scalars().first()
        
        if not admin_user:
            # Create default admin user
            default_admin = User(
                email="admin@vuln4.local",
                username="admin",
                hashed_password=get_password_hash("admin"),
                full_name="Admin User",
                role=UserRole.ADMIN,
                is_active=True,
            )
            db.add(default_admin)
            db.commit()
            logger.warning("Default admin user created with username: admin and password: admin")
    except Exception as e:
        logger.error(f"Error creating default admin user: {e}")
        db.rollback()
    finally:
        db.close()
