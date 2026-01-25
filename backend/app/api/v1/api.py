from fastapi import APIRouter
from .endpoints import auth, scans, targets, users, vulnerabilities

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(targets.router, prefix="/targets", tags=["Targets"])
api_router.include_router(scans.router, prefix="/scans", tags=["Scans"])
api_router.include_router(
    vulnerabilities.router, 
    prefix="/vulnerabilities", 
    tags=["Vulnerabilities"]
)
