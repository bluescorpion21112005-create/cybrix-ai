"""
backend/app/main.py — FastAPI scanner service entry point.
"""
import logging
import os

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.database import Base, engine

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Allowed origins — comma-separated in env var
_raw = os.getenv("ALLOWED_ORIGINS", "http://localhost:5000,http://127.0.0.1:5000")
ALLOWED_ORIGINS = [o.strip() for o in _raw.split(",") if o.strip()]

app = FastAPI(
    title="AI Pentest System API",
    description="AI-powered web vulnerability scanner",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# Create DB tables on startup
Base.metadata.create_all(bind=engine)
logger.info("Database tables ready.")

app.include_router(router, prefix="/api/v1")


@app.get("/", tags=["health"])
async def root():
    return {"service": "AI Pentest API", "version": "1.0.0", "status": "ok"}


@app.get("/health", tags=["health"])
async def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)
