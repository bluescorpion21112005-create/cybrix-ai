from fastapi import FastAPI, File, UploadFile, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
import uvicorn
import os
from dotenv import load_dotenv

from app.api.routes import router
from app.database import engine, Base
from app.models import User, ScanResult

load_dotenv()

app = FastAPI(
    title="AI Pentest System API",
    description="AI asosida veb-saytlarni xavfsizlikka tekshirish tizimi",
    version="1.0.0"
)

# CORS sozlamalari
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ma'lumotlar bazasini yaratish
Base.metadata.create_all(bind=engine)

# Routerlarni ulash
app.include_router(router, prefix="/api/v1")

security = HTTPBearer()

@app.get("/")
async def root():
    return {
        "message": "AI Pentest System API",
        "version": "1.0.0",
        "status": "active"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=True
    )