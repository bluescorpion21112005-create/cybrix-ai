from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, UploadFile, File
from fastapi.responses import FileResponse, JSONResponse
from typing import List, Optional
from pydantic import BaseModel, HttpUrl
from datetime import datetime
import os
import uuid

from app.scanner.vulnerability_scanner import VulnerabilityScanner
from app.scanner.reporters import ReportGenerator
from app.models import ScanResult, User
from app.database import get_db
from sqlalchemy.orm import Session

router = APIRouter()
scanner = VulnerabilityScanner()

class ScanRequest(BaseModel):
    url: str
    scan_type: str = "full"  # quick, full, ai_enhanced
    
class ScanResponse(BaseModel):
    scan_id: int
    status: str
    message: str

class VulnerabilityInfo(BaseModel):
    type: str
    severity: str
    description: str
    remediation: Optional[str] = None

@router.post("/scan", response_model=ScanResponse)
async def start_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Yangi skanerlashni boshlash"""
    try:
        # Yangi scan yozuvini yaratish
        scan_result = ScanResult(
            target_url=scan_request.url,
            scan_type=scan_request.scan_type,
            status="pending"
        )
        db.add(scan_result)
        db.commit()
        db.refresh(scan_result)
        
        # Backgroundda skanerlashni boshlash
        background_tasks.add_task(
            perform_scan,
            scan_id=scan_result.id,
            url=scan_request.url,
            scan_type=scan_request.scan_type,
            db=db
        )
        
        return ScanResponse(
            scan_id=scan_result.id,
            status="pending",
            message="Skanerlash boshlandi"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan/{scan_id}")
async def get_scan_status(scan_id: int, db: Session = Depends(get_db)):
    """Skanerlash holatini olish"""
    scan_result = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan_result:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_result.to_dict()

@router.get("/scan/{scan_id}/report/{format}")
async def get_report(scan_id: int, format: str, db: Session = Depends(get_db)):
    """Hisobotni olish (html, pdf, json, md)"""
    scan_result = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan_result:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan_result.status != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    
    # Hisobot yaratish
    report_gen = ReportGenerator(scan_result.to_dict())
    
    if format == "html":
        filepath = report_gen.generate_html_report()
    elif format == "pdf":
        filepath = report_gen.generate_pdf_report()
    elif format == "json":
        filepath = report_gen.generate_json_report()
    elif format == "md":
        filepath = report_gen.generate_markdown_report()
    else:
        raise HTTPException(status_code=400, detail="Unsupported format")
    
    return FileResponse(
        filepath,
        media_type='application/octet-stream',
        filename=os.path.basename(filepath)
    )

@router.get("/scans")
async def get_all_scans(
    skip: int = 0,
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """Barcha skanerlashlarni olish"""
    scans = db.query(ScanResult).order_by(
        ScanResult.start_time.desc()
    ).offset(skip).limit(limit).all()
    
    return [scan.to_dict() for scan in scans]

@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Skanerlashni o'chirish"""
    scan_result = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan_result:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    db.delete(scan_result)
    db.commit()
    
    return {"message": "Scan deleted successfully"}

@router.get("/vulnerability-types")
async def get_vulnerability_types():
    """Qo'llab-quvvatlanadigan zaiflik turlari"""
    return scanner.get_vulnerability_types()

async def perform_scan(scan_id: int, url: str, scan_type: str, db: Session):
    """Background skanerlash funksiyasi"""
    try:
        # Statusni yangilash
        scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        scan.status = "running"
        db.commit()
        
        # Skanerlashni amalga oshirish
        if scan_type == "quick":
            results = await scanner.quick_scan(url)
        else:
            results = await scanner.deep_scan(url)
        
        # Natijalarni saqlash
        scan.status = "completed"
        scan.end_time = datetime.utcnow()
        scan.vulnerabilities = results.get('vulnerabilities', [])
        scan.summary = results.get('summary', {})
        
        # Hisobot yaratish
        report_gen = ReportGenerator(results)
        report_path = report_gen.generate_html_report()
        scan.report_path = report_path
        
        db.commit()
        
    except Exception as e:
        # Xatolik yuz berganda
        scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        scan.status = "failed"
        scan.summary = {"error": str(e)}
        db.commit()

# Batch skanerlash
@router.post("/batch-scan")
async def batch_scan(
    urls: List[str],
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Bir nechta URL larni skanerlash"""
    scan_ids = []
    
    for url in urls:
        scan_result = ScanResult(
            target_url=url,
            scan_type="quick",
            status="pending"
        )
        db.add(scan_result)
        db.commit()
        db.refresh(scan_result)
        
        background_tasks.add_task(
            perform_scan,
            scan_id=scan_result.id,
            url=url,
            scan_type="quick",
            db=db
        )
        
        scan_ids.append(scan_result.id)
    
    return {"scan_ids": scan_ids, "count": len(scan_ids)}

# Fayl yuklash orqali skanerlash
@router.post("/upload-scan")
async def upload_scan(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db)
):
    """Fayl yuklash orqali skanerlash"""
    try:
        # Faylni saqlash
        content = await file.read()
        urls = content.decode().split('\n')
        urls = [url.strip() for url in urls if url.strip()]
        
        if not urls:
            raise HTTPException(status_code=400, detail="No valid URLs found")
        
        # Skanerlashni boshlash
        return await batch_scan(urls, background_tasks, db)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))