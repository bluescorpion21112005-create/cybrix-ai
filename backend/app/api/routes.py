"""
backend/app/api/routes.py — FastAPI scanner API endpoints.
"""
import logging
import os
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ScanResult
from app.scanner.reporters import ReportGenerator
from app.scanner.vulnerability_scanner import VulnerabilityScanner

logger = logging.getLogger(__name__)
router = APIRouter()
scanner = VulnerabilityScanner()

SUPPORTED_FORMATS = {"html", "pdf", "json", "md"}


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str
    scan_type: str = "full"  # quick | full | ai_enhanced


class ScanResponse(BaseModel):
    scan_id: int
    status: str
    message: str


class VulnerabilityInfo(BaseModel):
    type: str
    severity: str
    description: str
    remediation: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_scan_or_404(scan_id: int, db: Session) -> ScanResult:
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


async def _perform_scan(scan_id: int, url: str, scan_type: str, db: Session) -> None:
    """Background scan task."""
    scan = _get_scan_or_404(scan_id, db)
    try:
        scan.status = "running"
        db.commit()

        results = (
            await scanner.quick_scan(url)
            if scan_type == "quick"
            else await scanner.deep_scan(url)
        )

        scan.status = "completed"
        scan.end_time = datetime.utcnow()
        scan.vulnerabilities = results.get("vulnerabilities", [])
        scan.summary = results.get("summary", {})

        report_gen = ReportGenerator(results)
        scan.report_path = report_gen.generate_html_report()
        db.commit()

    except Exception as exc:
        logger.exception("Scan failed (id=%s): %s", scan_id, exc)
        scan = _get_scan_or_404(scan_id, db)
        scan.status = "failed"
        scan.summary = {"error": str(exc)}
        db.commit()


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/scan", response_model=ScanResponse, status_code=202)
async def start_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Start a new vulnerability scan."""
    try:
        scan = ScanResult(
            target_url=scan_request.url,
            scan_type=scan_request.scan_type,
            status="pending",
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        background_tasks.add_task(
            _perform_scan,
            scan_id=scan.id,
            url=scan_request.url,
            scan_type=scan_request.scan_type,
            db=db,
        )
        return ScanResponse(scan_id=scan.id, status="pending", message="Scan started")

    except Exception as exc:
        logger.exception("start_scan error: %s", exc)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/scan/{scan_id}")
async def get_scan_status(scan_id: int, db: Session = Depends(get_db)):
    """Get scan status and results."""
    return _get_scan_or_404(scan_id, db).to_dict()


@router.get("/scan/{scan_id}/report/{fmt}")
async def get_report(scan_id: int, fmt: str, db: Session = Depends(get_db)):
    """Download scan report (html, pdf, json, md)."""
    if fmt not in SUPPORTED_FORMATS:
        raise HTTPException(status_code=400, detail=f"Supported formats: {SUPPORTED_FORMATS}")

    scan = _get_scan_or_404(scan_id, db)
    if scan.status != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")

    report_gen = ReportGenerator(scan.to_dict())
    handlers = {
        "html": report_gen.generate_html_report,
        "pdf":  report_gen.generate_pdf_report,
        "json": report_gen.generate_json_report,
        "md":   report_gen.generate_markdown_report,
    }
    try:
        filepath = handlers[fmt]()
    except Exception as exc:
        logger.exception("Report generation failed: %s", exc)
        raise HTTPException(status_code=500, detail="Report generation failed")

    return FileResponse(
        filepath,
        media_type="application/octet-stream",
        filename=os.path.basename(filepath),
    )


@router.get("/scans")
async def get_all_scans(
    skip: int = 0, limit: int = 10, db: Session = Depends(get_db)
):
    """List all scans (paginated)."""
    limit = min(limit, 100)
    scans = (
        db.query(ScanResult)
        .order_by(ScanResult.start_time.desc())
        .offset(skip).limit(limit).all()
    )
    return [s.to_dict() for s in scans]


@router.delete("/scan/{scan_id}", status_code=200)
async def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Delete a scan record."""
    scan = _get_scan_or_404(scan_id, db)
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted"}


@router.get("/vulnerability-types")
async def get_vulnerability_types():
    """List supported vulnerability types."""
    return scanner.get_vulnerability_types()


@router.post("/batch-scan", status_code=202)
async def batch_scan(
    urls: List[str],
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Scan multiple URLs."""
    if not urls:
        raise HTTPException(status_code=400, detail="URL list is empty")

    scan_ids = []
    for url in urls:
        scan = ScanResult(target_url=url, scan_type="quick", status="pending")
        db.add(scan)
        db.commit()
        db.refresh(scan)
        background_tasks.add_task(_perform_scan, scan.id, url, "quick", db)
        scan_ids.append(scan.id)

    return {"scan_ids": scan_ids, "count": len(scan_ids)}


@router.post("/upload-scan", status_code=202)
async def upload_scan(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db),
):
    """Upload a file of URLs and scan them all."""
    try:
        content = await file.read()
        urls = [u.strip() for u in content.decode().splitlines() if u.strip()]
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not read file: {exc}")

    if not urls:
        raise HTTPException(status_code=400, detail="No valid URLs in file")

    return await batch_scan(urls, background_tasks, db)
