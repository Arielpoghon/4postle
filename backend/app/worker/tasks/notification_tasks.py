import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from celery import shared_task
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.scan import Scan
from app.models.user import User
from app.core.config import settings

logger = logging.getLogger(__name__)

@shared_task
def send_scan_completed_notification(scan_id: int):
    """
    Send a notification when a scan is completed.
    
    Args:
        scan_id: ID of the completed scan
    """
    db = SessionLocal()
    try:
        # Get the scan and its owner
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan with ID {scan_id} not found")
            return
            
        user = scan.owner
        if not user:
            logger.error(f"Owner not found for scan {scan_id}")
            return
            
        # Prepare notification data
        notification_data = {
            "scan_id": scan.id,
            "scan_name": scan.name,
            "status": scan.status,
            "target": scan.target.target if scan.target else "Unknown",
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "vulnerability_count": 0,
            "critical_count": 0,
            "high_count": 0,
        }
        
        # Add vulnerability counts if available
        if scan.results_summary and "vulnerability_count" in scan.results_summary:
            notification_data["vulnerability_count"] = scan.results_summary["vulnerability_count"]
            
        if scan.results_summary and "severity_counts" in scan.results_summary:
            severity_counts = scan.results_summary["severity_counts"]
            notification_data["critical_count"] = severity_counts.get("critical", 0)
            notification_data["high_count"] = severity_counts.get("high", 0)
        
        # TODO: Implement actual notification delivery
        # This could be email, webhook, Slack, etc.
        logger.info(
            f"Sending scan completed notification to {user.email} for scan {scan_id}"
        )
        
        # For now, just log the notification
        logger.debug(f"Notification data: {notification_data}")
        
    except Exception as e:
        logger.error(
            f"Error sending scan completed notification for scan {scan_id}: {str(e)}",
            exc_info=True
        )
    finally:
        db.close()

@shared_task
def send_vulnerability_alert(vulnerability_id: int, user_ids: List[int] = None):
    """
    Send an alert for a newly discovered vulnerability.
    
    Args:
        vulnerability_id: ID of the vulnerability
        user_ids: Optional list of user IDs to notify (defaults to all admins)
    """
    from app.models.vulnerability import Vulnerability
    
    db = SessionLocal()
    try:
        # Get the vulnerability
        vulnerability = db.query(Vulnerability).filter(
            Vulnerability.id == vulnerability_id
        ).first()
        
        if not vulnerability:
            logger.error(f"Vulnerability with ID {vulnerability_id} not found")
            return
            
        # Get users to notify
        query = db.query(User)
        if user_ids:
            query = query.filter(User.id.in_(user_ids))
        else:
            # Default to notifying all admins
            query = query.filter(User.role == "admin")
            
        users = query.all()
        
        # Prepare notification data
        notification_data = {
            "vulnerability_id": vulnerability.id,
            "title": vulnerability.title,
            "severity": vulnerability.severity,
            "target": vulnerability.target.target if vulnerability.target else "Unknown",
            "discovered_at": vulnerability.created_at.isoformat(),
            "scan_id": vulnerability.scan_id,
            "cve_id": vulnerability.cve_id,
            "cwe_id": vulnerability.cwe_id,
        }
        
        # Send notifications to each user
        for user in users:
            # TODO: Implement actual notification delivery
            logger.info(
                f"Sending vulnerability alert to {user.email} for "
                f"vulnerability {vulnerability_id}"
            )
            
            # For now, just log the notification
            logger.debug(f"Vulnerability alert data for {user.email}: {notification_data}")
            
    except Exception as e:
        logger.error(
            f"Error sending vulnerability alert for vulnerability {vulnerability_id}: {str(e)}",
            exc_info=True
        )
    finally:
        db.close()

@shared_task
def send_daily_digest():
    """
    Send a daily digest of scan results and vulnerabilities.
    """
    from sqlalchemy import func, and_
    from app.models.scan import Scan, ScanStatus
    from app.models.vulnerability import Vulnerability
    
    db = SessionLocal()
    try:
        # Get all admin users
        admins = db.query(User).filter(User.role == "admin").all()
        if not admins:
            logger.warning("No admin users found to send daily digest to")
            return
            
        # Calculate time range for the last 24 hours
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=1)
        
        # Get scan statistics
        scan_stats = db.query(
            func.count(Scan.id).label("total_scans"),
            func.sum(case([(Scan.status == ScanStatus.COMPLETED, 1)], else_=0)).label("completed_scans"),
            func.sum(case([(Scan.status == ScanStatus.FAILED, 1)], else_=0)).label("failed_scans"),
        ).filter(
            Scan.created_at >= start_time,
            Scan.created_at <= end_time
        ).first()
        
        # Get vulnerability statistics
        vuln_stats = db.query(
            Vulnerability.severity,
            func.count(Vulnerability.id).label("count")
        ).filter(
            Vulnerability.created_at >= start_time,
            Vulnerability.created_at <= end_time
        ).group_by(Vulnerability.severity).all()
        
        # Prepare digest data
        digest_data = {
            "period": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
            },
            "scans": {
                "total": scan_stats.total_scans or 0,
                "completed": scan_stats.completed_scans or 0,
                "failed": scan_stats.failed_scans or 0,
                "in_progress": (scan_stats.total_scans or 0) - 
                              ((scan_stats.completed_scans or 0) + (scan_stats.failed_scans or 0)),
            },
            "vulnerabilities": {severity: count for severity, count in vuln_stats},
            "new_targets": db.query(Target).filter(
                Target.created_at >= start_time,
                Target.created_at <= end_time
            ).count(),
        }
        
        # Send digest to each admin
        for admin in admins:
            # TODO: Implement actual digest delivery
            logger.info(
                f"Sending daily digest to {admin.email} for {end_time.date()}"
            )
            
            # For now, just log the digest
            logger.debug(f"Daily digest data for {admin.email}: {digest_data}")
            
    except Exception as e:
        logger.error(f"Error generating daily digest: {str(e)}", exc_info=True)
    finally:
        db.close()
