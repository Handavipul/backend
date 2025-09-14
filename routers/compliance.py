from fastapi import APIRouter, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import logging

from backend.config import settings
from backend.database import get_db, User, Transaction, BiometricAudit
from backend.routers.payment import verify_token

router = APIRouter()
security = HTTPBearer()

class ComplianceReport(BaseModel):
    user_id: int
    period_start: datetime
    period_end: datetime
    total_transactions: int
    total_amount: float
    successful_auths: int
    failed_auths: int
    average_confidence: float
    risk_score: float

class AuditLogEntry(BaseModel):
    id: int
    user_id: int
    action: str
    confidence_score: float
    liveness_check: bool
    ip_address: str
    timestamp: datetime
    success: bool

@router.get("/audit-log", response_model=List[AuditLogEntry])
async def get_audit_log(
    db: Session = Depends(get_db),
    user_id: int = Depends(verify_token),
    limit: int = 100,
    offset: int = 0
):
    """Get biometric audit log for compliance"""
    try:
        # Admin users can see all logs, regular users only their own
        query = db.query(BiometricAudit)
        
        # For demo, assume user with ID 1 is admin
        if user_id != 1:
            query = query.filter(BiometricAudit.user_id == user_id)
        
        audits = query.order_by(BiometricAudit.timestamp.desc()).offset(offset).limit(limit).all()
        
        return [
            AuditLogEntry(
                id=audit.id,
                user_id=audit.user_id,
                action=audit.action,
                confidence_score=audit.confidence_score,
                liveness_check=audit.liveness_check,
                ip_address=audit.ip_address,
                timestamp=audit.timestamp,
                success=audit.success
            )
            for audit in audits
        ]

    except Exception as e:
        logging.error(f"Audit log retrieval error: {e}")
        raise HTTPException(status_code=500, detail=f"Audit log error: {str(e)}")

@router.get("/compliance-report", response_model=ComplianceReport)
async def generate_compliance_report(
    db: Session = Depends(get_db),
    user_id: int = Depends(verify_token),
    days: int = 30
):
    """Generate compliance report for specified period"""
    try:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # For admin users, generate system-wide report
        if user_id == 1:
            user_filter = True
            report_user_id = 0  # System-wide
        else:
            user_filter = Transaction.user_id == user_id
            report_user_id = user_id

        # Get transaction statistics
        transaction_stats = db.query(
            func.count(Transaction.id).label('total_transactions'),
            func.sum(Transaction.amount).label('total_amount')
        ).filter(
            and_(
                user_filter,
                Transaction.created_at >= start_date,
                Transaction.created_at <= end_date
            )
        ).first()

        # Get authentication statistics
        auth_stats = db.query(
            func.count(BiometricAudit.id).label('total_auths'),
            func.sum(func.cast(BiometricAudit.success, db.Integer)).label('successful_auths'),
            func.avg(BiometricAudit.confidence_score).label('avg_confidence')
        ).filter(
            and_(
                BiometricAudit.user_id == user_id if user_id != 1 else True,
                BiometricAudit.timestamp >= start_date,
                BiometricAudit.timestamp <= end_date
            )
        ).first()

        # Calculate risk score based on various factors
        failed_auths = (auth_stats.total_auths or 0) - (auth_stats.successful_auths or 0)
        failure_rate = failed_auths / max(auth_stats.total_auths or 1, 1)
        avg_confidence = auth_stats.avg_confidence or 0

        # Simple risk scoring algorithm
        risk_score = (failure_rate * 50) + ((1 - avg_confidence) * 30) + (min(transaction_stats.total_transactions or 0, 10) * 2)
        risk_score = min(risk_score, 100)  # Cap at 100

        return ComplianceReport(
            user_id=report_user_id,
            period_start=start_date,
            period_end=end_date,
            total_transactions=transaction_stats.total_transactions or 0,
            total_amount=transaction_stats.total_amount or 0.0,
            successful_auths=auth_stats.successful_auths or 0,
            failed_auths=failed_auths,
            average_confidence=avg_confidence,
            risk_score=risk_score
        )

    except Exception as e:
        logging.error(f"Compliance report error: {e}")
        raise HTTPException(status_code=500, detail=f"Compliance report error: {str(e)}")

@router.get("/risk-assessment/{target_user_id}")
async def assess_user_risk(
    target_user_id: int,
    db: Session = Depends(get_db),
    user_id: int = Depends(verify_token)
):
    """Assess risk for a specific user (admin only)"""
    try:
        # Only admin can assess other users
        if user_id != 1 and user_id != target_user_id:
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        # Get recent activity (last 7 days)
        week_ago = datetime.utcnow() - timedelta(days=7)
        
        # Get authentication patterns
        recent_auths = db.query(BiometricAudit).filter(
            and_(
                BiometricAudit.user_id == target_user_id,
                BiometricAudit.timestamp >= week_ago
            )
        ).all()

        # Analyze patterns for risk indicators
        risk_indicators = []
        risk_score = 0

        # Check for unusual IP addresses
        ip_addresses = set([audit.ip_address for audit in recent_auths])
        if len(ip_addresses) > 3:
            risk_indicators.append("Multiple IP addresses used")
            risk_score += 20

        # Check for low confidence scores
        low_confidence_auths = [audit for audit in recent_auths if audit.confidence_score < 0.7]
        if len(low_confidence_auths) > 2:
            risk_indicators.append("Multiple low-confidence authentications")
            risk_score += 25

        # Check for failed liveness checks
        failed_liveness = [audit for audit in recent_auths if not audit.liveness_check]
        if len(failed_liveness) > 1:
            risk_indicators.append("Failed liveness checks detected")
            risk_score += 30

        # Check for rapid successive attempts
        auth_times = sorted([audit.timestamp for audit in recent_auths])
        rapid_attempts = 0
        for i in range(1, len(auth_times)):
            if (auth_times[i] - auth_times[i-1]).seconds < 30:
                rapid_attempts += 1
        
        if rapid_attempts > 3:
            risk_indicators.append("Rapid successive authentication attempts")
            risk_score += 15

        # Determine risk level
        if risk_score >= 70:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "user_id": target_user_id,
            "risk_score": min(risk_score, 100),
            "risk_level": risk_level,
            "risk_indicators": risk_indicators,
            "recent_auth_count": len(recent_auths),
            "assessment_timestamp": datetime.utcnow()
        }

    except Exception as e:
        logging.error(f"Risk assessment error: {e}")
        raise HTTPException(status_code=500, detail=f"Risk assessment error: {str(e)}")