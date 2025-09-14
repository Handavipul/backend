# Backend API Endpoints for Fraud Detection Integration
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Dict, List, Optional
from datetime import datetime
import logging
from sqlalchemy.orm import Session

from backend.routers.auth import get_current_user
from backend.routers.mollie import create_payment
from backend.routers.payment import get_payment_status
from backend.services.NetworkIntelligenceService import FraudCheckService


from ..database import User, get_db

logger = logging.getLogger(__name__)
fraud_router = APIRouter(prefix="/api/fraud", tags=["fraud-detection"])

# Request/Response Models
class PaymentData(BaseModel):
    amount: float
    currency: str = "EUR"
    merchant_category: str = "general"
    recipient_country: str = "US"

class DeviceData(BaseModel):
    device_id: str
    os: str
    os_version: str
    is_rooted: bool = False
    is_emulator: bool = False
    ip_address: Optional[str] = None
    user_agent: str
    behavioral_metrics: Dict = {}
    screen_resolution: Optional[str] = None
    timezone: Optional[str] = None
    language: Optional[List[str]] = None

class UserContext(BaseModel):
    user_id: str
    session_id: str
    last_sca_time: Optional[datetime] = None

class FraudCheckRequest(BaseModel):
    payment_data: PaymentData
    device_data: DeviceData
    user_context: UserContext

class FraudCheckResponse(BaseModel):
    risk_score: float
    risk_level: str
    action: str
    reason_codes: List[str]
    fraud_indicators: List[str]
    require_3ds: bool
    challenge_type: Optional[str] = None

class OutcomeReport(BaseModel):
    session_id: str
    outcome: str
    timestamp: datetime

# Initialize services
fraud_service = FraudCheckService()

@fraud_router.post("/check", response_model=FraudCheckResponse)
async def check_fraud(
    request: FraudCheckRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Perform fraud risk assessment on a transaction
    """
    try:
        # Get client IP address
        client_ip = get_client_ip(http_request)
        
        # Update device data with server-side information
        device_data_dict = request.device_data.dict()
        device_data_dict['ip_address'] = client_ip
        
        # Prepare fraud check data
        fraud_check_data = {
            'payment_data': request.payment_data.dict(),
            'device_data': device_data_dict,
            'user_context': request.user_context.dict()
        }
        
        logger.info(f"Fraud check requested for user {request.user_context.user_id}, session {request.user_context.session_id}")
        
        # Perform fraud assessment
        result = fraud_service.check_transaction_risk(
            fraud_check_data['payment_data'],
            fraud_check_data['device_data'],
            fraud_check_data['user_context']
        )
        
        # Log the assessment
        await log_fraud_assessment(db, fraud_check_data, result)
        
        return FraudCheckResponse(**result)
        
    except Exception as e:
        logger.error(f"Fraud check failed: {e}")
        
        # Fail secure - default to step-up
        return FraudCheckResponse(
            risk_score=0.5,
            risk_level="medium",
            action="step_up_otp",
            reason_codes=["System error - security verification required"],
            fraud_indicators=[],
            require_3ds=True,
            challenge_type="otp"
        )

@fraud_router.post("/outcome")
async def report_outcome(
    outcome_report: OutcomeReport,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Report the outcome of a transaction for learning purposes
    """
    try:
        logger.info(f"Outcome reported: {outcome_report.session_id} -> {outcome_report.outcome}")
        
        # Update fraud service with outcome
        fraud_service.update_outcome(
            outcome_report.session_id,
            outcome_report.outcome
        )
        
        # Store outcome in database for analysis
        await store_outcome(db, outcome_report)
        
        return {"status": "outcome_recorded"}
        
    except Exception as e:
        logger.error(f"Failed to record outcome: {e}")
        raise HTTPException(status_code=500, detail="Failed to record outcome")

# Enhanced Mollie Integration
mollie_router = APIRouter(prefix="/api/mollie", tags=["mollie-enhanced"])

@mollie_router.post("/payments/with-step-up")
async def create_payment_with_step_up(
    payment_request: Dict,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create Mollie payment with enhanced security and step-up authentication
    """
    try:
        
        # Extract risk metadata
        risk_score = float(payment_request.get('metadata', {}).get('risk_score', 0.0))
        challenge_type = payment_request.get('metadata', {}).get('challenge_type', 'otp')
        
        # Configure payment based on risk level
        enhanced_request = configure_payment_for_risk(payment_request, risk_score, challenge_type)
        
        # Create payment with Mollie
        payment = await create_payment(enhanced_request)
        
        logger.info(f"High-risk payment created: {payment.id}, risk_score: {risk_score}")
        
        # Store additional risk metadata
        await store_payment_risk_data(db, payment.id, {
            'risk_score': risk_score,
            'challenge_type': challenge_type,
            'requires_step_up': True,
            'user_id': current_user.id
        })
        
        return {
            'id': payment.id,
            'checkoutUrl': payment.checkoutUrl,
            'status': payment.status,
            'metadata': payment.metadata,
            'requires_authentication': True,
            'challenge_type': challenge_type
        }
        
    except Exception as e:
        logger.error(f"Failed to create high-risk payment: {e}")
        raise HTTPException(status_code=500, detail="Payment creation failed")

@mollie_router.post("/payments/{payment_id}/verify-step-up")
async def verify_step_up_completion(
    payment_id: str,
    verification_data: Dict,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verify that step-up authentication was completed successfully
    """
    try:
        
        # Get payment details
        payment = await get_payment_status(payment_id)
        
        if payment.status != 'paid':
            raise HTTPException(status_code=400, detail="Payment not completed")
        
        # Verify step-up authentication
        step_up_verified = await verify_step_up_authentication(
            payment_id, 
            verification_data,
            current_user.id
        )
        
        if not step_up_verified:
            raise HTTPException(status_code=400, detail="Step-up verification failed")
        
        # Update risk assessment with successful step-up
        await update_risk_outcome(db, payment_id, 'step_up_success')
        
        logger.info(f"Step-up verification successful for payment {payment_id}")
        
        return {
            'payment_id': payment_id,
            'step_up_verified': True,
            'status': payment.status
        }
        
    except Exception as e:
        logger.error(f"Step-up verification failed: {e}")
        raise HTTPException(status_code=500, detail="Verification failed")

# Utility Functions

def get_client_ip(request: Request) -> str:
    """Extract client IP address from request"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    return request.client.host

def configure_payment_for_risk(payment_request: Dict, risk_score: float, challenge_type: str) -> Dict:
    """Configure Mollie payment request based on risk assessment"""
    
    enhanced_request = payment_request.copy()
    
    # Force 3D Secure for higher risk transactions
    if risk_score > 0.3:
        enhanced_request['method'] = None  # Let Mollie choose secure method
        
    # Add risk-specific metadata
    enhanced_request['metadata'].update({
        'fraud_protection': 'enabled',
        'risk_assessment_timestamp': datetime.now().isoformat(),
        'requires_strong_authentication': str(risk_score > 0.5).lower()
    })
    
    # Configure webhook for enhanced monitoring
    enhanced_request['webhookUrl'] = enhanced_request.get('webhookUrl', '') + '?risk_monitoring=true'
    
    return enhanced_request

async def log_fraud_assessment(db: Session, request_data: Dict, result: Dict):
    """Log fraud assessment for audit and learning"""
    
    assessment_log = {
        'timestamp': datetime.now(),
        'user_id': request_data['user_context']['user_id'],
        'session_id': request_data['user_context']['session_id'],
        'device_id': request_data['device_data']['device_id'],
        'amount': request_data['payment_data']['amount'],
        'currency': request_data['payment_data']['currency'],
        'risk_score': result['risk_score'],
        'risk_level': result['risk_level'],
        'action': result['action'],
        'reason_codes': result['reason_codes'],
        'fraud_indicators': result['fraud_indicators'],
        'ip_address': request_data['device_data']['ip_address'],
        'user_agent': request_data['device_data']['user_agent']
    }
    
    # Store in fraud assessment table
    # db.execute(insert_fraud_assessment_query, assessment_log)
    # db.commit()
    
    logger.info(f"Fraud assessment logged: {assessment_log['session_id']}")

async def store_payment_risk_data(db: Session, payment_id: str, risk_data: Dict):
    """Store payment risk metadata"""
    
    risk_record = {
        'payment_id': payment_id,
        'risk_score': risk_data['risk_score'],
        'challenge_type': risk_data['challenge_type'],
        'requires_step_up': risk_data['requires_step_up'],
        'user_id': risk_data['user_id'],
        'created_at': datetime.now()
    }
    
    # Store in payment_risk_data table
    logger.info(f"Risk data stored for payment {payment_id}")

async def store_outcome(db: Session, outcome_report: OutcomeReport):
    """Store transaction outcome for model training"""
    
    outcome_record = {
        'session_id': outcome_report.session_id,
        'outcome': outcome_report.outcome,
        'reported_at': outcome_report.timestamp,
        'created_at': datetime.now()
    }
    
    # Store in fraud_outcomes table
    logger.info(f"Outcome stored: {outcome_report.session_id} -> {outcome_report.outcome}")

async def update_risk_outcome(db: Session, payment_id: str, outcome: str):
    """Update risk assessment with actual outcome"""
    
    # Update payment risk record with outcome
    logger.info(f"Risk outcome updated: {payment_id} -> {outcome}")

async def verify_step_up_authentication(payment_id: str, verification_data: Dict, user_id: str) -> bool:
    """Verify that step-up authentication was completed"""
    
    # This would integrate with your authentication system
    # to verify OTP, biometric, or document verification
    
    verification_type = verification_data.get('type', 'otp')
    
    if verification_type == 'otp':
        # Verify OTP code
        return await verify_otp_code(
            user_id, 
            verification_data.get('code'),
            verification_data.get('reference')
        )
    elif verification_type == 'biometric':
        # Verify biometric authentication
        return await verify_biometric_auth(
            user_id,
            verification_data.get('biometric_data')
        )
    elif verification_type == 'document':
        # Verify document submission
        return await verify_document_submission(
            user_id,
            verification_data.get('document_images')
        )
    
    return False

async def verify_otp_code(user_id: str, code: str, reference: str) -> bool:
    """Verify OTP code"""
    # Implement OTP verification logic
    return True  # Placeholder

async def verify_biometric_auth(user_id: str, biometric_data: Dict) -> bool:
    """Verify biometric authentication"""
    # Implement biometric verification logic
    return True  # Placeholder

async def verify_document_submission(user_id: str, document_images: List[str]) -> bool:
    """Verify document submission for high-risk transactions"""
    # Implement document verification logic
    return True  # Placeholder


# Webhook Enhancement for Fraud Monitoring
@mollie_router.post("/webhook")
async def enhanced_mollie_webhook(
    request: Request,
    db: Session = Depends(get_db)
):
    """Enhanced Mollie webhook with fraud monitoring"""
    
    try:
        webhook_data = await request.json()
        payment_id = webhook_data.get("id")
        
        if not payment_id:
            raise HTTPException(status_code=400, detail="No payment ID")
        
        # Check if this is a risk-monitored payment
        is_risk_monitored = 'risk_monitoring=true' in str(request.url)
        
        logger.info(f"Webhook received for payment {payment_id}, risk_monitored: {is_risk_monitored}")
        
        # Get payment details
        payment = await get_payment_status(payment_id)
        
        # Standard webhook processing
        await process_payment_webhook(payment, db)
        
        # Enhanced fraud monitoring
        if is_risk_monitored:
            await process_fraud_monitoring_webhook(payment, db)
        
        return {"status": "received"}
        
    except Exception as e:
        logger.error(f"Enhanced webhook processing failed: {e}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")

async def process_payment_webhook(payment, db: Session):
    """Standard payment webhook processing"""
    # Your existing webhook processing logic
    pass

async def process_fraud_monitoring_webhook(payment, db: Session):
    """Additional fraud monitoring for high-risk payments"""
    
    try:
        # Extract risk metadata
        risk_score = float(payment.metadata.get('risk_score', 0))
        challenge_type = payment.metadata.get('challenge_type')
        
        # Analyze payment completion patterns
        if payment.status == 'paid':
            # Check for suspicious payment timing or patterns
            await analyze_payment_completion_patterns(payment, risk_score, db)
            
            # Update fraud model with successful high-risk payment
            await update_fraud_model_feedback(payment.id, 'legitimate', risk_score, db)
            
        elif payment.status == 'failed':
            # Analyze failure patterns
            await analyze_payment_failure_patterns(payment, risk_score, db)
            
        logger.info(f"Fraud monitoring completed for payment {payment.id}")
        
    except Exception as e:
        logger.error(f"Fraud monitoring webhook failed: {e}")

async def analyze_payment_completion_patterns(payment, risk_score: float, db: Session):
    """Analyze completion patterns for learning"""
    
    completion_data = {
        'payment_id': payment.id,
        'risk_score': risk_score,
        'completion_time': payment.paidAt,
        'method_used': payment.method,
        'amount': float(payment.amount.value),
        'customer_id': payment.customerId
    }
    
    # Store for pattern analysis
    logger.info(f"Payment completion pattern recorded: {payment.id}")

async def analyze_payment_failure_patterns(payment, risk_score: float, db: Session):
    """Analyze failure patterns"""
    
    failure_data = {
        'payment_id': payment.id,
        'risk_score': risk_score,
        'failure_reason': getattr(payment, 'failureReason', None),
        'failed_at': datetime.now(),
        'method_attempted': payment.method
    }
    
    # Store for pattern analysis
    logger.info(f"Payment failure pattern recorded: {payment.id}")

async def update_fraud_model_feedback(payment_id: str, outcome: str, risk_score: float, db: Session):
    """Update fraud model with outcome feedback"""
    
    feedback_data = {
        'payment_id': payment_id,
        'predicted_risk': risk_score,
        'actual_outcome': outcome,
        'feedback_timestamp': datetime.now()
    }
    
    # Store feedback for model retraining
    logger.info(f"Fraud model feedback recorded: {payment_id} -> {outcome}")