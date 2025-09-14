# backend/routers/otp.py

from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import or_
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import Optional
import uuid
from backend.database import User, get_db
from backend.routers.auth import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token
from backend.services.otp_service import otp_service

router = APIRouter()

class OTPRequest(BaseModel):
    session_id: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    method: str = 'email'  # 'email', 'sms'
    purpose: str = 'login_fallback'  # 'login_fallback', 'transaction_auth', 'registration'
    transaction_id: Optional[str] = None
    user_id: Optional[int] = None
    original_auth_method: Optional[str] = None  # 'face_recognition', 'biometric'
    fallback_reason: Optional[str] = None

class OTPVerifyRequest(BaseModel):
    session_id: str
    otp_code: str

class OTPResponse(BaseModel):
    success: bool
    message: str
    session_id: Optional[str] = None
    expires_in_minutes: Optional[int] = None
    error: Optional[str] = None

class OTPVerifyResponse(BaseModel):
    success: bool
    message: str
    user_id: Optional[int] = None
    email: Optional[str] = None
    purpose: Optional[str] = None
    transaction_id: Optional[str] = None
    remaining_attempts: Optional[int] = None
    error: Optional[str] = None
    token: Optional[str] = None 

def get_client_info(request: Request):
    """Extract client IP and User-Agent"""
    return {
        'ip_address': request.client.host,
        'user_agent': request.headers.get('user-agent', '')
    }

@router.post("/request", response_model=OTPResponse)
async def request_otp(
    otp_request: OTPRequest, 
    request: Request,
    db: Session = Depends(get_db)
):
    """Request OTP for fallback authentication"""
    print("OTP Request:", otp_request)
    # Generate session ID if not provided
    if not otp_request.session_id:
        otp_request.session_id = str(uuid.uuid4())
    
    # Validate request
    if otp_request.method == 'email' and not otp_request.email:
        raise HTTPException(status_code=400, detail="Email required for email OTP")
    
    if otp_request.method == 'sms' and not otp_request.phone:
        raise HTTPException(status_code=400, detail="Phone number required for SMS OTP")
    
    # Get client info
    client_info = get_client_info(request)
    print("Client Info:", client_info)
    # Generate and send OTP
    # Generate and send OTP
    if otp_request.method == "email":
        user = db.query(User).filter(User.email == otp_request.email).first()
    elif otp_request.method == "sms":
        user = db.query(User).filter(User.phone == otp_request.phone).first()
    else:
        raise HTTPException(status_code=400, detail="Invalid OTP method")

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    print("Matched User:", user)
    result = await otp_service.generate_and_store_otp(
        db=db,
        session_id=otp_request.session_id,
        email=otp_request.email,
        phone=otp_request.phone,
        method=otp_request.method,
        purpose=otp_request.purpose,
        transaction_id=otp_request.transaction_id,
        user_id=user.id,
        ip_address=client_info['ip_address'],
        user_agent=client_info['user_agent'],
        original_auth_method=otp_request.original_auth_method,
        fallback_reason=otp_request.fallback_reason
    )
    
    if not result['success']:
        raise HTTPException(status_code=500, detail=result['message'])
    
    return OTPResponse(**result)

@router.post("/verify", response_model=OTPVerifyResponse)
async def verify_otp(
    verify_request: OTPVerifyRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Verify OTP code"""
    
    if not verify_request.otp_code or len(verify_request.otp_code) != 6:
        raise HTTPException(status_code=400, detail="Invalid OTP format")
    
    # Get client info
    client_info = get_client_info(request)
    
    # Verify OTP
    print("Verify Request:", verify_request)
    result = await otp_service.verify_otp(
        db=db,
        session_id=verify_request.session_id,
        otp_code=verify_request.otp_code,
        ip_address=client_info['ip_address'],
        user_agent=client_info['user_agent']
    )
    print("Verify Result:", result)
    if result.get('success'):
        # Create access token (same as in face auth)
        email = result.get('email')
        user = None
        # If email missing, fetch from DB using user_id
    if not email:
        user = db.query(User).filter(User.id == result.get('user_id')).first()
        if user:
            email = user.email
            result['email'] = email
    else:
        # Optional: verify user exists in DB even if email is present
        user = db.query(User).filter(User.email == email).first()
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": result['email']}, expires_delta=access_token_expires
        )
        result['token'] = access_token
    
    return OTPVerifyResponse(**result)

@router.post("/resend")
async def resend_otp(
    session_id: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """Resend OTP for existing session"""
    
    # Find existing OTP record
    from backend.database import OTPVerification
    otp_record = db.query(OTPVerification).filter(
        OTPVerification.session_id == session_id,
        OTPVerification.is_expired == False
    ).first()
    
    if not otp_record:
        raise HTTPException(status_code=404, detail="OTP session not found")
    
    # Create new OTP request based on existing record
    client_info = get_client_info(request)
    
    result = await otp_service.generate_and_store_otp(
        db=db,
        session_id=session_id,
        email=otp_record.email,
        phone=otp_record.phone,
        method=otp_record.otp_method,
        purpose=otp_record.purpose,
        transaction_id=otp_record.transaction_id,
        user_id=otp_record.user_id,
        ip_address=client_info['ip_address'],
        user_agent=client_info['user_agent']
    )
    
    if not result['success']:
        raise HTTPException(status_code=500, detail=result['message'])
    
    return {"success": True, "message": "OTP resent successfully"}

@router.delete("/session/{session_id}")
async def cancel_otp_session(
    session_id: str,
    db: Session = Depends(get_db)
):
    """Cancel/expire OTP session"""
    
    from backend.database import OTPVerification
    otp_record = db.query(OTPVerification).filter(
        OTPVerification.session_id == session_id
    ).first()
    
    if otp_record:
        otp_record.is_expired = True
        db.commit()
    
    return {"success": True, "message": "OTP session cancelled"}

@router.get("/status/{session_id}")
async def get_otp_status(
    session_id: str,
    db: Session = Depends(get_db)
):
    """Get OTP session status"""
    
    from backend.database import OTPVerification
    from datetime import datetime
    
    otp_record = db.query(OTPVerification).filter(
        OTPVerification.session_id == session_id
    ).first()
    
    if not otp_record:
        return {"exists": False}
    
    is_expired = (
        otp_record.is_expired or 
        datetime.utcnow() > otp_record.expires_at
    )
    
    return {
        "exists": True,
        "is_verified": otp_record.is_verified,
        "is_expired": is_expired,
        "attempts": otp_record.attempts,
        "max_attempts": otp_record.max_attempts,
        "method": otp_record.otp_method,
        "purpose": otp_record.purpose,
        "expires_at": otp_record.expires_at.isoformat()
    }