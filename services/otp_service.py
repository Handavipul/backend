# backend/services/otp_service.py

import hashlib
import secrets
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, Any
import requests
import json
from sqlalchemy.orm import Session
from backend.database import OTPVerification, OTPAuditLog
from backend.config import settings
import logging

logger = logging.getLogger(__name__)

class OTPService:
    def __init__(self):
        # Email configuration (using Gmail SMTP - free)
        self.smtp_server = "sandbox.smtp.mailtrap.io"
        self.smtp_port = 2525
        self.email_user = settings.EMAIL_USER  # Your Gmail address
        self.email_password = settings.EMAIL_APP_PASSWORD  # Gmail app password
        
        # SMS configuration (using Textbelt - free tier)
        self.textbelt_api_key = settings.TEXTBELT_API_KEY or "textbelt"  # "textbelt" for free tier
        
        # OTP settings
        self.otp_length = 6
        self.otp_expiry_minutes = 10
        self.max_attempts = 3

    def generate_otp(self) -> str:
        """Generate a secure 6-digit OTP"""
        return ''.join([str(secrets.randbelow(10)) for _ in range(self.otp_length)])

    def hash_otp(self, otp: str) -> str:
        """Hash OTP for secure storage"""
        return hashlib.sha256(otp.encode()).hexdigest()

    def verify_otp_hash(self, otp: str, hashed_otp: str) -> bool:
        """Verify OTP against stored hash"""
        return hashlib.sha256(otp.encode()).hexdigest() == hashed_otp

    async def generate_and_store_otp(
        self, 
        db: Session,
        session_id: str,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        method: str = 'email',
        purpose: str = 'login_fallback',
        transaction_id: Optional[str] = None,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        original_auth_method: Optional[str] = None,
        fallback_reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate OTP and store in database"""
        
        try:
            # Generate OTP
            otp_code = self.generate_otp()
            otp_hash = self.hash_otp(otp_code)
            expires_at = datetime.utcnow() + timedelta(minutes=self.otp_expiry_minutes)
            # Check if session already exists and clean up
            existing = db.query(OTPVerification).filter(
                OTPVerification.session_id == session_id
            ).first()
            
            if existing:
                db.delete(existing)
                db.commit()
            
            # Store OTP verification record
            otp_record = OTPVerification(
                session_id=session_id,
                user_id=user_id,
                email=email,
                phone=phone,
                otp_code_hash=otp_hash,
                otp_method=method,
                purpose=purpose,
                transaction_id=transaction_id,
                expires_at=expires_at,
                ip_address=ip_address,
                user_agent=user_agent,
                original_auth_method=original_auth_method,
                fallback_reason=fallback_reason
            )
            
            db.add(otp_record)
            db.commit()
            print("OTP generated and stored step 1:", otp_record)
            # Log generation
            await self._log_otp_action(
                db, session_id, 'generated', method, email, phone, 
                ip_address, user_agent, True
            )
            print("OTP generated and stored step 2",method)
            # Send OTP
            if method == 'email' and email:
                send_result = await self._send_email_otp(email, otp_code, purpose)
            elif method == 'sms' and phone:
                send_result = await self._send_sms_otp(phone, otp_code, purpose)
                print("SMS send result step 3:", send_result)
            else:
                raise ValueError(f"Invalid method {method} or missing contact info")
            
            if send_result['success']:
                # Log successful send
                await self._log_otp_action(
                    db, session_id, 'sent', method, email, phone,
                    ip_address, user_agent, True
                )
                print("OTP generated and stored step 4:", session_id)
                return {
                    'success': True,
                    'message': f'OTP sent to your {method}',
                    'session_id': session_id,
                    'expires_in_minutes': self.otp_expiry_minutes
                }
            else:
                # Log failed send
                print("OTP send failed step 5:", send_result)
                await self._log_otp_action(
                    db, session_id, 'sent', method, email, phone,
                    ip_address, user_agent, False, send_result.get('error')
                )
                
                return {
                    'success': False,
                    'message': 'Failed to send OTP',
                    'error': send_result.get('error')
                }
                
        except Exception as e:
            logger.error(f"Error generating OTP: {str(e)}")
            await self._log_otp_action(
                db, session_id, 'generated', method, email, phone,
                ip_address, user_agent, False, str(e)
            )
            return {
                'success': False,
                'message': 'Error generating OTP',
                'error': str(e)
            }

    async def verify_otp(
        self,
        db: Session,
        session_id: str,
        otp_code: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verify OTP code"""
        
        try:
            # Find OTP record
            print("Verifying OTP for session:", session_id)
            otp_record = db.query(OTPVerification).filter(
                OTPVerification.session_id == session_id,
                OTPVerification.is_expired == False,
                OTPVerification.is_verified == False
            ).first()
            print("OTP Record:", otp_record)
            if not otp_record:
                await self._log_otp_action(
                    db, session_id, 'failed', '', None, None,
                    ip_address, user_agent, False, 'OTP record not found'
                )
                return {
                    'success': False,
                    'message': 'Invalid or expired OTP session'
                }
            
            # Check if expired
            if datetime.utcnow() > otp_record.expires_at:
                otp_record.is_expired = True
                db.commit()
                
                await self._log_otp_action(
                    db, session_id, 'expired', otp_record.otp_method,
                    otp_record.email, otp_record.phone,
                    ip_address, user_agent, False, 'OTP expired'
                )
                
                return {
                    'success': False,
                    'message': 'OTP has expired'
                }
            print("OTP Record check attempts:", otp_record)
            # Check attempts
            if otp_record.attempts >= otp_record.max_attempts:
                otp_record.is_expired = True
                db.commit()
                
                await self._log_otp_action(
                    db, session_id, 'failed', otp_record.otp_method,
                    otp_record.email, otp_record.phone,
                    ip_address, user_agent, False, 'Max attempts exceeded'
                )
                
                return {
                    'success': False,
                    'message': 'Maximum attempts exceeded'
                }
            
            # Increment attempts
            otp_record.attempts += 1
            
            # Verify OTP
            print("Verifying OTP:", otp_code, otp_record.otp_code_hash)
            if self.verify_otp_hash(otp_code, otp_record.otp_code_hash):
                # Success
                otp_record.is_verified = True
                otp_record.verified_at = datetime.utcnow()
                db.commit()
                
                await self._log_otp_action(
                    db, session_id, 'verified', otp_record.otp_method,
                    otp_record.email, otp_record.phone,
                    ip_address, user_agent, True
                )
                
                return {
                    'success': True,
                    'message': 'OTP verified successfully',
                    'user_id': otp_record.user_id,
                    'email': otp_record.email,
                    'purpose': otp_record.purpose,
                    'transaction_id': otp_record.transaction_id
                }
            else:
                # Failed verification
                db.commit()
                
                await self._log_otp_action(
                    db, session_id, 'failed', otp_record.otp_method,
                    otp_record.email, otp_record.phone,
                    ip_address, user_agent, False, 'Invalid OTP code'
                )
                
                remaining = otp_record.max_attempts - otp_record.attempts
                return {
                    'success': False,
                    'message': f'Invalid OTP. {remaining} attempts remaining',
                    'remaining_attempts': remaining
                }
                
        except Exception as e:
            logger.error(f"Error verifying OTP: {str(e)}")
            return {
                'success': False,
                'message': 'Error verifying OTP',
                'error': str(e)
            }

    async def _send_email_otp(self, email: str, otp_code: str, purpose: str) -> Dict[str, Any]:
        """Send OTP via email using Gmail SMTP"""
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.email_user
            msg['To'] = email
            msg['Subject'] = f"AV Pay - Verification Code"
            
            # Email body
            purpose_text = {
                'login_fallback': 'backup login verification',
                'transaction_auth': 'secure your payment',
                'registration': 'complete your registration'
            }.get(purpose, 'verify your action')
            
            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #004d99 0%, #001a33 100%); padding: 20px; text-align: center;">
                    <h1 style="color: white; margin: 0;">AV Pay</h1>
                    <p style="color: #ccc; margin: 5px 0 0 0;">Secure Payment Solution</p>
                </div>
                
                <div style="padding: 30px 20px; background: #f8f9fa;">
                    <h2 style="color: #004d99; margin-bottom: 20px;">Verification Code</h2>
                    
                    <p>Hi there,</p>
                    <p>Use this code to {purpose_text}:</p>
                    
                    <div style="background: white; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0; border: 2px solid #004d99;">
                        <h1 style="font-size: 36px; letter-spacing: 8px; color: #004d99; margin: 0;">{otp_code}</h1>
                    </div>
                    
                    <p style="color: #666; font-size: 14px;">
                        This code expires in {self.otp_expiry_minutes} minutes for your security.
                    </p>
                    
                    <p style="color: #666; font-size: 14px;">
                        If you didn't request this code, please ignore this email.
                    </p>
                </div>
                
                <div style="background: #004d99; padding: 15px; text-align: center;">
                    <p style="color: white; margin: 0; font-size: 12px;">
                        © 2024 AV Pay. Secure payments made simple.
                    </p>
                </div>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.email_user, self.email_password)
                server.send_message(msg)
            
            return {'success': True}
            
        except Exception as e:
            logger.error(f"Error sending email OTP: {str(e)}")
            return {'success': False, 'error': str(e)}

    async def _send_sms_otp(self, phone: str, otp_code: str, purpose: str) -> Dict[str, Any]:
        """Send OTP via SMS using Textbelt (free tier available)"""
        try:
            # Clean phone number (remove non-digits)
            print("Cleaning phone number:", phone)
            clean_phone = ''.join(filter(str.isdigit, phone))
            
            # Format message
            message = f"AV Pay verification code: {otp_code}. Expires in {self.otp_expiry_minutes} minutes. Do not share this code."
            
            # Textbelt API call
            response = requests.post(
                'https://textbelt.com/text',
                data={
                    'phone': clean_phone,
                    'message': message,
                    'key': self.textbelt_api_key
                },
                timeout=10
            )
            
            result = response.json()
            
            if result.get('success'):
                return {'success': True, 'quota_remaining': result.get('quotaRemaining')}
            else:
                return {'success': False, 'error': result.get('error', 'SMS send failed')}
                
        except Exception as e:
            logger.error(f"Error sending SMS OTP: {str(e)}")
            return {'success': False, 'error': str(e)}

    async def _log_otp_action(
        self, 
        db: Session, 
        session_id: str, 
        action: str, 
        method: str,
        email: Optional[str], 
        phone: Optional[str],
        ip_address: Optional[str], 
        user_agent: Optional[str], 
        success: bool,
        error_message: Optional[str] = None
    ):
        """Log OTP action for audit trail"""
        print("Logging OTP action:", action, session_id)
        try:
            log_entry = OTPAuditLog(
                session_id=session_id,
                action=action,
                otp_method=method,
                email=email,
                phone=phone,
                ip_address=ip_address,
                user_agent=user_agent,
                success=success,
                error_message=error_message
            )
            db.add(log_entry)
            db.commit()
        except Exception as e:
            logger.error(f"Error logging OTP action: {str(e)}")

    def cleanup_expired_otps(self, db: Session):
        """Clean up expired OTP records (run this periodically)"""
        try:
            expired_count = db.query(OTPVerification).filter(
                OTPVerification.expires_at < datetime.utcnow()
            ).update({OTPVerification.is_expired: True})
            
            # Delete old records (older than 24 hours)
            old_threshold = datetime.utcnow() - timedelta(hours=24)
            deleted_count = db.query(OTPVerification).filter(
                OTPVerification.created_at < old_threshold
            ).delete()
            
            db.commit()
            logger.info(f"Expired {expired_count} OTPs, deleted {deleted_count} old records")
            
        except Exception as e:
            logger.error(f"Error cleaning up OTPs: {str(e)}")

# Create service instance
otp_service = OTPService()