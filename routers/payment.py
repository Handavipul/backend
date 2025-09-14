import json
import os
import re
from fastapi import APIRouter, HTTPException, Depends, Security, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import numpy as np
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List
import jwt
import uuid
import logging
from datetime import datetime, timedelta

from backend.config import settings
from backend.database import FaceEncoding, SavedCard, get_db, User, Transaction, BiometricAudit
from backend.routers.auth import AuthResponse
from backend.services.CrossBorderPaymentProcessor import CrossBorderPaymentProcessor, PaymentGatewayAPI
from backend.services.encryption_service  import EncryptionService
from backend.services.face_service import FaceDuplicateDetectionService
from backend.services.payment_processor  import PaymentProcessor
from backend.services.aws_service import AWSService
from backend.middleware.metrics import MetricsUtils

router = APIRouter()
encryption_service = EncryptionService(master_key=settings.PAYMENT_ENCRYPTION_KEY)
print(f"Encryption service initialized with master key: {settings.PAYMENT_ENCRYPTION_KEY}")
payment_processor = PaymentProcessor()
CrossBorder_processor = CrossBorderPaymentProcessor()
security = HTTPBearer()
aws_service = AWSService()
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class SavedCardResponse(BaseModel):
    id: str
    last_four: str
    brand: str
    expiry_month: int
    expiry_year: int
    holder_name: str
    created_at: datetime
    is_primary: Optional[bool] = False

class CardDetails(BaseModel):
    number: str
    expiry_month: int
    expiry_year: int
    is_primary: Optional[bool] = False
    cvv: str
    holder_name: str

class CardPaymentRequest(BaseModel):
    amount: float
    currency: str
    card_id: Optional[str] = None  # For saved cards
    card_details: Optional[CardDetails] = None  # For new cards
    save_card: Optional[bool] = False
    purpose: Optional[str] = ""

class MultiAnglePaymentAuthRequest(BaseModel):
    images_data: List[str]  # Multiple face angles
    card_payment_data: CardPaymentRequest
    timestamp: str

class PaymentRequest(BaseModel):
    amount: float
    currency: str
    recipient_account: str
    recipient_bank: str
    purpose: str

class CardValidationRequest(BaseModel):
    number: str
    expiry_month: int
    expiry_year: int
    cvv: str

class PaymentResponse(BaseModel):
    success: bool
    transaction_id: Optional[str] = None
    status: Optional[str] = None
    message: Optional[str] = None
    receipt_url: Optional[str] = None
    confidence_score: Optional[float] = None
    angles_verified: Optional[int] = None

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return email
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

@router.post("/process", response_model=PaymentResponse)
async def process_payment(
    payment: PaymentRequest,
    db: Session = Depends(get_db),
    email: str = Depends(verify_token)
):
    """Process an authorized payment"""
    try:
        print(f"Processing payment for user ID: {email}")
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Generate transaction ID
        transaction_id = str(uuid.uuid4())

        # Create transaction record
        transaction = Transaction(
            transaction_id=transaction_id,
            user_id=user.id,
            amount=payment.amount,
            currency=payment.currency,
            recipient_account=payment.recipient_account,
            recipient_bank=payment.recipient_bank,
            purpose=payment.purpose,
            status="processing"
        )
        db.add(transaction)
        db.commit()

        # Queue for payment processing
        await aws_service.queue_payment_processing({
            'transaction_id': transaction_id,
            'user_id': user.id,
            'amount': payment.amount,
            'currency': payment.currency
        })

        # Record metric
        MetricsUtils.record_payment_transaction("processing", payment.currency)

        return PaymentResponse(
            success=True,
            transaction_id=transaction_id,
            status="processing",
            message="Payment is being processed"
        )

    except Exception as e:
        logging.error(f"Payment processing error: {e}")
        raise HTTPException(status_code=500, detail=f"Payment processing error: {str(e)}")

@router.get("/status/{transaction_id}")
async def get_payment_status(
    transaction_id: str,
    db: Session = Depends(get_db),
    user_id: int = Depends(verify_token)
):
    """Get payment transaction status"""
    try:
        transaction = db.query(Transaction).filter(
            Transaction.transaction_id == transaction_id,
            Transaction.user_id == user_id
        ).first()
        
        if not transaction:
            raise HTTPException(status_code=404, detail="Transaction not found")

        return {
            "transaction_id": transaction.transaction_id,
            "status": transaction.status,
            "amount": transaction.amount,
            "currency": transaction.currency,
            "created_at": transaction.created_at,
            "updated_at": transaction.updated_at
        }

    except Exception as e:
        logging.error(f"Status check error: {e}")
        raise HTTPException(status_code=500, detail=f"Status check error: {str(e)}")
    
@router.get("/cards", response_model=List[SavedCardResponse])
async def get_saved_cards(
    db: Session = Depends(get_db),
    user_id: int = Depends(verify_token)
):
    """Get user's saved cards"""
    try:
        print(f"Fetching saved cards for user ID: {user_id}")
        user = db.query(User).filter(User.email == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        print(f"Fetching saved cards for user ID: {user_id}")
        saved_cards = db.query(SavedCard).filter(
            SavedCard.user_id == user.id,
            SavedCard.is_active == True
        ).order_by(SavedCard.created_at.desc()).all()
        print(f"Found {len(saved_cards)} saved cards for user ID: {user_id}")
        cards_response = []
        for card in saved_cards:
            # Decrypt last four digits for display
            print(f"Processing card ID: {card.id}, Brand: {card.brand}")
            last_four = encryption_service.decrypt(card.last_four_encrypted)
            print(f"Decrypted last four digits for card ID: {card.id}, Last Four: {last_four}")
            cards_response.append(SavedCardResponse(
                id=card.id,
                last_four=last_four,
                brand=card.brand,
                expiry_month=card.expiry_month,
                expiry_year=card.expiry_year,
                holder_name=encryption_service.decrypt(card.holder_name_encrypted),
                created_at=card.created_at,
                is_primary=card.is_primary
            ))

        return cards_response

    except Exception as e:
        logging.error(f"Error fetching saved cards: {e}")
        raise HTTPException(status_code=500, detail="Error fetching saved cards")

@router.get("/health")
async def authentication_health_check(db: Session = Depends(get_db)):
    """Check the health of the authentication system"""
    try:
        # Count users with valid face encodings
        valid_users = db.query(User).filter(
            User.is_active == True,
            User.face_encoding.isnot(None),
            User.face_encoding != ''
        ).count()
        
        total_active_users = db.query(User).filter(User.is_active == True).count()
        
        # Basic health metrics
        health_status = {
            "status": "healthy" if valid_users > 0 else "degraded",
            "total_active_users": total_active_users,
            "users_with_face_data": valid_users,
            "face_data_coverage": valid_users / max(total_active_users, 1),
            "authentication_enabled": valid_users > 0,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if valid_users == 0:
            health_status["warnings"] = ["No users with face encodings - authentication will fail"]
        
        return health_status
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }
        
@router.delete("/{card_id}")
async def delete_saved_card(
    card_id: str,
    db: Session = Depends(get_db),
    user_email: str = Depends(verify_token)  # clarify this is email
):
    """Delete a saved card"""
    try:
        # Get user by email
        user = db.query(User).filter(User.email == user_email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Get the card
        card = db.query(SavedCard).filter(
            SavedCard.id == card_id,
            SavedCard.user_id == user.id,
            SavedCard.is_active == True
        ).first()

        if not card:
            raise HTTPException(status_code=404, detail="Card not found")

        # Block deleting primary card unless there is another primary
        if card.is_primary:
            # Check if user has another active card
            other_cards = db.query(SavedCard).filter(
                SavedCard.user_id == user.id,
                SavedCard.is_active == True,
                SavedCard.id != card.id
            ).all()

            if not other_cards:
                # Last card cannot be deleted
                raise HTTPException(
                    status_code=400,
                    detail="You must have at least one primary card"
                )

            raise HTTPException(
                status_code=400,
                detail="Please select another card as primary before deleting this card"
            )

        # Soft delete
        card.is_active = False
        card.deleted_at = datetime.utcnow()
        db.commit()

        return {"message": "Card deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error deleting card: {e}")
        raise HTTPException(status_code=500, detail="Error deleting card")

@router.post("/authorize-card-payment", response_model=PaymentResponse)
async def authorize_card_payment(
    request: MultiAnglePaymentAuthRequest,
    db: Session = Depends(get_db),
    user_id: int = Depends(verify_token),
    x_forwarded_for: Optional[str] = Header(None),
    user_agent: Optional[str] = Header(None)
):
    """Authorize card payment with multi-angle face recognition"""
    try:
        user = db.query(User).filter(User.email == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Validate payment data
        payment_data = request.card_payment_data
        if not payment_data.amount:
            raise HTTPException(status_code=400, detail="Missing required field: amount")
        if not payment_data.currency:
            raise HTTPException(status_code=400, detail="Missing required field: currency")

        # Validate card information
        card_details = None
        saved_card = None
        if payment_data.card_id:
            # Using saved card
            print(f"Using saved card ID: {payment_data.card_id}")
            saved_card = db.query(SavedCard).filter(
                SavedCard.id == payment_data.card_id,
                SavedCard.user_id == user.id,
                SavedCard.is_active == True
            ).first()
            print(f"Using saved card: {saved_card}")
            if not saved_card:
                raise HTTPException(status_code=404, detail="Saved card not found")

        elif payment_data.card_details:
            # Using new card
            card_info = payment_data.card_details

            # Validate card number
            if not validate_card_number(card_info.number):
                raise HTTPException(status_code=400, detail="Invalid card number")
            
            print(f"Card number {card_info.number} is valid")
            # Validate expiry
            current_year = datetime.now().year
            current_month = datetime.now().month

            if (card_info.expiry_year < current_year or
                (card_info.expiry_year == current_year and card_info.expiry_month < current_month)):
                raise HTTPException(status_code=400, detail="Card has expired")
            
            card_details = card_info
        else:
            raise HTTPException(status_code=400, detail="No card information provided")

        # Get stored face encodings
        stored_encodings = db.query(FaceEncoding).filter(FaceEncoding.email == user.email).all()
        if not stored_encodings:
            return PaymentResponse(
                success=False,
                message="No face data found for this user"
            )
        
        # Process login images and find best match
        max_similarity = 0.0
        best_match = None
        best_confidence = 0.0
        face_extraction_service = FaceDuplicateDetectionService()
        
        for image_data in request.images_data:
            # Extract face encodings from the image
            result, error = face_extraction_service.extract_face_encodings(
                image_data=image_data, 
                angle_info="login"
            )
            
            if error:
                continue
            
            login_encoding = result['embedding']
           
            # Compare with all stored encodings
            for stored_enc in stored_encodings:
                stored_embedding = np.frombuffer(stored_enc.encoding, dtype=np.float32)
                similarity = face_extraction_service.compare_encodings(login_encoding, stored_embedding)
                
                if similarity > max_similarity:
                    max_similarity = similarity
                    best_match = stored_enc.angle_info
                    best_confidence = result.get('confidence', 0.0)
        
        # Threshold for face recognition (adjust based on your needs)
        RECOGNITION_THRESHOLD = 0.4
        
        if max_similarity < RECOGNITION_THRESHOLD:
            return PaymentResponse(
                success=False,
                message=f"Face not recognized. Similarity: {max_similarity:.3f} (threshold: {RECOGNITION_THRESHOLD})"
            )
        
        # Face recognition successful, proceed with payment
        transaction_id = str(uuid.uuid4())
        
        # Get client IP
        client_ip = x_forwarded_for.split(',')[0] if x_forwarded_for else "127.0.0.1"

        # Create transaction record
        transaction = Transaction(
            transaction_id=transaction_id,
            user_id=user.id,
            amount=payment_data.amount,
            currency=payment_data.currency,
            transaction_type='card_payment',
            purpose=payment_data.purpose or "",
            status="pending",
            face_auth_confidence=str(best_confidence),
            metadata=''
        )
        if saved_card:
            transaction.card_id = saved_card.id
        
        db.add(transaction)

        # Log biometric audit for payment
        audit = BiometricAudit(
            user_id=user.id,
            action="card_payment_auth_multi_angle",
            confidence_score=str(best_confidence),
            liveness_check=True,
            ip_address=client_ip,
            user_agent=user_agent or "unknown",
            success=True,
            transaction_id=transaction_id,
            metadata=""
        )
        db.add(audit)
        db.commit()
        
        # Record metrics
        MetricsUtils.record_face_auth_attempt(
            status="success",
            user_id=user.id,
            confidence=float(best_confidence) if best_confidence is not None else None
        )

        # Save new card if requested
        card_saved = False
        if card_details and payment_data.save_card:
            try:
                card_id = str(uuid.uuid4())
                card_number = re.sub(r'\D', '', card_details.number)
                
                # Create card token for secure storage
                card_token = encryption_service.generate_card_token(card_number)
                print(f"Generated card token: {card_token}")
                new_saved_card = SavedCard(
                    id=card_id,
                    user_id=user.id,
                    card_token=card_token,
                    last_four_encrypted=encryption_service.encrypt(card_number[-4:]),
                    brand=get_card_brand(card_number),
                    expiry_month=card_details.expiry_month,
                    expiry_year=card_details.expiry_year,
                    is_primary=card_details.is_primary if hasattr(card_details, 'is_primary') else False,
                    holder_name_encrypted=encryption_service.encrypt(card_details.holder_name),
                    is_active=True
                )
                db.add(new_saved_card)
                transaction.card_id = card_id
                card_saved = True
                print(f"New card saved: {new_saved_card}")
            except Exception as e:
                logging.error(f"Error saving card: {e}")
                # Continue with payment even if card saving fails

        # Update transaction status
        transaction.status = "authorized"
        db.commit()
        print(f"Transaction {transaction_id} authorized with multi-angle verification")
        
        # Process payment through appropriate processor
        if payment_data.currency != settings.DEFAULT_CURRENCY:
            # Use CrossBorderPaymentProcessor through PaymentGatewayAPI
            cross_border_processor = CrossBorderPaymentProcessor()
            payment_gateway_api = PaymentGatewayAPI(cross_border_processor)
            
            print(f"Using cross-border payment processor for currency: {payment_data.currency}")
            
            # Prepare cross-border payment data
            cross_border_payment_data = {
                'transaction_id': transaction_id,
                'sender': {
                    'user_id': user.id,
                    'country': getattr(user, 'country', 'US'),  # Default to US if not set
                    'currency': settings.DEFAULT_CURRENCY,
                    'amount': str(payment_data.amount)
                },
                'recipient': {
                    'user_id': user.id,  # Same user for card payment
                    'country': getattr(user, 'country', 'US'),
                    'currency': payment_data.currency,
                    'bank_details': {}  # Card payments don't need bank details
                },
                'payment_method': 'card',
                'purpose': payment_data.purpose or 'Card Payment',
                'metadata': {
                    'card_details': card_details.model_dump() if card_details else None,
                    'saved_card': saved_card.id if saved_card else None,
                    'confidence': str(best_confidence),
                    'face_auth': True
                }
            }
            print(f"Cross-border payment data prepared: {cross_border_payment_data}")
            # Process through PaymentGatewayAPI
            api_key = getattr(settings, 'CROSS_BORDER_API_KEY', 'cbp_live_key_12345')
            gateway_result = await payment_gateway_api.handle_payment_request(
                cross_border_payment_data, 
                api_key
            )
            
            if gateway_result['success']:
                payment_result = gateway_result['data']
                print(f"Cross-border payment result: {payment_result}")
            else:
                payment_result = {
                    'success': False,
                    'error_message': gateway_result.get('error', 'Cross-border payment failed')
                }
        else:
            # Use default payment processor for domestic payments
            processor = payment_processor
            print(f"Using default payment processor for currency: {payment_data.currency}")
            
            payment_result = await processor.process_card_payment({
                'transaction_id': transaction_id,
                'user_id': user.id,
                'amount': payment_data.amount,
                'currency': payment_data.currency,
                'card_details': card_details.model_dump() if card_details else None,
                'saved_card': saved_card,
                'confidence': str(best_confidence),
                'metadata': cross_border_payment_data['metadata']
            })

        print(f"Payment result: {payment_result}")
        
        if payment_result.get("success"):
            transaction.status = "completed"
            
            # For cross-border payments, update with additional info
            if payment_data.currency != settings.DEFAULT_CURRENCY:
                transaction.metadata = json.dumps({
                    'routing_method': payment_result.get('routing_method'),
                    'external_reference': payment_result.get('external_reference'),
                    'processing_fee': str(payment_result.get('processing_fee', 0)),
                    'cross_border': True
                })
            
            db.commit()

            # Send notification
            notification_message = f"Card payment of ${payment_data.amount} {payment_data.currency} completed successfully"
            if payment_data.currency != settings.DEFAULT_CURRENCY:
                notification_message += f" via cross-border payment gateway"
            
            await aws_service.send_notification(
                message=notification_message,
                subject="Card Payment Successful",
                user_email=user.email
            )

            # Record successful payment metric
            MetricsUtils.record_payment_transaction("completed-card", payment_data.currency)

            response_data = {
                'success': True,
                'transaction_id': transaction_id,
                'status': "completed",
                'message': "Card payment processed successfully with multi-angle verification",
                'confidence_score': best_confidence * 100 if best_confidence else 0,
                'angles_verified': len(request.images_data)
            }
            
            # Add cross-border specific information
            if payment_data.currency != settings.DEFAULT_CURRENCY:
                response_data.update({
                    'cross_border': True,
                    'routing_method': payment_result.get('routing_method'),
                    'external_reference': payment_result.get('external_reference'),
                    'processing_fee': payment_result.get('processing_fee'),
                    'estimated_completion': payment_result.get('estimated_completion')
                })

            return PaymentResponse(**response_data)
        else:
            transaction.status = "failed"
            transaction.failure_reason = payment_result.get('error_message', 'Unknown error')
            db.commit()
            
            return PaymentResponse(
                success=False,
                transaction_id=transaction_id,
                status="failed",
                message=f"Card payment failed: {transaction.failure_reason}"
            )
            
    except Exception as e:
        logging.error(f"Card payment authorization error: {e}")
        raise HTTPException(status_code=500, detail=f"Card payment authorization error: {str(e)}")

@router.post("/save-card", response_model=SavedCardResponse)
async def save_new_card(
    card_data: CardDetails,
    db: Session = Depends(get_db),
    user_id: str = Depends(verify_token)
):
    """Save a new card for the user"""
    try:
        print(f"Saving new card for user: {user_id}")
        
        # Get user from database
        user = db.query(User).filter(User.email == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if not card_data.number or not card_data.holder_name:
            raise HTTPException(status_code=400, detail="Card number and holder name are required")

        print(f"Testing User: {user_id}")
        # Validate card number using Luhn algorithm
        # if not validate_card_number(card_data.number):
        #     raise HTTPException(status_code=400, detail="Invalid card number")
        
        print(f"Card number {card_data.number} is valid")
        
        # Validate expiry date
        current_year = datetime.now().year
        current_month = datetime.now().month
        
        # if (card_data.expiry_year < current_year or
        #     (card_data.expiry_year == current_year and card_data.expiry_month < current_month)):
        #     raise HTTPException(status_code=400, detail="Card has expired")
        
        # Clean card number (remove spaces and non-digits)
        card_number = re.sub(r'\D', '', card_data.number)
        print(f"Cleaned card number: {card_number}")
        # Check if card already exists for this user
        card_token = encryption_service.generate_card_token(card_number)
        existing_card = db.query(SavedCard).filter(
            SavedCard.user_id == user.id,
            SavedCard.card_token == card_token,
            SavedCard.is_active == True
        ).first()
        print(f"Checking for existing card: {existing_card}")
        if existing_card:
            raise HTTPException(status_code=409, detail="This card is already saved")
        
        # If this is set as primary, update existing primary cards
        if card_data.is_primary:
            db.query(SavedCard).filter(
                SavedCard.user_id == user.id,
                SavedCard.is_active == True
            ).update({SavedCard.is_primary: False})
        
        # Generate unique card ID
        card_id = str(uuid.uuid4())
        
        # Create new saved card
        new_saved_card = SavedCard(
            id=card_id,
            user_id=user.id,
            card_token=card_token,
            last_four_encrypted=encryption_service.encrypt(card_number[-4:]),
            brand=get_card_brand(card_number),
            expiry_month=card_data.expiry_month,
            expiry_year=card_data.expiry_year,
            is_primary=card_data.is_primary or False,
            holder_name_encrypted=encryption_service.encrypt(card_data.holder_name),
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        # Save to database
        db.add(new_saved_card)
        db.commit()
        db.refresh(new_saved_card)
        
        print(f"New card saved successfully with ID: {card_id}")
        
        # Log audit trail
        audit = BiometricAudit(
            user_id=user.id,
            action="save_card",
            success=True,
            ip_address="127.0.0.1",  # You may want to extract real IP
            user_agent="api_request",
            metadata=f"Card saved: {get_card_brand(card_number)} ending in {card_number[-4:]}"
        )
        db.add(audit)
        db.commit()
        
        # Record metrics
        # MetricsUtils.record_card_saved(user.id, get_card_brand(card_number))

        # Send notification
        await aws_service.send_notification(
            message=f"New {get_card_brand(card_number)} card ending in {card_number[-4:]} has been saved to your account",
            subject="New Card Added",
            user_email=user.email
        )
        
        # Return the saved card response
        return SavedCardResponse(
            id=new_saved_card.id,
            last_four=card_number[-4:],
            brand=new_saved_card.brand,
            expiry_month=new_saved_card.expiry_month,
            expiry_year=new_saved_card.expiry_year,
            holder_name=card_data.holder_name,
            created_at=new_saved_card.created_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error saving card: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error saving card: {str(e)}")

@router.put("/{card_id}/primary")
async def set_primary_card(
    card_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(verify_token)
):
    """Set a saved card as primary"""
    try:
        print(f"Setting card {card_id} as primary for user: {user_id}")
        user = db.query(User).filter(User.email == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Find the card
        card = db.query(SavedCard).filter(
            SavedCard.id == card_id,
            SavedCard.user_id == user.id,
            SavedCard.is_active == True
        ).first()
        
        if not card:
            raise HTTPException(status_code=404, detail="Card not found")
        
        # Update all cards for this user to not be primary
        db.query(SavedCard).filter(
            SavedCard.user_id == user.id,
            SavedCard.is_active == True
        ).update({SavedCard.is_primary: False})
        
        # Set this card as primary
        card.is_primary = True
        card.updated_at = datetime.utcnow()
        
        db.commit()
        
        print(f"Card {card_id} set as primary for user {user.id}")
        
        return {"message": "Card set as primary successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error setting primary card: {e}")
        raise HTTPException(status_code=500, detail=f"Error setting primary card: {str(e)}")

@router.patch("/cards/{card_id}")
async def update_saved_card(
    card_id: str,
    updates: dict,
    db: Session = Depends(get_db),
    user_id: str = Depends(verify_token)
):
    """Update card details (limited fields for security)"""
    try:
        user = db.query(User).filter(User.email == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Find the card
        card = db.query(SavedCard).filter(
            SavedCard.id == card_id,
            SavedCard.user_id == user.id,
            SavedCard.is_active == True
        ).first()
        
        if not card:
            raise HTTPException(status_code=404, detail="Card not found")
        
        # Only allow updating certain fields for security
        allowed_fields = ['holder_name', 'expiry_month', 'expiry_year', 'is_primary']
        
        for field, value in updates.items():
            if field not in allowed_fields:
                raise HTTPException(status_code=400, detail=f"Field '{field}' cannot be updated")
            
            if field == 'holder_name':
                card.holder_name_encrypted = encryption_service.encrypt(str(value))
            elif field == 'expiry_month':
                if not isinstance(value, int) or value < 1 or value > 12:
                    raise HTTPException(status_code=400, detail="Invalid expiry month")
                card.expiry_month = value
            elif field == 'expiry_year':
                if not isinstance(value, int) or value < datetime.now().year:
                    raise HTTPException(status_code=400, detail="Invalid expiry year")
                card.expiry_year = value
            elif field == 'is_primary':
                if value:
                    # Set all other cards to not primary
                    db.query(SavedCard).filter(
                        SavedCard.user_id == user.id,
                        SavedCard.is_active == True,
                        SavedCard.id != card_id
                    ).update({SavedCard.is_primary: False})
                card.is_primary = bool(value)
        
        card.updated_at = datetime.utcnow()
        db.commit()
        
        print(f"Card {card_id} updated successfully")
        
        return {"message": "Card updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error updating card: {e}")
        raise HTTPException(status_code=500, detail=f"Error updating card: {str(e)}")

@router.post("/validate-card")
async def validate_card_details(
    card_validation: CardValidationRequest,
    user_id: str = Depends(verify_token)
):
    """Validate card details without saving"""
    try:
        # Validate card number
        if not validate_card_number(card_validation.number):
            return {
                "valid": False,
                "errors": ["Invalid card number"]
            }
        
        # Validate expiry
        current_year = datetime.now().year
        current_month = datetime.now().month
        
        errors = []
        
        if (card_validation.expiry_year < current_year or
            (card_validation.expiry_year == current_year and card_validation.expiry_month < current_month)):
            errors.append("Card has expired")
        
        if card_validation.expiry_month < 1 or card_validation.expiry_month > 12:
            errors.append("Invalid expiry month")
        
        if len(card_validation.cvv) < 3 or len(card_validation.cvv) > 4:
            errors.append("Invalid CVV")
        
        if not card_validation.cvv.isdigit():
            errors.append("CVV must contain only digits")
        
        card_brand = get_card_brand(card_validation.number)
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "card_brand": card_brand,
            "last_four": card_validation.number[-4:] if len(errors) == 0 else None
        }
        
    except Exception as e:
        logging.error(f"Card validation error: {e}")
        return {
            "valid": False,
            "errors": ["Validation failed"]
        }

def validate_card_number(card_number: str) -> bool:
    """Validate card number using Luhn algorithm"""
    card_number = re.sub(r'\D', '', card_number)
    
    if len(card_number) < 13 or len(card_number) > 19:
        return False
    
    # Luhn algorithm
    def luhn_check(card_num):
        num = [int(x) for x in card_num[::-1]]
        for i in range(1, len(num), 2):
            num[i] *= 2
            if num[i] > 9:
                num[i] = num[i] // 10 + num[i] % 10
        return sum(num) % 10 == 0
    
    return luhn_check(card_number)

def get_card_brand(card_number: str) -> str:
    """Determine card brand from card number"""
    card_number = re.sub(r'\D', '', card_number)
    
    if card_number.startswith('4'):
        return 'Visa'
    elif card_number.startswith(('51', '52', '53', '54', '55')):
        return 'Mastercard'
    elif card_number.startswith(('34', '37')):
        return 'American Express'
    elif card_number.startswith('6011'):
        return 'Discover'
    else:
        return 'Unknown'
