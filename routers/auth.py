import logging
import os
from fastapi import APIRouter, HTTPException, Depends, Header, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import numpy as np
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from backend.config import settings
from backend.database import FaceEncoding, UserFaceProfile, get_db, User, BiometricAudit
from backend.middleware.metrics import MetricsUtils
from sklearn.metrics.pairwise import cosine_similarity
from backend.services.face_service import FaceDuplicateDetectionService

router = APIRouter()
face_extraction_service = FaceDuplicateDetectionService()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class MultiAngleFaceAuthRequest(BaseModel):
    images_data: List[str]  # Multiple angle images
    timestamp: str
    user_agent: Optional[str] = None
    email: Optional[str]

class FaceAuthResponse(BaseModel):
    success: bool
    user_id: Optional[int] = None
    token: Optional[str] = None
    confidence: Optional[float] = None
    consistency_score: Optional[float] = None
    angles_captured: Optional[int] = None
    message: Optional[str] = None
    debug_info: Optional[dict] = None
    Email: Optional[str] = None

# Pydantic models
class EmailValidationRequest(BaseModel):
    email: EmailStr
    mode: str  # 'login' or 'register'

class EmailValidationResponse(BaseModel):
    valid: bool
    message: str

class FaceAuthRequest(BaseModel):
    images: List[str]  # Base64 encoded images
    email: Optional[EmailStr] = None

class AuthResponse(BaseModel):
    success: bool
    message: str
    token: Optional[str] = None
    email: Optional[str] = None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return email
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

@router.post("/register", response_model=AuthResponse)
async def register_face(request: FaceAuthRequest, db: Session = Depends(get_db), 
                        x_forwarded_for: Optional[str] = Header(None),
                        user_agent: Optional[str] = Header(None)):
    """Register user with face encodings from multiple angles - includes duplicate detection"""
    try:
        if not request.email:
            raise HTTPException(status_code=400, detail="Email is required for registration")
        
        # Check if user already exists
        existing_user = db.query(User).filter(User.email == request.email).first()
        if existing_user:
            return AuthResponse(
                success=False, 
                message="Email already registered. Please use login instead."
            )
        
        if len(request.images) < 3:
            return AuthResponse(
                success=False, 
                message="Please provide at least 3 images from different angles for better recognition"
            )
        
        # Extract face encodings from all images
        face_encodings = []
        angles = ["center", "left", "right", "up", "down"]
        
        for i, image_data in enumerate(request.images):
            angle_info = angles[i] if i < len(angles) else f"angle_{i+1}"
            result, error = face_extraction_service.extract_face_encodings(
            image_data=image_data, 
            angle_info=angle_info
        )
            if error:
                logging.warning(f"Failed to process {angle_info} image for {request.email}: {error}")
                continue
            
            face_encodings.append(result['embedding'])
        
        if not face_encodings:
            return AuthResponse(
                success=False,
                message="Could not extract face encodings from any of the provided images. Please ensure your face is clearly visible."
            )
        
        # Check for duplicate registration using the extracted encodings
        is_duplicate, existing_email = face_extraction_service.check_for_duplicate_registration(
            face_encodings, request.email, db
        )
        
        if is_duplicate:
            return AuthResponse(
                success=False,
                message=f"This face is already registered with a different email address ({existing_email}). "
                       f"Please use your existing account or contact support if this is an error."
            )
        
        # Create new user
        new_user = User(email=request.email)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        # Store each face encoding in the database
        successful_encodings = 0
        
        for i, image_data in enumerate(request.images):
            angle_info = angles[i] if i < len(angles) else f"angle_{i+1}"

            result, error = face_extraction_service.extract_face_encodings(
            image_data=image_data, 
            angle_info=angle_info
        )
            if error:
                continue
            
            # Store face encoding in database
            face_encoding = FaceEncoding(
                user_id=new_user.id,
                email=request.email,
                encoding=result['embedding'].tobytes(),  # Convert numpy array to bytes
                angle_info=angle_info,
                confidence_score=str(result['confidence'])
            )
            db.add(face_encoding)
            successful_encodings += 1
        
        if successful_encodings == 0:
            # Clean up user if no encodings were successful
            db.delete(new_user)
            db.commit()
            return AuthResponse(
                success=False,
                message="Could not extract face encodings from any of the provided images. Please ensure your face is clearly visible."
            )
        
        # Also create a UserFaceProfile entry for additional duplicate checking
        user_face_profile = UserFaceProfile(
            email=request.email,
            face_encodings=face_extraction_service.serialize_encodings(face_encodings),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(user_face_profile)
        
        db.commit()
        
        # Get client IP
        client_ip = x_forwarded_for.split(',')[0] if x_forwarded_for else "127.0.0.1"
          # Log audit
        audit = BiometricAudit(
            user_id=face_encoding.user_id,
            action="multi_angle_auth",
            confidence_score= float(result['confidence']),
            liveness_check= True,
            ip_address=client_ip,
            user_agent=user_agent or "unknown",
            success=True,
            metadata=''
        )
        db.add(audit)
        db.commit()
        
        # Record metrics
        MetricsUtils.record_face_auth_attempt(
            status="success",
            user_id=face_encoding.user_id,
            confidence=float(face_encoding.confidence_score) if face_encoding.confidence_score is not None else None
        )
        
        logging.info(f"✅ Authentication successful for user {face_encoding.id}")
        
        return AuthResponse(
            success=True,
            message=f"Registration successful! Stored {successful_encodings} face encodings with duplicate protection."
        )
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Registration error: {str(e)}")
    
@router.post("/login", response_model=AuthResponse)
async def authenticate_with_face(request: FaceAuthRequest, db: Session = Depends(get_db)):
    """Authenticate user with face and email"""
    try:
        if not request.email:
            raise HTTPException(status_code=400, detail="Email is required for authentication")
        
        # Get user and their face encodings
        user = db.query(User).filter(User.email == request.email).first()
        if not user:
            return AuthResponse(success=False, message="User not found")
        
        stored_encodings = db.query(FaceEncoding).filter(FaceEncoding.email == request.email).all()
        if not stored_encodings:
            return AuthResponse(success=False, message="No face data found for this user")
        
        # Process login images
        max_similarity = 0.0
        best_match = None
        
        for image_data in request.images:
            # Fixed: Use keyword arguments
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
        
        # Threshold for face recognition (adjust based on your needs)
        RECOGNITION_THRESHOLD = 0.4
        
        if max_similarity >= RECOGNITION_THRESHOLD:
            # Create access token
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": request.email}, expires_delta=access_token_expires
            )
            
            return AuthResponse(
                success=True,
                message=f"Authentication successful! (Match: {max_similarity:.3f}, Best angle: {best_match})",
                token=access_token,
                email=request.email
            )
        else:
            return AuthResponse(
                success=False,
                message=f"Face not recognized. Similarity: {max_similarity:.3f} (threshold: {RECOGNITION_THRESHOLD})"
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Authentication error: {str(e)}")

@router.post("/validate-email", response_model=EmailValidationResponse)
async def validate_email(request: EmailValidationRequest, db: Session = Depends(get_db)):
    """Validate email for login/registration"""
    try:
        user = db.query(User).filter(User.email == request.email).first()
        
        if request.mode == "register":
            if user:
                return EmailValidationResponse(
                    valid=False, 
                    message="Email already exists. Please use login instead."
                )
            return EmailValidationResponse(valid=True, message="Email available for registration")
            
        elif request.mode == "login":
            if not user:
                return EmailValidationResponse(
                    valid=False, 
                    message="Email not found. Please register first."
                )
            return EmailValidationResponse(valid=True, message="Email found")
        
        return EmailValidationResponse(valid=False, message="Invalid mode")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Validation error: {str(e)}")

# @router.post("/identify", response_model=AuthResponse)
# async def identify_face_only(request: FaceAuthRequest, db: Session = Depends(get_db)):
#     """Identify user by face only (no email required)"""
#     try:
#         if not request.images:
#             raise HTTPException(status_code=400, detail="At least one image is required")
        
#         # Get all stored face encodings
#         all_encodings = db.query(FaceEncoding).all()
#         if not all_encodings:
#             return AuthResponse(success=False, message="No registered faces found")
        
#         best_match_email = None
#         max_similarity = 0.0
#         best_angle = None
        
#         # Process each login image
#         for image_data in request.images:
#             # Fixed: Use keyword arguments
#             result, error = face_extraction_service.extract_face_encodings(
#                 image_data=image_data, 
#                 angle_info="identify"
#             )
            
#             if error:
#                 continue
            
#             login_encoding = result['embedding']
            
#             # Compare with all stored encodings
#             for stored_enc in all_encodings:
#                 stored_embedding = np.frombuffer(stored_enc.encoding, dtype=np.float32)
#                 similarity = face_extraction_service.compare_encodings(login_encoding, stored_embedding)
                
#                 if similarity > max_similarity:
#                     max_similarity = similarity
#                     best_match_email = stored_enc.email
#                     best_angle = stored_enc.angle_info
        
#         RECOGNITION_THRESHOLD = 0.4
        
#         if max_similarity >= RECOGNITION_THRESHOLD and best_match_email:
#             # Create access token
#             access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#             access_token = create_access_token(
#                 data={"sub": best_match_email}, expires_delta=access_token_expires
#             )
            
#             return AuthResponse(
#                 success=True,
#                 message=f"Welcome back! (Confidence: {max_similarity:.3f})",
#                 token=access_token,
#                 email=best_match_email
#             )
#         else:
#             return AuthResponse(
#                 success=False,
#                 message="Face not recognized. Please register first or try different angles."
#             )
            
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Face identification error: {str(e)}")

@router.post("/identify", response_model=AuthResponse)
async def identify_face_only(request: FaceAuthRequest, db: Session = Depends(get_db)):
    """Identify user by face only (no email required)"""
    try:
        if not request.images:
            raise HTTPException(
                status_code=400, 
                detail={
                    "code": "NO_IMAGE_PROVIDED",
                    "message": "At least one image is required",
                    "requiresFallback": False
                }
            )
        
        # Get all stored face encodings
        all_encodings = db.query(FaceEncoding).all()
        if not all_encodings:
            return AuthResponse(
                success=False, 
                message="No registered faces found. Please register first.",
                code="NO_REGISTERED_FACES",
                requiresFallback=False
            )
        
        best_match_email = None
        max_similarity = 0.0
        best_angle = None
        failed_extractions = 0
        total_images = len(request.images)
        
        # Process each login image
        for image_data in request.images:
            # Fixed: Use keyword arguments
            result, error = face_extraction_service.extract_face_encodings(
                image_data=image_data, 
                angle_info="identify"
            )
            
            if error:
                failed_extractions += 1
                continue
            
            login_encoding = result['embedding']
            
            # Compare with all stored encodings
            for stored_enc in all_encodings:
                stored_embedding = np.frombuffer(stored_enc.encoding, dtype=np.float32)
                similarity = face_extraction_service.compare_encodings(login_encoding, stored_embedding)
                
                if similarity > max_similarity:
                    max_similarity = similarity
                    best_match_email = stored_enc.email
                    best_angle = stored_enc.angle_info
        
        # Check if all image processing failed
        if failed_extractions == total_images:
            return AuthResponse(
                success=False,
                message="Unable to detect face in images. Please ensure good lighting and try again.",
                code="FACE_DETECTION_FAILED",
                requiresFallback=True  # Trigger OTP fallback
            )
        
        RECOGNITION_THRESHOLD = 0.4
        
        if max_similarity >= RECOGNITION_THRESHOLD and best_match_email:
            # Create access token
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": best_match_email}, expires_delta=access_token_expires
            )
            
            return AuthResponse(
                success=True,
                message=f"Welcome back! (Confidence: {max_similarity:.3f})",
                token=access_token,
                email=best_match_email,
                code="SUCCESS"
            )
        else:
            # Face detected but not recognized - trigger fallback
            confidence_msg = f"Low confidence: {max_similarity:.3f}" if max_similarity > 0 else "No match found"
            
            return AuthResponse(
                success=False,
                message=f"Face not recognized. {confidence_msg}. Please use backup verification.",
                code="BIOMETRIC_FAILED",  # This will trigger OTP fallback
                requiresFallback=True,
                email=None  # No email since face wasn't recognized
            )
            
    except Exception as e:
        # System error - trigger fallback
        return AuthResponse(
            success=False,
            message="Face recognition system error. Please use backup verification.",
            code="SYSTEM_ERROR",
            requiresFallback=True
        )

@router.get("/me")
async def get_current_user(current_user_email: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Get current user information"""
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "email": user.email,
        "created_at": user.created_at,
        "is_active": user.is_active
    }

@router.get("/")
async def root():
    return {"message": "Face Recognition API is running"}

