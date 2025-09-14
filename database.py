from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON, Boolean, ForeignKey, Enum, create_engine, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, Session
from sqlalchemy.sql import func
from datetime import datetime
import enum
from typing import Generator

from backend.config import settings

DATABASE_URL = settings.DATABASE_URL

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=300)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Enums
class PaymentStatus(str, enum.Enum):
    OPEN = "open"
    PAID = "paid"
    CANCELED = "canceled"
    EXPIRED = "expired"
    FAILED = "failed"
    PENDING = "pending"

class RefundStatus(str, enum.Enum):
    QUEUED = "queued"
    PENDING = "pending"
    PROCESSING = "processing"
    REFUNDED = "refunded"
    FAILED = "failed"

# User and Authentication Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    phone = Column(String, unique=True, index=True, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    payments = relationship("Payment", back_populates="user")
    mollie_customers = relationship("MollieCustomer", back_populates="user")
    payment_methods = relationship("PaymentMethod", back_populates="user")
    transaction_logs = relationship("TransactionLog", back_populates="user")

class OTPVerification(Base):
    __tablename__ = "otp_verifications"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, index=True, nullable=True)  # May be null for new registrations
    email = Column(String, index=True, nullable=True)
    phone = Column(String, index=True, nullable=True)
    otp_code_hash = Column(String, nullable=False)  # Store hashed OTP for security
    otp_method = Column(String, nullable=False)  # 'sms', 'email', 'app'
    purpose = Column(String, nullable=False)  # 'login_fallback', 'transaction_auth', 'registration'
    transaction_id = Column(String, nullable=True)  # Link to specific transaction if applicable
    attempts = Column(Integer, default=0)
    max_attempts = Column(Integer, default=3)
    is_verified = Column(Boolean, default=False)
    is_expired = Column(Boolean, default=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    verified_at = Column(DateTime, nullable=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    
    # Metadata for tracking and security
    original_auth_method = Column(String, nullable=True)  # What auth method failed
    fallback_reason = Column(String, nullable=True)  # Why fallback was triggered

class OTPAuditLog(Base):
    __tablename__ = "otp_audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True, nullable=False)
    action = Column(String, nullable=False)  # 'generated', 'sent', 'verified', 'failed', 'expired'
    otp_method = Column(String, nullable=False)
    email = Column(String, nullable=True)
    phone = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    success = Column(Boolean, nullable=False)
    error_message = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    meta_data = Column(JSON, nullable=True)  # Additional context

# Transaction Models
class Transaction(Base):
    __tablename__ = "transactions"
    
    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(String, unique=True, index=True)
    user_id = Column(Integer, index=True)
    amount = Column(Float)
    currency = Column(String)
    recipient_account = Column(String)
    recipient_bank = Column(String)
    transaction_type = Column(String)  # 'payment', 'refund', etc.
    purpose = Column(String)
    status = Column(String, default="pending")
    failure_reason = Column(String, nullable=True)  # For failed transactions
    face_auth_confidence = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    processed_at = Column(DateTime, nullable=True)
    meta_data = Column(Text, nullable=True)  # Store additional info as JSON string
    card_id = Column(String, nullable=True)  # Link to saved card if used

# Mollie Payment Models
class Payment(Base):
    __tablename__ = "payments"
    
    id = Column(Integer, primary_key=True, index=True)
    mollie_payment_id = Column(String(50), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Payment details
    amount = Column(Float, nullable=False)
    currency = Column(String(3), nullable=False)
    description = Column(String(255), nullable=False)
    method = Column(String(50), nullable=True)
    
    # Status and tracking
    status = Column(Enum(PaymentStatus), nullable=False, default=PaymentStatus.OPEN, index=True)
    checkout_url = Column(Text, nullable=True)
    redirect_url = Column(Text, nullable=True)
    webhook_url = Column(Text, nullable=True)
    
    # Metadata and details
    metadata_payment = Column(JSON, nullable=True)
    details = Column(JSON, nullable=True)
    
    # Customer information
    customer_id = Column(String(50), nullable=True)
    mandate_id = Column(String(50), nullable=True)
    sequence_type = Column(String(20), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=True, onupdate=func.now())
    paid_at = Column(DateTime(timezone=True), nullable=True)
    canceled_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    failed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="payments")
    refunds = relationship("RefundModel", back_populates="payment")
    transaction_logs = relationship("TransactionLog", back_populates="payment")
    
    def __repr__(self):
        return f"<Payment(id={self.id}, mollie_id={self.mollie_payment_id}, status={self.status})>"

class RefundModel(Base):
    __tablename__ = "refunds"
    
    id = Column(Integer, primary_key=True, index=True)
    mollie_refund_id = Column(String(50), unique=True, nullable=False, index=True)
    payment_id = Column(Integer, ForeignKey("payments.id"), nullable=False, index=True)
    
    # Refund details
    amount = Column(Float, nullable=False)
    currency = Column(String(3), nullable=False)
    description = Column(String(255), nullable=True)
    status = Column(Enum(RefundStatus), nullable=False, default=RefundStatus.QUEUED, index=True)
    
    # Settlement information
    settlement_amount = Column(Float, nullable=True)
    settlement_currency = Column(String(3), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=True, onupdate=func.now())
    
    # Relationships
    payment = relationship("Payment", back_populates="refunds")
    
    def __repr__(self):
        return f"<Refund(id={self.id}, mollie_id={self.mollie_refund_id}, status={self.status})>"

class MollieCustomer(Base):
    __tablename__ = "mollie_customers"
    
    id = Column(Integer, primary_key=True, index=True)
    mollie_customer_id = Column(String(50), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Customer details
    name = Column(String(255), nullable=True)
    email = Column(String(255), nullable=True, index=True)
    locale = Column(String(10), nullable=True)
    
    # Metadata
    metadata_payment = Column(JSON, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=True, onupdate=func.now())
    
    # Relationships
    user = relationship("User", back_populates="mollie_customers")
    mandates = relationship("MollieMandate", back_populates="customer")
    
    def __repr__(self):
        return f"<MollieCustomer(id={self.id}, mollie_id={self.mollie_customer_id})>"

class MollieMandate(Base):
    __tablename__ = "mollie_mandates"
    
    id = Column(Integer, primary_key=True, index=True)
    mollie_mandate_id = Column(String(50), unique=True, nullable=False, index=True)
    customer_id = Column(Integer, ForeignKey("mollie_customers.id"), nullable=False, index=True)
    
    # Mandate details
    method = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False, index=True)
    mandate_reference = Column(String(255), nullable=True)
    signature_date = Column(DateTime(timezone=True), nullable=True)
    
    # Consumer details
    consumer_name = Column(String(255), nullable=True)
    consumer_account = Column(String(255), nullable=True)
    consumer_bic = Column(String(20), nullable=True)
    
    # Additional details
    details = Column(JSON, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=True, onupdate=func.now())
    
    # Relationships
    customer = relationship("MollieCustomer", back_populates="mandates")
    
    def __repr__(self):
        return f"<MollieMandate(id={self.id}, mollie_id={self.mollie_mandate_id}, status={self.status})>"

class PaymentMethod(Base):
    __tablename__ = "payment_methods"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Method details
    mollie_method_id = Column(String(50), nullable=False)
    method_name = Column(String(100), nullable=False)
    method_type = Column(String(50), nullable=False)  # card, bank, wallet, etc.
    
    # Method-specific data
    last_four = Column(String(4), nullable=True)  # For cards
    brand = Column(String(50), nullable=True)  # Card brand
    issuer = Column(String(100), nullable=True)  # Bank/issuer name
    
    # Status
    is_active = Column(Boolean, default=True, index=True)
    is_primary = Column(Boolean, default=False, index=True)
    
    # Expiration (for cards)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Metadata
    metadata_payment = Column(JSON, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=True, onupdate=func.now())
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="payment_methods")
    
    def __repr__(self):
        return f"<PaymentMethod(id={self.id}, method={self.mollie_method_id}, type={self.method_type})>"

class WebhookLog(Base):
    __tablename__ = "webhook_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    mollie_payment_id = Column(String(50), nullable=True, index=True)
    
    # Webhook details
    event_type = Column(String(50), nullable=False)
    payload = Column(JSON, nullable=False)
    signature = Column(String(255), nullable=True)
    
    # Processing status
    processed = Column(Boolean, default=False, index=True)
    processing_attempts = Column(Integer, default=0)
    processing_error = Column(Text, nullable=True)
    
    # Timestamps
    received_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    processed_at = Column(DateTime(timezone=True), nullable=True)
    
    def __repr__(self):
        return f"<WebhookLog(id={self.id}, event_type={self.event_type}, processed={self.processed})>"

class TransactionLog(Base):
    __tablename__ = "transaction_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    payment_id = Column(Integer, ForeignKey("payments.id"), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Transaction details
    transaction_type = Column(String(50), nullable=False)  # payment, refund, etc.
    action = Column(String(50), nullable=False)  # create, update, cancel, etc.
    
    # Change tracking
    old_values = Column(JSON, nullable=True)
    new_values = Column(JSON, nullable=True)
    
    # Context
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    
    # Relationships
    payment = relationship("Payment", back_populates="transaction_logs")
    user = relationship("User", back_populates="transaction_logs")
    
    def __repr__(self):
        return f"<TransactionLog(id={self.id}, type={self.transaction_type}, action={self.action})>"

# Biometric and Security Models
class BiometricAudit(Base):
    __tablename__ = "biometric_audit"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    action = Column(String)  # 'auth', 'payment_auth', 'multi_angle_auth'
    confidence_score = Column(Float)
    liveness_check = Column(Boolean)
    ip_address = Column(String)
    user_agent = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean)
    transaction_id = Column(String, nullable=True)  # Link to transaction if applicable
    meta_data = Column(Text, nullable=True)  # Additional audit data

class SavedCard(Base):
    __tablename__ = "saved_cards"
    
    id = Column(String, primary_key=True)
    user_id = Column(Integer, nullable=False, index=True)
    card_token = Column(String, nullable=False, unique=True)  # Tokenized card reference
    last_four_encrypted = Column(String, nullable=False)
    brand = Column(String, nullable=False)  # Visa, Mastercard, etc.
    expiry_month = Column(Integer, nullable=False)
    expiry_year = Column(Integer, nullable=False)
    is_primary = Column(Boolean, default=False, nullable=False)
    holder_name_encrypted = Column(String, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    deleted_at = Column(DateTime, nullable=True)

class UserFaceProfile(Base):
    __tablename__ = "user_face_profiles"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    face_encodings = Column(LargeBinary, nullable=False)  # Serialized face encodings
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)
    
    # Optional: Store metadata about registration
    registration_device = Column(String, nullable=True)
    registration_ip = Column(String, nullable=True)

class FaceEncoding(Base):
    __tablename__ = "face_encodings"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    email = Column(String, index=True, nullable=False)
    encoding = Column(LargeBinary, nullable=False)  # Store numpy array as binary
    angle_info = Column(String, nullable=True)  # Store which angle this encoding represents
    confidence_score = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

# System Monitoring
class SystemMetrics(Base):
    __tablename__ = "system_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    metric_name = Column(String, index=True)
    metric_value = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)
    tags = Column(JSON, nullable=True)  # Store additional metric tags

# Database functions
def create_tables():
    """Create all tables in the database"""
    Base.metadata.create_all(bind=engine)

def get_db() -> Generator[Session, None, None]:
    """Database dependency for FastAPI"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()