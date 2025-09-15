import os
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # Database
    # DATABASE_URL: str = "postgresql://postgres:Vipul123@localhost/payment_gatewaydemo"
    DATABASE_URL: str = "postgresql+psycopg2://avpayuser:Avsol%401990@localhost:5432/avpay"  #docker test

    # JWT
    #>>> from cryptography.fernet import Fernet  --> ENCRYPTION_KEY
    #>>> print(Fernet.generate_key().decode())
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = 24

    #Encryption
    PAYMENT_ENCRYPTION_KEY: str 

    # AWS
    AWS_ACCESS_KEY_ID: str = os.getenv("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY: str = os.getenv("AWS_SECRET_ACCESS_KEY")
    AWS_REGION: str = "eu-west-2"
    SNS_NOTIFICATION_TOPIC_ARN: str = os.getenv("SNS_NOTIFICATION_TOPIC_ARN")
    SQS_PAYMENT_QUEUE_URL: str = os.getenv("SQS_PAYMENT_QUEUE_URL")
    S3_SECURE_BUCKET: str = os.getenv("S3_SECURE_BUCKET")
    MOLLIE_API_KEY: str = os.getenv("MOLLIE_API_KEY")


    # Face Recognition
    FACE_CONFIDENCE_THRESHOLD: float = 0.3
    LIVENESS_THRESHOLD: float = 0.7
    MULTI_ANGLE_REQUIRED: int = 2  # Number of angles required
    DEFAULT_CURRENCY: str = "GBP"
    
    # mTLS Configuration
    MTLS_ENABLED: bool = False
    CLIENT_CERT_PATH: Optional[str] = "/certs/client.crt"
    CLIENT_KEY_PATH: Optional[str] = "/certs/client.key"
    CA_CERT_PATH: Optional[str] = "/certs/ca.crt"
    
    # Server Configuration
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False

    # Email Configuration (Gmail)
    EMAIL_USER: Optional[str] = "f144ab1908830f"  # Your Gmail address
    EMAIL_APP_PASSWORD: Optional[str] = "07638b4c54ae77"  # Gmail app-specific password
    
    # SMS Configuration (Textbelt)
    TEXTBELT_API_KEY: Optional[str] = "59e1c0feca58d34c1f085c2669e13bc7ae01835ep5HkHGW4HCo0CKx73WufzWf1M"  # "textbelt" for free tier, or your API key
    
    # OTP Settings
    OTP_EXPIRY_MINUTES: int = 10
    OTP_MAX_ATTEMPTS: int = 3
    OTP_COOLDOWN_MINUTES: int = 5
    
    # Security Settings
    OTP_RATE_LIMIT_PER_HOUR: int = 10  # Max OTPs per email/phone per hour
    
    
    # CORS
    CORS_ORIGINS: list = ["http://localhost:4200", "https://localhost:8000"]
    
    # Prometheus
    METRICS_ENABLED: bool = True
    METRICS_PATH: str = "/metrics"
    
    class Config:
        env_file = ".env"

settings = Settings()