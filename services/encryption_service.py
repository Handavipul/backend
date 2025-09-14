import base64
import hashlib
import os
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging
from typing import Optional

class EncryptionService:
    def __init__(self, master_key: Optional[str] = None):
        """Initialize encryption service with master key"""
        if master_key is None:
            master_key = os.getenv("PAYMENT_ENCRYPTION_KEY", "MyDevFallbackKey123!@#")
        self.master_key = master_key.encode()
        self._fernet = self._create_fernet_instance()

    def _create_fernet_instance(self) -> Fernet:
        """Create Fernet instance for encryption/decryption"""
        try:
            # Derive key from master key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'secure_payment_salt',  # In production, use random salt per encryption
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.master_key))
            return Fernet(key)
        except Exception as e:
            logging.error(f"Error creating Fernet instance: {e}")
            raise
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext string"""
        try:
            if not plaintext:
                return ""
            return self._fernet.encrypt(plaintext.encode()).decode()
        except Exception as e:
            logging.error(f"Encryption error: {e}")
            raise ValueError("Failed to encrypt data")
    
    def decrypt(self, encrypted_text: str) -> str:
        """Decrypt encrypted string"""
        try:
            if not encrypted_text:
                return ""
            print(f"Decrypting: {encrypted_text}")  # Debugging line
            decrypted_data = self._fernet.decrypt(encrypted_text.encode())
            print(f"Decrypted data: {decrypted_data}")  # Debugging line
            return decrypted_data.decode()
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            raise ValueError("Failed to decrypt data")
    
    def generate_card_token(self, card_number: str) -> str:
        """Generate a secure token for card number"""
        try:
            # Remove spaces and non-digits
            clean_card_number = ''.join(filter(str.isdigit, card_number))
            
            # Create hash with salt
            salt = secrets.token_bytes(16)
            card_hash = hashlib.pbkdf2_hmac(
                'sha256',
                clean_card_number.encode(),
                salt,
                100000
            )
            
            # Combine salt and hash, then encode
            token_data = salt + card_hash
            return base64.urlsafe_b64encode(token_data).decode()
            
        except Exception as e:
            logging.error(f"Token generation error: {e}")
            raise ValueError("Failed to generate card token")
    
    def verify_card_token(self, card_number: str, token: str) -> bool:
        """Verify if card number matches the token"""
        try:
            # Decode token
            token_data = base64.urlsafe_b64decode(token.encode())
            salt = token_data[:16]
            stored_hash = token_data[16:]
            
            # Clean card number
            clean_card_number = ''.join(filter(str.isdigit, card_number))
            
            # Generate hash with same salt
            card_hash = hashlib.pbkdf2_hmac(
                'sha256',
                clean_card_number.encode(),
                salt,
                100000
            )
            
            return secrets.compare_digest(stored_hash, card_hash)
            
        except Exception as e:
            logging.error(f"Token verification error: {e}")
            return False
    
    def hash_sensitive_data(self, data: str) -> str:
        """Create a one-way hash for sensitive data"""
        try:
            salt = secrets.token_bytes(16)
            hash_value = hashlib.pbkdf2_hmac('sha256', data.encode(), salt, 100000)
            return base64.urlsafe_b64encode(salt + hash_value).decode()
        except Exception as e:
            logging.error(f"Hashing error: {e}")
            raise ValueError("Failed to hash data")