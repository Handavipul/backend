"""
Authentication security service with adaptive thresholds and metrics
"""
import logging
from sqlalchemy.orm import Session
from backend.database import get_db, User, BiometricAudit

logger = logging.getLogger(__name__)

class AdaptiveSecurityThresholds:
    """Enhanced security thresholds with adaptive adjustment"""
    
    def __init__(self, db: Session):
        self.db = db
        self.update_thresholds()
    
    def update_thresholds(self):
        """Adjust thresholds based on database state"""
        try:
            valid_users_count = self.db.query(User).filter(
                User.is_active == True,
                User.face_encoding.isnot(None),
                User.face_encoding != ''
            ).count()
            
            if valid_users_count == 0:
                # No valid users - make authentication impossible
                self.MIN_FACE_CONFIDENCE = 1.0
                self.MAX_DISTANCE_THRESHOLD = 0.0
                logger.warning("No valid users found - authentication disabled")
            elif valid_users_count < 5:
                # Few users - be more strict to prevent false positives
                self.MIN_FACE_CONFIDENCE = 0.8
                self.MAX_DISTANCE_THRESHOLD = 0.3
                logger.info(f"Strict thresholds applied for {valid_users_count} users")
            else:
                # Normal operation
                self.MIN_FACE_CONFIDENCE = 0.65
                self.MAX_DISTANCE_THRESHOLD = 0.4
                logger.info(f"Normal thresholds applied for {valid_users_count} users")
                
        except Exception as e:
            logger.error(f"Failed to update security thresholds: {e}")
            # Fallback to safe defaults
            self.MIN_FACE_CONFIDENCE = 0.8
            self.MAX_DISTANCE_THRESHOLD = 0.3
    
    def get_thresholds(self):
        """Get current threshold values"""
        return {
            "min_face_confidence": self.MIN_FACE_CONFIDENCE,
            "max_distance_threshold": self.MAX_DISTANCE_THRESHOLD
        }

class AuthenticationMetrics:
    """Add comprehensive authentication metrics"""
    
    def __init__(self):
        self.total_attempts = 0
        self.successful_authentications = 0
        self.failed_no_face_data = 0
        self.failed_low_confidence = 0
        self.failed_security_validation = 0
        self.failed_no_match = 0
    
    def record_attempt(self, result_type: str):
        """Record an authentication attempt"""
        self.total_attempts += 1
        
        if result_type == "success":
            self.successful_authentications += 1
        elif result_type == "no_face_data":
            self.failed_no_face_data += 1
        elif result_type == "low_confidence":
            self.failed_low_confidence += 1
        elif result_type == "security_validation":
            self.failed_security_validation += 1
        elif result_type == "no_match":
            self.failed_no_match += 1
        
        # Log significant events
        if result_type != "success":
            logger.warning(f"Authentication failed: {result_type}")
    
    def get_metrics(self):
        """Get authentication metrics summary"""
        if self.total_attempts == 0:
            return {"message": "No authentication attempts yet"}
        
        success_rate = self.successful_authentications / self.total_attempts
        
        metrics = {
            "total_attempts": self.total_attempts,
            "successful_authentications": self.successful_authentications,
            "success_rate": round(success_rate, 4),
            "failure_breakdown": {
                "no_face_data": self.failed_no_face_data,
                "low_confidence": self.failed_low_confidence,
                "security_validation": self.failed_security_validation,
                "no_match": self.failed_no_match
            },
            "failure_rate": round(1 - success_rate, 4)
        }
        
        # Add warnings for low success rates
        if success_rate < 0.7 and self.total_attempts > 10:
            metrics["warnings"] = [
                f"Low authentication success rate: {success_rate:.2%}"
            ]
        
        return metrics
    
    def reset_metrics(self):
        """Reset all metrics (useful for testing or periodic resets)"""
        self.total_attempts = 0
        self.successful_authentications = 0
        self.failed_no_face_data = 0
        self.failed_low_confidence = 0
        self.failed_security_validation = 0
        self.failed_no_match = 0
        logger.info("Authentication metrics reset")