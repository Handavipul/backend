from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from prometheus_client import Counter, Histogram, Gauge
import time
import logging

# Prometheus metrics
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status_code']
)

REQUEST_DURATION = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint']
)

ACTIVE_REQUESTS = Gauge(
    'http_requests_active',
    'Active HTTP requests'
)

FACE_AUTH_ATTEMPTS = Counter(
    'face_auth_attempts_total',
    'Total face authentication attempts',
    ['status', 'user_id']
)

FACE_AUTH_CONFIDENCE = Histogram(
    'face_auth_confidence_score',
    'Face authentication confidence scores'
)

PAYMENT_TRANSACTIONS = Counter(
    'payment_transactions_total',
    'Total payment transactions',
    ['status', 'currency']
)

MULTI_ANGLE_CAPTURES = Counter(
    'multi_angle_captures_total',
    'Multi-angle face captures',
    ['angles_count', 'success']
)

class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip metrics endpoint to avoid recursion
        if request.url.path == "/metrics":
            return await call_next(request)
        
        start_time = time.time()
        ACTIVE_REQUESTS.inc()
        
        try:
            response = await call_next(request)
            
            # Record metrics
            duration = time.time() - start_time
            method = request.method
            endpoint = request.url.path
            status_code = response.status_code
            
            REQUEST_COUNT.labels(
                method=method,
                endpoint=endpoint,
                status_code=status_code
            ).inc()
            
            REQUEST_DURATION.labels(
                method=method,
                endpoint=endpoint
            ).observe(duration)
            
            return response
            
        except Exception as e:
            logging.error(f"Request processing error: {e}")
            raise
        finally:
            ACTIVE_REQUESTS.dec()

# Utility functions for custom metrics
class MetricsUtils:
    @staticmethod
    def record_face_auth_attempt(status: str, user_id: int, confidence: float = None):
        """Record face authentication attempt"""
        FACE_AUTH_ATTEMPTS.labels(status=status, user_id=str(user_id)).inc()
        if confidence is not None:
            FACE_AUTH_CONFIDENCE.observe(confidence)
    
    @staticmethod
    def record_payment_transaction(status: str, currency: str):
        """Record payment transaction"""
        PAYMENT_TRANSACTIONS.labels(status=status, currency=currency).inc()
    
    @staticmethod
    def record_multi_angle_capture(angles_count: int, success: bool):
        """Record multi-angle capture attempt"""
        MULTI_ANGLE_CAPTURES.labels(
            angles_count=str(angles_count),
            success=str(success).lower()
        ).inc()