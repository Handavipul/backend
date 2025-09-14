from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
import time
import logging
from collections import defaultdict, deque
from backend.config import settings

class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.rate_limiter = defaultdict(lambda: deque())
        self.blocked_ips = set()
        self.max_requests_per_minute = 60
        self.max_requests_per_hour = 1000
        
    async def dispatch(self, request: Request, call_next):
        client_ip = self._get_client_ip(request)
        
        # Check if IP is blocked
        if client_ip in self.blocked_ips:
            return JSONResponse(
                status_code=429,
                content={"error": "IP blocked due to suspicious activity"}
            )
        
        # Rate limiting
        if not self._check_rate_limit(client_ip):
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded"}
            )
        
        # Security headers
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
    
    def _check_rate_limit(self, client_ip: str) -> bool:
        """Check if client IP is within rate limits"""
        now = time.time()
        minute_ago = now - 60
        hour_ago = now - 3600
        
        # Clean old entries
        while self.rate_limiter[client_ip] and self.rate_limiter[client_ip][0] < hour_ago:
            self.rate_limiter[client_ip].popleft()
        
        # Count recent requests
        recent_requests = len([t for t in self.rate_limiter[client_ip] if t > minute_ago])
        total_requests = len(self.rate_limiter[client_ip])
        
        # Check limits
        if recent_requests >= self.max_requests_per_minute or total_requests >= self.max_requests_per_hour:
            self.blocked_ips.add(client_ip)
            logging.warning(f"Rate limit exceeded for IP: {client_ip}")
            return False
        
        # Add current request
        self.rate_limiter[client_ip].append(now)
        return True