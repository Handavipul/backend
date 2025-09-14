# mollie_controller.py - FastAPI controller for Mollie integration
from operator import and_
from fastapi import APIRouter, HTTPException, Request, Depends, BackgroundTasks, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List

from requests import Session
from backend.database import MollieCustomer, MollieMandate, Payment, PaymentStatus, RefundModel, User, get_db
from backend.routers.auth import get_current_user
import httpx
import json
import hmac
import hashlib
import os
from datetime import datetime, timezone
import uuid
import logging

# Database models (replace with your actual models)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()
security = HTTPBearer()

# Mollie API Configuration
MOLLIE_API_KEY = os.getenv("MOLLIE_API_KEY", "test_jmCkdTUcct3aEeuvCeuHJDeqS6NzAR")
MOLLIE_API_URL = "https://api.mollie.com/v2"
MOLLIE_WEBHOOK_SECRET = os.getenv("MOLLIE_WEBHOOK_SECRET", "")
BASE_URL = os.getenv("BASE_URL", "https://1e966c8c8417.ngrok-free.app")

# Pydantic Models
class MollieAmount(BaseModel):
    currency: str 
    value: str 

class MollieAddress(BaseModel):
    streetAndNumber: Optional[str] = None
    postalCode: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    organizationName: Optional[str] = None
    title: Optional[str] = None
    givenName: Optional[str] = None
    familyName: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None

class MolliePaymentRequest(BaseModel):
    amount: MollieAmount
    description: str = Field(..., min_length=1, max_length=255)
    redirectUrl: str
    webhookUrl: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    method: Optional[str] = None
    locale: Optional[str] = None
    sequenceType: Optional[str] = None
    customerId: Optional[str] = None
    mandateId: Optional[str] = None
    billingAddress: Optional[MollieAddress] = None
    shippingAddress: Optional[MollieAddress] = None
    consumerName: Optional[str] = None
    consumerAccount: Optional[str] = None
    issuer: Optional[str] = None

class MollieRefundRequest(BaseModel):
    amount: Optional[MollieAmount] = None
    description: Optional[str] = None

class MollieCustomerRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    locale: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class MollieMandateRequest(BaseModel):
    method: str
    consumerName: Optional[str] = None
    consumerAccount: Optional[str] = None
    consumerBic: Optional[str] = None
    signatureDate: Optional[str] = None
    mandateReference: Optional[str] = None

class MollieMethodsRequest(BaseModel):
    amount: Optional[MollieAmount] = None
    locale: Optional[str] = None
    billingCountry: Optional[str] = None

class WebhookValidationRequest(BaseModel):
    body: str
    signature: str

# Helper Functions
def generate_order_id() -> str:
    """Generate unique order ID"""
    return f"ORD-{uuid.uuid4().hex[:12].upper()}"

async def make_mollie_request(method: str, endpoint: str, data: Optional[Dict] = None) -> Dict:
    """Make authenticated request to Mollie API"""
    headers = {
        "Authorization": f"Bearer {MOLLIE_API_KEY}",
        "Content-Type": "application/json"
    }
    
    url = f"{MOLLIE_API_URL}{endpoint}"
    
    async with httpx.AsyncClient() as client:
        try:
            if method.upper() == "GET":
                response = await client.get(url, headers=headers)
            elif method.upper() == "POST":
                response = await client.post(url, headers=headers, json=data)
            elif method.upper() == "PATCH":
                response = await client.patch(url, headers=headers, json=data)
            elif method.upper() == "DELETE":
                response = await client.delete(url, headers=headers)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            return response.json()
            
        except httpx.HTTPStatusError as e:
            logger.error(f"Mollie API error: {e.response.status_code} - {e.response.text}")
            raise HTTPException(
                status_code=e.response.status_code,
                detail=f"Mollie API error: {e.response.text}"
            )
        except Exception as e:
            logger.error(f"Request error: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Request failed: {str(e)}")

def verify_webhook_signature(body: str, signature: str) -> bool:
    """Verify Mollie webhook signature"""
    if not MOLLIE_WEBHOOK_SECRET:
        logger.warning("Webhook secret not configured, skipping signature verification")
        return True
    
    expected_signature = hmac.new(
        MOLLIE_WEBHOOK_SECRET.encode(),
        body.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, expected_signature)

# API Endpoints

@router.get("/config")
async def get_mollie_config():
    """Get Mollie configuration"""
    try:
        print("Mollie Service Configuration:")
        profile_data = await make_mollie_request("GET", "/profiles/me")
        
        return {
            "profileId": profile_data.get("id"),
            "testMode": profile_data.get("mode") == "test",
            "supportedCurrencies": ["EUR", "USD", "GBP", "CHF", "DKK", "SEK", "NOK", "PLN", "CZK", "HUF"],
            "status": "initialized"
        }
    except Exception as e:
        logger.error(f"Config error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get Mollie configuration")

@router.post("/methods")
async def get_payment_methods(request: MollieMethodsRequest):
    """Get available payment methods"""
    try:
        params = {}
        if request.amount:
            params["amount[currency]"] = request.amount.currency
            params["amount[value]"] = request.amount.value
        if request.locale:
            params["locale"] = request.locale
        if request.billingCountry:
            params["billingCountry"] = request.billingCountry
        
        # Build query string
        query_params = "&".join([f"{k}={v}" for k, v in params.items()])
        endpoint = f"/methods?{query_params}" if query_params else "/methods"
        
        methods_data = await make_mollie_request("GET", endpoint)
        return methods_data
        
    except Exception as e:
        logger.error(f"Get methods error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get payment methods")

@router.post("/payments")
async def create_payment(
    request: MolliePaymentRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db_session = Depends(get_db)
):
    """Create a new payment"""
    try:
        print("Creating payment with data:", request)
        print("current user ", current_user)
        user: User = db_session.query(User).filter(User.email == current_user['email']).first()
        print("user from db", user.id)
        # Prepare payment data
        payment_data = {
            "amount": {
                "currency": request.amount.currency,
                "value": request.amount.value
            },
            "description": request.description,
            "redirectUrl": request.redirectUrl,
            "webhookUrl": request.webhookUrl or f"{BASE_URL}/mollie/webhook",
            "metadata": {
                **(request.metadata or {}),
                "orderId": generate_order_id(),
                "userId": str(user.id),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }

        print("vipul creating payment:")

        # Add optional fields
        if request.method:
            payment_data["method"] = request.method
        if request.locale:
            payment_data["locale"] = request.locale
        if request.sequenceType:
            payment_data["sequenceType"] = request.sequenceType
        if request.customerId:
            payment_data["customerId"] = request.customerId
        if request.mandateId:
            payment_data["mandateId"] = request.mandateId
        if request.billingAddress:
            payment_data["billingAddress"] = request.billingAddress.dict(exclude_none=True)
        if request.shippingAddress:
            payment_data["shippingAddress"] = request.shippingAddress.dict(exclude_none=True)
        if request.consumerName:
            payment_data["consumerName"] = request.consumerName
        if request.consumerAccount:
            payment_data["consumerAccount"] = request.consumerAccount
        if request.issuer:
            payment_data["issuer"] = request.issuer
        
        # Create payment with Mollie
        mollie_payment = await make_mollie_request("POST", "/payments", payment_data)
        
        print("Mollie payment created:", mollie_payment)
        # Save payment to database
        payment = Payment(
            mollie_payment_id=mollie_payment["id"],
            user_id=user.id,
            amount=float(request.amount.value),
            currency=request.amount.currency,
            description=request.description,
            method=mollie_payment.get("method"),
            status=PaymentStatus(mollie_payment["status"]),
            metadata=payment_data["metadata"],
            checkout_url=mollie_payment.get("_links", {}).get("checkout", {}).get("href"),
            created_at=datetime.fromisoformat(mollie_payment["createdAt"].replace("Z", "+00:00"))
        )
        
        db_session.add(payment)
        db_session.commit()
        
        return mollie_payment
        
    except Exception as e:
        logger.error(f"Create payment error: {str(e)}")
        db_session.rollback()
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to create payment: {str(e)}"
        )

@router.get("/payments/{payment_id}")
async def get_payment_status(
    payment_id: str,
    db_session = Depends(get_db)
):
    """Get payment status"""
    try:
        mollie_payment = await make_mollie_request("GET", f"/payments/{payment_id}")
        print("Mollie payment retrieved:", mollie_payment)
        # Update local database
        payment = db_session.query(Payment).filter(
            Payment.mollie_payment_id == payment_id
        ).first()
        
        if payment:
            payment.status = PaymentStatus(mollie_payment["status"])
            if mollie_payment.get("paidAt"):
                payment.paid_at = datetime.fromisoformat(
                    mollie_payment["paidAt"].replace("Z", "+00:00")
                )
            payment.details = mollie_payment.get("details")
            payment.updated_at = datetime.now(timezone.utc)
            
            db_session.commit()
        
        return mollie_payment
        
    except Exception as e:
        logger.error(f"Get payment error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get payment status")

@router.delete("/payments/{payment_id}")
async def cancel_payment(
    payment_id: str,
    current_user: User = Depends(get_current_user),
    db_session = Depends(get_db)
):
    """Cancel payment"""
    try:
        mollie_payment = await make_mollie_request("DELETE", f"/payments/{payment_id}")
        
        # Update local database
        payment = db_session.query(Payment).filter(
            Payment.mollie_payment_id == payment_id,
            Payment.user_id == current_user.id
        ).first()
        
        if payment:
            payment.status = PaymentStatus.CANCELED
            payment.updated_at = datetime.now(timezone.utc)
            db_session.commit()
        
        return mollie_payment
        
    except Exception as e:
        logger.error(f"Cancel payment error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to cancel payment")

@router.post("/payments/{payment_id}/refunds")
async def create_refund(
    payment_id: str,
    request: MollieRefundRequest,
    current_user: User = Depends(get_current_user),
    db_session = Depends(get_db)
):
    """Create refund"""
    try:
        refund_data = {}
        if request.amount:
            refund_data["amount"] = request.amount.dict()
        if request.description:
            refund_data["description"] = request.description
        
        refund = await make_mollie_request("POST", f"/payments/{payment_id}/refunds", refund_data)
        
        # Update payment in database
        payment = db_session.query(Payment).filter(
            Payment.mollie_payment_id == payment_id,
            Payment.user_id == current_user.id
        ).first()
        
        if payment:
            refund_model = RefundModel(
                mollie_refund_id=refund["id"],
                payment_id=payment.id,
                amount=float(refund["amount"]["value"]),
                currency=refund["amount"]["currency"],
                status=refund["status"],
                description=refund.get("description"),
                created_at=datetime.fromisoformat(refund["createdAt"].replace("Z", "+00:00"))
            )
            
            db_session.add(refund_model)
            db_session.commit()
        
        return refund
        
    except Exception as e:
        logger.error(f"Create refund error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create refund")

@router.post("/customers")
async def create_customer(
    request: MollieCustomerRequest,
    current_user: User = Depends(get_current_user),
    db_session = Depends(get_db)
):
    """Create customer"""
    try:
        customer_data = request.dict(exclude_none=True)
        customer = await make_mollie_request("POST", "/customers", customer_data)
        user: User = db_session.query(User).filter(User.email == current_user['email']).first()
         # Save to database
        db_customer = MollieCustomer(
            mollie_customer_id=customer["id"],
            user_id=user.id,
            name=customer.get("name"),
            email=customer.get("email"),
            metadata_payment=customer.get("metadata")
        )
        
        db_session.add(db_customer)
        db_session.commit()
        return customer
        
    except Exception as e:
        logger.error(f"Create customer error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create customer")

@router.get("/customers/{customer_id}")
async def get_customer(customer_id: str):
    """Get customer details"""
    try:
        customer = await make_mollie_request("GET", f"/customers/{customer_id}")
        return customer
        
    except Exception as e:
        logger.error(f"Get customer error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get customer")

@router.patch("/customers/{customer_id}")
async def update_customer(
    customer_id: str,
    request: MollieCustomerRequest
):
    """Update customer"""
    try:
        customer_data = request.dict(exclude_none=True)
        customer = await make_mollie_request("PATCH", f"/customers/{customer_id}", customer_data)
        return customer
        
    except Exception as e:
        logger.error(f"Update customer error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update customer")

@router.delete("/customers/{customer_id}")
async def delete_customer(customer_id: str):
    """Delete customer"""
    try:
        await make_mollie_request("DELETE", f"/customers/{customer_id}")
        return {"message": "Customer deleted successfully"}
        
    except Exception as e:
        logger.error(f"Delete customer error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete customer")

@router.get("/customers/{customer_id}/mandates")
async def get_mandate(customer_id: str):
    """Get mandate details"""
    try:
        mandate = await make_mollie_request("GET", f"/customers/{customer_id}/mandates/")
        print("Mandates retrieved:", mandate)
        return mandate
        
    except Exception as e:
        logger.error(f"Get mandate error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get mandate")

@router.post("/customers/{customer_id}/mandates")
async def create_mandate(
    customer_id: str,
    request: MollieMandateRequest
):
    """Create mandate for recurring payments"""
    try:
        print("Creating mandate...")
        mandate_data = request.dict(exclude_none=True)
        mandate = await make_mollie_request("POST", f"/customers/{customer_id}/mandates", mandate_data)
        return mandate
        
    except Exception as e:
        logger.error(f"Create mandate error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create mandate")

@router.get("/customers/{customer_id}/mandates/{mandate_id}")
async def get_mandate(customer_id: str, mandate_id: str):
    """Get mandate details"""
    try:
        mandate = await make_mollie_request("GET", f"/customers/{customer_id}/mandates/{mandate_id}")
        return mandate
        
    except Exception as e:
        logger.error(f"Get mandate error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get mandate")

@router.delete("/customers/{customer_id}/mandates/{mandate_id}")
async def revoke_mandate(customer_id: str, mandate_id: str):
    """Revoke mandate"""
    try:
        await make_mollie_request("DELETE", f"/customers/{customer_id}/mandates/{mandate_id}")
        return {"message": "Mandate revoked successfully"}
        
    except Exception as e:
        logger.error(f"Revoke mandate error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to revoke mandate")

@router.post("/webhook")
async def handle_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_mollie_signature: Optional[str] = Header(None, alias="X-Mollie-Signature"),
    db_session = Depends(get_db)
):
    """Handle Mollie webhooks"""
    try:
        body = await request.body()
        body_str = body.decode()
        
        # Verify webhook signature in production
        if os.getenv("ENVIRONMENT") == "production" and x_mollie_signature:
            if not verify_webhook_signature(body_str, x_mollie_signature):
                raise HTTPException(status_code=401, detail="Invalid signature")
        
        # Parse webhook payload
        try:
            payload = json.loads(body_str)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")
        
        payment_id = payload.get("id")
        if not payment_id:
            raise HTTPException(status_code=400, detail="Missing payment ID")
        
        # Process webhook in background
        background_tasks.add_task(process_webhook, payment_id, db_session)
        
        return {"status": "accepted"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Webhook error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to process webhook")

async def process_webhook(payment_id: str, db_session):
    """Process webhook in background"""
    try:
        # Get payment from Mollie
        mollie_payment = await make_mollie_request("GET", f"/payments/{payment_id}")
        
        # Update payment in database
        payment = db_session.query(Payment).filter(
            Payment.mollie_payment_id == payment_id
        ).first()
        
        if not payment:
            logger.error(f"Payment not found in database: {payment_id}")
            return
        
        # Update payment status
        old_status = payment.status
        payment.status = PaymentStatus(mollie_payment["status"])
        payment.details = mollie_payment.get("details")
        payment.updated_at = datetime.now(timezone.utc)
        
        if mollie_payment.get("paidAt"):
            payment.paid_at = datetime.fromisoformat(
                mollie_payment["paidAt"].replace("Z", "+00:00")
            )
        
        db_session.commit()
        
        # Handle status changes
        if old_status != payment.status:
            await handle_payment_status_change(payment, old_status, payment.status)
        
        logger.info(f"Webhook processed for payment {payment_id}, status: {payment.status}")
        
    except Exception as e:
        logger.error(f"Webhook processing error for payment {payment_id}: {str(e)}")
        db_session.rollback()

async def handle_payment_status_change(payment: Payment, old_status: PaymentStatus, new_status: PaymentStatus):
    """Handle payment status changes"""
    try:
        if new_status == PaymentStatus.PAID:
            logger.info(f"Payment {payment.mollie_payment_id} completed successfully")
            # Add success handling logic here (e.g., send confirmation email, update order status)
            
        elif new_status == PaymentStatus.FAILED:
            logger.info(f"Payment {payment.mollie_payment_id} failed")
            # Add failure handling logic here
            
        elif new_status == PaymentStatus.CANCELED:
            logger.info(f"Payment {payment.mollie_payment_id} was canceled")
            # Add cancellation handling logic here
            
        elif new_status == PaymentStatus.EXPIRED:
            logger.info(f"Payment {payment.mollie_payment_id} expired")
            # Add expiration handling logic here
            
    except Exception as e:
        logger.error(f"Error handling status change for payment {payment.mollie_payment_id}: {str(e)}")

@router.post("/webhook/validate")
async def validate_webhook_signature(request: WebhookValidationRequest):
    """Validate webhook signature"""
    try:
        is_valid = verify_webhook_signature(request.body, request.signature)
        return {"valid": is_valid}
        
    except Exception as e:
        logger.error(f"Signature validation error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to validate signature")

@router.get("/payments/{payment_id}/link")
async def get_payment_link(payment_id: str):
    """Get payment checkout link"""
    try:
        mollie_payment = await make_mollie_request("GET", f"/payments/{payment_id}")
        checkout_url = mollie_payment.get("_links", {}).get("checkout", {}).get("href", "")
        
        return {"checkoutUrl": checkout_url}
        
    except Exception as e:
        logger.error(f"Get payment link error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get payment link")


@router.get("/customers/by-user/{user_id}")
async def get_customer_by_user(
    user_id: int,
    db_session = Depends(get_db)
):
    """Get Mollie customer by user ID"""
    try:
        # Get customer from database
        mollie_customer = db_session.query(MollieCustomer).filter(
            MollieCustomer.user_id == user_id
        ).first()
        
        if not mollie_customer:
            raise HTTPException(status_code=404, detail="Customer not found")
            
        # Get customer from Mollie API to ensure it's still valid
        customer_data = await make_mollie_request("GET", f"/customers/{mollie_customer.mollie_customer_id}")
        
        return {
            "id": mollie_customer.mollie_customer_id,
            "database_id": mollie_customer.id,
            "user_id": mollie_customer.user_id,
            "name": customer_data.get("name"),
            "email": customer_data.get("email"),
            "mollie_data": customer_data
        }
        
    except Exception as e:
        logger.error(f"Get customer by user error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get customer")

@router.post("/customers/get-or-create")
async def get_or_create_customer(
    request: MollieCustomerRequest,
    current_user: User = Depends(get_current_user),
    db_session = Depends(get_db)
):
    """Get existing customer or create new one"""
    try:
        user: User = db_session.query(User).filter(User.email == current_user['email']).first()
        
        # Check if customer already exists in database
        existing_customer = db_session.query(MollieCustomer).filter(
            MollieCustomer.user_id == user.id
        ).first()
        
        if existing_customer:
            # Verify customer still exists in Mollie
            try:
                mollie_customer = await make_mollie_request("GET", f"/customers/{existing_customer.mollie_customer_id}")
                return {
                    "id": existing_customer.mollie_customer_id,
                    "database_id": existing_customer.id,
                    "user_id": existing_customer.user_id,
                    **mollie_customer
                }
            except HTTPException as e:
                if e.status_code == 404:
                    # Customer deleted from Mollie, remove from database
                    db_session.delete(existing_customer)
                    db_session.commit()
                else:
                    raise
        
        # Create new customer
        customer_data = {
            "name": request.name or user.name or user.email.split('@')[0],
            "email": request.email or user.email,
            "metadata": {
                "user_id": str(user.id),
                "phone": request.metadata.get("phone") if request.metadata else None,
                "created_from": "payment_component"
            }
        }
        
        mollie_customer = await make_mollie_request("POST", "/customers", customer_data)
        
        # Save to database
        db_customer = MollieCustomer(
            mollie_customer_id=mollie_customer["id"],
            user_id=user.id,
            name=mollie_customer.get("name"),
            email=mollie_customer.get("email"),
            metadata_payment=mollie_customer.get("metadata")
        )
        
        # db_session.add(db_customer)
        # db_session.commit()
        
        return {
            "id": mollie_customer["id"],
            "database_id": db_customer.id,
            "user_id": user.id,
            **mollie_customer
        }
        
    except Exception as e:
        logger.error(f"Get or create customer error: {str(e)}")
        db_session.rollback()
        raise HTTPException(status_code=500, detail="Failed to get or create customer")

@router.get("/customers/{customer_id}/mandates")
async def get_customer_mandates(
    customer_id: str,
    db_session = Depends(get_db)
):
    """Get customer mandates"""
    try:
        # Get mandates from Mollie
        mandates_response = await make_mollie_request("GET", f"/customers/{customer_id}/mandates")
        print("mandates_response:", mandates_response)
        # Update local database with current mandates
        mollie_customer = db_session.query(MollieCustomer).filter(
            MollieCustomer.mollie_customer_id == customer_id
        ).first()
        print("mollie----customer:", mollie_customer)
        if mollie_customer and mandates_response.get("_embedded", {}).get("mandates"):
            for mandate_data in mandates_response["_embedded"]["mandates"]:
                # Check if mandate exists in database
                existing_mandate = db_session.query(MollieMandate).filter(
                    MollieMandate.mollie_mandate_id == mandate_data["id"]
                ).first()
                
                if existing_mandate:
                    # Update existing mandate
                    existing_mandate.status = mandate_data["status"]
                    existing_mandate.details = mandate_data.get("details")
                    existing_mandate.updated_at = datetime.now(timezone.utc)
                else:
                    # Create new mandate record
                    new_mandate = MollieMandate(
                        mollie_mandate_id=mandate_data["id"],
                        customer_id=mollie_customer.id,
                        method=mandate_data["method"],
                        status=mandate_data["status"],
                        mandate_reference=mandate_data.get("mandateReference"),
                        signature_date=datetime.fromisoformat(mandate_data["signatureDate"].replace("Z", "+00:00")) if mandate_data.get("signatureDate") else None,
                        consumer_name=mandate_data.get("details", {}).get("consumerName"),
                        consumer_account=mandate_data.get("details", {}).get("consumerAccount"),
                        consumer_bic=mandate_data.get("details", {}).get("consumerBic"),
                        details=mandate_data.get("details")
                    )
                    db_session.add(new_mandate)
            
            db_session.commit()
        
        return mandates_response
        
    except Exception as e:
        logger.error(f"Get customer mandates error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get customer mandates")

@router.post("/payments/recurring")
async def create_recurring_payment(
    request: dict,
    current_user: User = Depends(get_current_user),
    db_session = Depends(get_db)
):
    """Create recurring payment using existing mandate"""
    try:
        # Get user from DB
        user: User = (
            db_session.query(User)
            .filter(User.email == current_user["email"])
            .first()
        )

        # Extract request params
        customer_id = request.get("customerId")
        mandate_id = request.get("mandateId")

        if not customer_id or not mandate_id:
            raise HTTPException(
                status_code=400,
                detail="Customer ID and Mandate ID are required",
            )

        # Verify customer belongs to this user
        mollie_customer = (
            db_session.query(MollieCustomer)
            .filter(
                MollieCustomer.mollie_customer_id == customer_id,
                MollieCustomer.user_id == user.id,
            )
            .first()
        )

        if not mollie_customer:
            raise HTTPException(
                status_code=404,
                detail="Customer not found or access denied",
            )

        # Verify mandate is valid
        mandate = await make_mollie_request("GET", f"/customers/{customer_id}/mandates")
        print("mandate---", mandate)
        if not mandate:
            raise HTTPException(
                status_code=404, detail="Valid mandate not found"
            )

        # Prepare payment data for Mollie
        payment_data = {
            "amount": {
                "currency": request.get("currency", "EUR"),
                "value": f"{request['amount']:.2f}",
            },
            "description": request.get("description", "Recurring payment"),
            "customerId": customer_id,
            "mandateId": mandate_id,
            "sequenceType": "recurring",
            "webhookUrl": f"{BASE_URL}/mollie/webhook",
            "metadata": {
                **(request.get("metadata", {})),
                "userId": str(user.id),
                "recurringPayment": True,
                "mandateId": mandate_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        }

        # Create payment with Mollie
        mollie_payment = await make_mollie_request(
            "POST", "/payments", payment_data
        )

        # Save payment to database
        payment = Payment(
            mollie_payment_id=mollie_payment["id"],
            user_id=user.id,
            amount=float(request["amount"]),
            currency=request.get("currency", "EUR"),
            description=request.get("description", "Recurring payment"),
            method=mollie_payment.get("method"),
            status=PaymentStatus(mollie_payment["status"]),
            metadata=payment_data["metadata"],
            customer_id=customer_id,
            mandate_id=mandate_id,
            sequence_type="recurring",
            created_at=datetime.fromisoformat(
                mollie_payment["createdAt"].replace("Z", "+00:00")
            ),
        )

        db_session.add(payment)
        db_session.commit()

        return mollie_payment

    except Exception as e:
        logger.error(f"Create recurring payment error: {str(e)}")
        db_session.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create recurring payment: {str(e)}",
        )

# FIXED: Update the existing create_payment endpoint to handle stored methods
@router.post("/payments")
async def create_payment(
    request: MolliePaymentRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db_session = Depends(get_db)
):
    """Create a new payment (updated to handle stored methods)"""
    try:
        user: User = db_session.query(User).filter(User.email == current_user['email']).first()
        
        # Prepare payment data
        payment_data = {
            "amount": {
                "currency": request.amount.currency,
                "value": request.amount.value
            },
            "description": request.description,
            "redirectUrl": request.redirectUrl,
            "webhookUrl": request.webhookUrl or f"{BASE_URL}/mollie/webhook",
            "metadata": {
                **(request.metadata or {}),
                "orderId": generate_order_id(),
                "userId": str(user.id),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }

        # Add optional fields
        if request.method:
            payment_data["method"] = request.method
        if request.locale:
            payment_data["locale"] = request.locale
        if request.sequenceType:
            payment_data["sequenceType"] = request.sequenceType
        if request.customerId:
            payment_data["customerId"] = request.customerId
        if request.mandateId:
            payment_data["mandateId"] = request.mandateId
            
        # Create payment with Mollie
        mollie_payment = await make_mollie_request("POST", "/payments", payment_data)
        
        # Save payment to database
        payment = Payment(
            mollie_payment_id=mollie_payment["id"],
            user_id=user.id,
            amount=float(request.amount.value),
            currency=request.amount.currency,
            description=request.description,
            method=mollie_payment.get("method"),
            status=PaymentStatus(mollie_payment["status"]),
            metadata=payment_data["metadata"],
            checkout_url=mollie_payment.get("_links", {}).get("checkout", {}).get("href"),
            customer_id=request.customerId,
            mandate_id=request.mandateId,
            sequence_type=request.sequenceType,
            created_at=datetime.fromisoformat(mollie_payment["createdAt"].replace("Z", "+00:00"))
        )
        
        db_session.add(payment)
        db_session.commit()
        
        return mollie_payment
        
    except Exception as e:
        logger.error(f"Create payment error: {str(e)}")
        db_session.rollback()
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to create payment: {str(e)}"
        )

# Add this helper function to get user's Mollie customer
async def get_user_mollie_customer(user_id: int, db_session: Session):
    """Get user's Mollie customer, create if doesn't exist"""
    mollie_customer = db_session.query(MollieCustomer).filter(
        MollieCustomer.user_id == user_id
    ).first()
    
    if mollie_customer:
        # Verify customer still exists in Mollie
        try:
            customer_data = await make_mollie_request("GET", f"/customers/{mollie_customer.mollie_customer_id}")
            return mollie_customer, customer_data
        except HTTPException as e:
            if e.status_code == 404:
                # Customer was deleted, remove from database
                db_session.delete(mollie_customer)
                db_session.commit()
                return None, None
            raise
    
    return None, None

# Health check endpoint
@router.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Test Mollie API connectivity
        await make_mollie_request("GET", "/profiles/me")
        
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mollie_api": "connected"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e)
        }