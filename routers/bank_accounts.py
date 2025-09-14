# # routers/bank_accounts.py
# from fastapi import APIRouter, Depends, HTTPException, status
# from sqlalchemy.orm import Session
# from sqlalchemy.exc import IntegrityError
# from typing import List
# import hashlib
# import secrets
# from decimal import Decimal

# from database import get_db
# from database import User
# from models.bank_account import BankAccount, AccountType, VerificationStatus, BankAccountVerification
# from schemas.bank_account import (
#     BankAccountCreate, BankAccountUpdate, BankAccountResponse, BankAccountList,
#     BankAccountValidation, BankAccountValidationResponse, MicroDepositVerification,
#     VerificationResponse, MicroDepositInitiationResponse, BalanceResponse
# )
# from services.auth import get_current_user
# from services.encryption import encrypt_sensitive_data, decrypt_sensitive_data
# from services.bank_validation import validate_bank_details, get_bank_info
# from services.micro_deposits import initiate_micro_deposits, verify_micro_deposits

# router = APIRouter(prefix="/api/v1/bank-accounts", tags=["bank-accounts"])

# @router.get("/", response_model=BankAccountList)
# async def get_bank_accounts(
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Get all bank accounts for the current user"""
#     try:
#         accounts = db.query(BankAccount).filter(
#             BankAccount.user_id == current_user.id
#         ).order_by(BankAccount.is_primary.desc(), BankAccount.created_at.desc()).all()
        
#         account_responses = [
#             BankAccountResponse.from_orm_with_masked_account(account) 
#             for account in accounts
#         ]
        
#         has_primary = any(account.is_primary for account in accounts)
        
#         return BankAccountList(
#             accounts=account_responses,
#             total=len(accounts),
#             has_primary=has_primary
#         )
    
#     except Exception as e:
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=f"Failed to retrieve bank accounts: {str(e)}"
#         )

# @router.get("/{account_id}", response_model=BankAccountResponse)
# async def get_bank_account(
#     account_id: str,
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Get a specific bank account"""
#     account = db.query(BankAccount).filter(
#         BankAccount.id == account_id,
#         BankAccount.user_id == current_user.id
#     ).first()
    
#     if not account:
#         raise HTTPException(
#             status_code=status.HTTP_404_NOT_FOUND,
#             detail="Bank account not found"
#         )
    
#     return BankAccountResponse.from_orm_with_masked_account(account)

# @router.post("/", response_model=BankAccountResponse, status_code=status.HTTP_201_CREATED)
# async def create_bank_account(
#     account_data: BankAccountCreate,
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Add a new bank account"""
#     try:
#         # Create hash of account number for duplicate detection
#         account_hash = hashlib.sha256(
#             f"{account_data.account_number}:{account_data.routing_number}".encode()
#         ).hexdigest()
        
#         # Check if account already exists
#         existing_account = db.query(BankAccount).filter(
#             BankAccount.user_id == current_user.id,
#             BankAccount.account_number_hash == account_hash
#         ).first()
        
#         if existing_account:
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="This bank account is already added to your profile"
#             )
        
#         # If this is set as primary, remove primary flag from other accounts
#         if account_data.is_primary:
#             db.query(BankAccount).filter(
#                 BankAccount.user_id == current_user.id,
#                 BankAccount.is_primary == True
#             ).update({"is_primary": False})
        
#         # Encrypt sensitive data
#         encrypted_account_number = encrypt_sensitive_data(account_data.account_number)
        
#         # Create new bank account
#         new_account = BankAccount(
#             user_id=current_user.id,
#             account_name=account_data.account_name,
#             account_number=encrypted_account_number,
#             account_number_hash=account_hash,
#             routing_number=account_data.routing_number,
#             bank_name=account_data.bank_name,
#             account_type=account_data.account_type,
#             is_primary=account_data.is_primary
#         )
        
#         db.add(new_account)
#         db.commit()
#         db.refresh(new_account)
        
#         # Store decrypted account number temporarily for masking
#         new_account.account_number = account_data.account_number
        
#         return BankAccountResponse.from_orm_with_masked_account(new_account)
    
#     except IntegrityError:
#         db.rollback()
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Bank account already exists"
#         )
#     except Exception as e:
#         db.rollback()
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=f"Failed to add bank account: {str(e)}"
#         )

# @router.put("/{account_id}", response_model=BankAccountResponse)
# async def update_bank_account(
#     account_id: str,
#     account_data: BankAccountUpdate,
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Update a bank account"""
#     account = db.query(BankAccount).filter(
#         BankAccount.id == account_id,
#         BankAccount.user_id == current_user.id
#     ).first()
    
#     if not account:
#         raise HTTPException(
#             status_code=status.HTTP_404_NOT_FOUND,
#             detail="Bank account not found"
#         )
    
#     try:
#         # If setting as primary, remove primary flag from other accounts
#         if account_data.is_primary:
#             db.query(BankAccount).filter(
#                 BankAccount.user_id == current_user.id,
#                 BankAccount.id != account_id,
#                 BankAccount.is_primary == True
#             ).update({"is_primary": False})
        
#         # Update fields
#         update_data = account_data.dict(exclude_unset=True)
#         for field, value in update_data.items():
#             setattr(account, field, value)
        
#         db.commit()
#         db.refresh(account)
        
#         # Decrypt account number for response
#         decrypted_account = decrypt_sensitive_data(account.account_number)
#         account.account_number = decrypted_account
        
#         return BankAccountResponse.from_orm_with_masked_account(account)
    
#     except Exception as e:
#         db.rollback()
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=f"Failed to update bank account: {str(e)}"
#         )

# @router.delete("/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
# async def delete_bank_account(
#     account_id: str,
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Delete a bank account"""
#     account = db.query(BankAccount).filter(
#         BankAccount.id == account_id,
#         BankAccount.user_id == current_user.id
#     ).first()
    
#     if not account:
#         raise HTTPException(
#             status_code=status.HTTP_404_NOT_FOUND,
#             detail="Bank account not found"
#         )
    
#     # Check if this is the primary account and there are other accounts
#     if account.is_primary:
#         other_accounts = db.query(BankAccount).filter(
#             BankAccount.user_id == current_user.id,
#             BankAccount.id != account_id
#         ).count()
        
#         if other_accounts > 0:
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Cannot delete primary bank account. Please set another account as primary first."
#             )
    
#     try:
#         db.delete(account)
#         db.commit()
#     except Exception as e:
#         db.rollback()
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=f"Failed to delete bank account: {str(e)}"
#         )

# @router.patch("/{account_id}/set-primary", response_model=BankAccountResponse)
# async def set_primary_bank_account(
#     account_id: str,
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Set a bank account as primary"""
#     account = db.query(BankAccount).filter(
#         BankAccount.id == account_id,
#         BankAccount.user_id == current_user.id
#     ).first()
    
#     if not account:
#         raise HTTPException(
#             status_code=status.HTTP_404_NOT_FOUND,
#             detail="Bank account not found"
#         )
    
#     try:
#         # Remove primary flag from all other accounts
#         db.query(BankAccount).filter(
#             BankAccount.user_id == current_user.id,
#             BankAccount.is_primary == True
#         ).update({"is_primary": False})
        
#         # Set this account as primary
#         account.is_primary = True
#         db.commit()
#         db.refresh(account)
        
#         # Decrypt for response
#         decrypted_account = decrypt_sensitive_data(account.account_number)
#         account.account_number = decrypted_account
        
#         return BankAccountResponse.from_orm_with_masked_account(account)
    
#     except Exception as e:
#         db.rollback()
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=f"Failed to set primary account: {str(e)}"
#         )

# @router.post("/validate", response_model=BankAccountValidationResponse)
# async def validate_bank_account(
#     validation_data: BankAccountValidation,
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Validate bank account details"""
#     try:
#         # Validate routing number and get bank info
#         bank_info = get_bank_info(validation_data.routing_number)
        
#         if not bank_info:
#             return BankAccountValidationResponse(
#                 valid=False,
#                 errors=["Invalid routing number or bank not found"]
#             )
        
#         # Additional validation logic can be added here
#         validation_result = validate_bank_details(
#             validation_data.routing_number, 
#             validation_data.account_number
#         )
        
#         if validation_result["valid"]:
#             return BankAccountValidationResponse(
#                 valid=True,
#                 bank_name=bank_info.get("bank_name"),
#                 account_type=validation_result.get("account_type")
#             )
#         else:
#             return BankAccountValidationResponse(
#                 valid=False,
#                 errors=validation_result.get("errors", ["Validation failed"])
#             )
    
#     except Exception as e:
#         return BankAccountValidationResponse(
#             valid=False,
#             errors=[f"Validation error: {str(e)}"]
#         )

# @router.post("/{account_id}/initiate-verification", response_model=MicroDepositInitiationResponse)
# async def initiate_account_verification(
#     account_id: str,
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Initiate micro-deposit verification for a bank account"""
#     account = db.query(BankAccount).filter(
#         BankAccount.id == account_id,
#         BankAccount.user_id == current_user.id
#     ).first()
    
#     if not account:
#         raise HTTPException(
#             status_code=status.HTTP_404_NOT_FOUND,
#             detail="Bank account not found"
#         )
    
#     if account.is_verified:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Bank account is already verified"
#         )
    
#     try:
#         # Check if there's an existing pending verification
#         existing_verification = db.query(BankAccountVerification).filter(
#             BankAccountVerification.bank_account_id == account_id,
#             BankAccountVerification.status == VerificationStatus.PENDING
#         ).first()
        
#         if existing_verification:
#             # Check if it's still valid (not expired)
#             from datetime import datetime, timedelta
#             if existing_verification.expires_at and existing_verification.expires_at > datetime.utcnow():
#                 raise HTTPException(
#                     status_code=status.HTTP_400_BAD_REQUEST,
#                     detail="Verification already in progress. Please wait for micro-deposits to arrive."
#                 )
        
#         # Generate micro-deposit amounts (between $0.01 and $0.99)
#         amount1 = Decimal(secrets.randbelow(99) + 1) / 100
#         amount2 = Decimal(secrets.randbelow(99) + 1) / 100
        
#         # Ensure the amounts are different
#         while amount2 == amount1:
#             amount2 = Decimal(secrets.randbelow(99) + 1) / 100
        
#         # Create verification record
#         verification = BankAccountVerification(
#             bank_account_id=account_id,
#             micro_deposit_1=amount1,
#             micro_deposit_2=amount2,
#             expires_at=datetime.utcnow() + timedelta(days=2),  # 2 days to verify
#             status=VerificationStatus.PENDING
#         )
        
#         db.add(verification)
        
#         # Update account verification status
#         account.verification_status = VerificationStatus.PENDING
#         account.verification_attempts = 0
        
#         db.commit()
#         db.refresh(verification)
        
#         # Initiate actual micro-deposits (this would integrate with your payment processor)
#         decrypted_account = decrypt_sensitive_data(account.account_number)
#         result = await initiate_micro_deposits(
#             routing_number=account.routing_number,
#             account_number=decrypted_account,
#             amount1=amount1,
#             amount2=amount2
#         )
        
#         if not result.get("success"):
#             # Rollback if micro-deposit initiation fails
#             db.rollback()
#             raise HTTPException(
#                 status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#                 detail="Failed to initiate micro-deposits"
#             )
        
#         return MicroDepositInitiationResponse(
#             message="Micro-deposits initiated. Please check your account in 1-2 business days.",
#             verification_id=str(verification.id),
#             expires_at=verification.expires_at
#         )
    
#     except Exception as e:
#         db.rollback()
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=f"Failed to initiate verification: {str(e)}"
#         )

# @router.post("/{account_id}/verify", response_model=VerificationResponse)
# async def verify_bank_account(
#     account_id: str,
#     verification_data: MicroDepositVerification,
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Verify bank account with micro-deposit amounts"""
#     account = db.query(BankAccount).filter(
#         BankAccount.id == account_id,
#         BankAccount.user_id == current_user.id
#     ).first()
    
#     if not account:
#         raise HTTPException(
#             status_code=status.HTTP_404_NOT_FOUND,
#             detail="Bank account not found"
#         )
    
#     if account.is_verified:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Bank account is already verified"
#         )
    
#     # Get active verification
#     verification = db.query(BankAccountVerification).filter(
#         BankAccountVerification.bank_account_id == account_id,
#         BankAccountVerification.status == VerificationStatus.PENDING
#     ).order_by(BankAccountVerification.initiated_at.desc()).first()
    
#     if not verification:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="No pending verification found. Please initiate verification first."
#         )
    
#     # Check if verification has expired
#     from datetime import datetime
#     if verification.expires_at and verification.expires_at < datetime.utcnow():
#         verification.status = VerificationStatus.FAILED
#         account.verification_status = VerificationStatus.FAILED
#         db.commit()
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Verification has expired. Please initiate a new verification."
#         )
    
#     # Check attempt limits
#     if verification.attempts_count >= verification.max_attempts:
#         verification.status = VerificationStatus.FAILED
#         account.verification_status = VerificationStatus.FAILED
#         db.commit()
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Maximum verification attempts exceeded. Please initiate a new verification."
#         )
    
#     try:
#         # Increment attempt count
#         verification.attempts_count += 1
        
#         # Check if amounts match (in any order)
#         provided_amounts = set(verification_data.amounts)
#         correct_amounts = {verification.micro_deposit_1, verification.micro_deposit_2}
        
#         if provided_amounts == correct_amounts:
#             # Verification successful
#             verification.status = VerificationStatus.VERIFIED
#             verification.verified_at = datetime.utcnow()
            
#             account.is_verified = True
#             account.verification_status = VerificationStatus.VERIFIED
            
#             db.commit()
            
#             return VerificationResponse(
#                 verified=True,
#                 message="Bank account verified successfully!",
#                 attempts_remaining=0
#             )
#         else:
#             # Verification failed
#             attempts_remaining = verification.max_attempts - verification.attempts_count
            
#             if attempts_remaining <= 0:
#                 verification.status = VerificationStatus.FAILED
#                 account.verification_status = VerificationStatus.FAILED
            
#             db.commit()
            
#             return VerificationResponse(
#                 verified=False,
#                 message=f"Incorrect amounts. {attempts_remaining} attempts remaining.",
#                 attempts_remaining=attempts_remaining
#             )
    
#     except Exception as e:
#         db.rollback()
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=f"Verification failed: {str(e)}"
#         )

# @router.get("/{account_id}/balance", response_model=BalanceResponse)
# async def get_account_balance(
#     account_id: str,
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Get account balance (mock implementation)"""
#     account = db.query(BankAccount).filter(
#         BankAccount.id == account_id,
#         BankAccount.user_id == current_user.id
#     ).first()
    
#     if not account:
#         raise HTTPException(
#             status_code=status.HTTP_404_NOT_FOUND,
#             detail="Bank account not found"
#         )
    
#     # In a real implementation, this would connect to your bank or use Plaid/similar service
#     # For now, return the stored balance or a mock balance
#     balance = account.balance or Decimal('0.00')
    
#     return BalanceResponse(
#         balance=balance,
#         last_updated=account.last_balance_check or account.updated_at
#     )