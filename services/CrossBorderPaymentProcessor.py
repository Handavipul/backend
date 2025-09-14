import logging
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import aiohttp
import json
import asyncio
from enum import Enum
from dataclasses import dataclass
import hashlib
import hmac
from decimal import Decimal, ROUND_HALF_UP
import re
from datetime import datetime, timedelta
import uuid

class PaymentMethod(Enum):
    CARD = "card"
    BANK_TRANSFER = "bank_transfer"
    SWIFT = "swift"
    SEPA = "sepa"
    ACH = "ach"
    FASTER_PAYMENTS = "faster_payments"
    UPI = "upi"
    CRYPTO = "crypto"

class PaymentStatus(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REQUIRES_VERIFICATION = "requires_verification"

@dataclass
class CurrencyRate:
    from_currency: str
    to_currency: str
    rate: Decimal
    timestamp: datetime
    source: str

@dataclass
class CountryRegulation:
    country_code: str
    max_transaction_limit: Decimal
    requires_kyc: bool
    requires_license: bool
    prohibited_countries: List[str]
    restricted_categories: List[str]

class CrossBorderPaymentProcessor:
    def __init__(self):
        """Initialize cross-border payment processor with own gateway"""
        self.gateway_id = "CBP_GATEWAY_001"
        self.processing_fee_percentage = Decimal('0.025')  # 2.5% processing fee
        self.fx_margin = Decimal('0.015')  # 1.5% FX margin
        self.timeout = 30
        
        # Internal routing configuration
        self.routing_config = {
            'USD': {'primary': 'federal_reserve', 'backup': 'correspondent_bank'},
            'EUR': {'primary': 'ecb_target2', 'backup': 'correspondent_bank'},
            'GBP': {'primary': 'faster_payments', 'backup': 'correspondent_bank'},
            'INR': {'primary': 'rbi_rtgs', 'backup': 'correspondent_bank'},
            'JPY': {'primary': 'boj_rtgs', 'backup': 'correspondent_bank'},
            'CAD': {'primary': 'lynx', 'backup': 'correspondent_bank'},
            'AUD': {'primary': 'rba_rits', 'backup': 'correspondent_bank'},
            'CHF': {'primary': 'sic', 'backup': 'correspondent_bank'},
            'CNY': {'primary': 'cips', 'backup': 'correspondent_bank'},
            'SGD': {'primary': 'meps_plus', 'backup': 'correspondent_bank'}
        }
        
        # Correspondent bank network
        self.correspondent_banks = {
            'USD': {'bank': 'JP Morgan Chase', 'swift': 'CHASUS33', 'account': 'USD001'},
            'EUR': {'bank': 'Deutsche Bank AG', 'swift': 'DEUTDEFF', 'account': 'EUR001'},
            'GBP': {'bank': 'Barclays Bank PLC', 'swift': 'BARCGB22', 'account': 'GBP001'},
            'INR': {'bank': 'State Bank of India', 'swift': 'SBININBB', 'account': 'INR001'},
            'JPY': {'bank': 'Mizuho Bank', 'swift': 'MHCBJPJT', 'account': 'JPY001'},
        }
        
        # Initialize compliance rules
        self.compliance_rules = self._initialize_compliance_rules()
        
        # Currency rates cache
        self.currency_rates_cache = {}
        self.rates_cache_duration = timedelta(minutes=5)
    
    def _initialize_compliance_rules(self) -> Dict[str, CountryRegulation]:
        """Initialize country-specific compliance rules"""
        return {
            'US': CountryRegulation('US', Decimal('10000'), True, True, ['CU', 'IR', 'KP'], ['gambling']),
            'GB': CountryRegulation('GB', Decimal('15000'), True, True, ['AF', 'BY', 'MM'], ['adult']),
            'IN': CountryRegulation('IN', Decimal('25000'), True, True, ['PK'], ['crypto']),
            'EU': CountryRegulation('EU', Decimal('15000'), True, True, ['BY', 'RU'], ['sanctions']),
            'CA': CountryRegulation('CA', Decimal('10000'), True, True, ['AF', 'IR'], ['tobacco']),
            'AU': CountryRegulation('AU', Decimal('10000'), True, True, ['MM', 'KP'], ['gambling']),
            'SG': CountryRegulation('SG', Decimal('20000'), True, True, ['MM', 'KP'], ['adult']),
            'JP': CountryRegulation('JP', Decimal('1000000'), True, True, ['KP', 'IR'], ['adult']),
        }
    
    async def process_cross_border_payment(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process cross-border payment through own gateway
        
        Args:
            payment_data: Dictionary containing payment information
                - transaction_id: str
                - sender: dict (user_id, country, currency, amount)
                - recipient: dict (user_id, country, currency, bank_details)
                - payment_method: str
                - purpose: str
                - metadata: dict
        
        Returns:
            Dictionary with payment result
        """
        try:
            transaction_id = payment_data['transaction_id']
            logging.info(f"Processing cross-border payment: {transaction_id}")
            
            # Step 1: Validate payment request
            validation_result = await self._validate_payment_request(payment_data)
            if not validation_result['valid']:
                return {
                    'success': False,
                    'error_code': 'VALIDATION_ERROR',
                    'error_message': validation_result['error']
                }
            
            # Step 2: Compliance and AML checks
            compliance_result = await self._perform_compliance_checks(payment_data)
            if not compliance_result['approved']:
                return {
                    'success': False,
                    'error_code': 'COMPLIANCE_REJECTION',
                    'error_message': compliance_result['reason']
                }
            
            # Step 3: Currency conversion if needed
            conversion_result = await self._handle_currency_conversion(payment_data)
            if not conversion_result['success']:
                return {
                    'success': False,
                    'error_code': 'CURRENCY_CONVERSION_ERROR',
                    'error_message': conversion_result['error']
                }
            
            # Step 4: Route payment through appropriate network
            routing_result = await self._route_payment(payment_data, conversion_result)
            if not routing_result['success']:
                return {
                    'success': False,
                    'error_code': 'ROUTING_ERROR',
                    'error_message': routing_result['error']
                }
            
            # Step 5: Execute payment
            execution_result = await self._execute_payment(payment_data, routing_result)
            
            return execution_result
            
        except Exception as e:
            logging.error(f"Cross-border payment processing error: {e}")
            return {
                'success': False,
                'error_code': 'PROCESSING_ERROR',
                'error_message': 'Internal payment processing error'
            }
    
    async def _validate_payment_request(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate cross-border payment request"""
        try:
            sender = payment_data.get('sender', {})
            recipient = payment_data.get('recipient', {})
            
            # Basic validation
            required_fields = ['transaction_id', 'sender', 'recipient', 'payment_method']
            for field in required_fields:
                if field not in payment_data:
                    return {'valid': False, 'error': f'Missing required field: {field}'}
            
            # Validate sender
            if not all(k in sender for k in ['user_id', 'country', 'currency', 'amount']):
                return {'valid': False, 'error': 'Invalid sender information'}
            
            # Validate recipient
            if not all(k in recipient for k in ['user_id', 'country', 'currency']):
                return {'valid': False, 'error': 'Invalid recipient information'}
            
            # Validate amount
            amount = Decimal(str(sender['amount']))
            if amount <= 0:
                return {'valid': False, 'error': 'Invalid payment amount'}
            
            # Validate currencies
            supported_currencies = ['USD', 'EUR', 'GBP', 'INR', 'JPY', 'CAD', 'AUD', 'CHF', 'CNY', 'SGD']
            if sender['currency'] not in supported_currencies:
                return {'valid': False, 'error': f'Unsupported sender currency: {sender["currency"]}'}
            
            if recipient['currency'] not in supported_currencies:
                return {'valid': False, 'error': f'Unsupported recipient currency: {recipient["currency"]}'}
            
            # Validate countries
            if sender['country'] == recipient['country'] and sender['currency'] == recipient['currency']:
                return {'valid': False, 'error': 'Use domestic payment method for same country transactions'}
            
            return {'valid': True}
            
        except Exception as e:
            return {'valid': False, 'error': f'Validation error: {str(e)}'}
    
    async def _perform_compliance_checks(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform AML, KYC, and sanctions checks"""
        try:
            sender = payment_data['sender']
            recipient = payment_data['recipient']
            amount = Decimal(str(sender['amount']))
            
            # Check sanctions lists
            sanctions_check = await self._check_sanctions_list(sender, recipient)
            if not sanctions_check['clear']:
                return {'approved': False, 'reason': sanctions_check['reason']}
            
            # Check transaction limits
            sender_country = sender['country']
            if sender_country in self.compliance_rules:
                rules = self.compliance_rules[sender_country]
                if amount > rules.max_transaction_limit:
                    return {'approved': False, 'reason': f'Exceeds transaction limit for {sender_country}'}
                
                if recipient['country'] in rules.prohibited_countries:
                    return {'approved': False, 'reason': f'Transactions to {recipient["country"]} are prohibited'}
            
            # Check purpose/category restrictions
            purpose = payment_data.get('purpose', '')
            if purpose in self.compliance_rules.get(sender_country, CountryRegulation('', 0, False, False, [], [])).restricted_categories:
                return {'approved': False, 'reason': f'Transaction purpose "{purpose}" is restricted'}
            
            # High-value transaction additional checks
            if amount > Decimal('10000'):  # Amounts over $10,000 USD equivalent
                enhanced_check = await self._enhanced_due_diligence(payment_data)
                if not enhanced_check['approved']:
                    return enhanced_check
            
            return {'approved': True, 'compliance_score': 0.95}
            
        except Exception as e:
            logging.error(f"Compliance check error: {e}")
            return {'approved': False, 'reason': 'Compliance check failed'}
    
    async def _check_sanctions_list(self, sender: Dict, recipient: Dict) -> Dict[str, Any]:
        """Check against sanctions and watchlists"""
        # Simplified sanctions check - in production, integrate with OFAC, UN, EU lists
        high_risk_countries = ['AF', 'BY', 'CU', 'IR', 'KP', 'MM', 'RU', 'SY', 'VE']
        
        if sender['country'] in high_risk_countries or recipient['country'] in high_risk_countries:
            return {'clear': False, 'reason': 'High-risk country detected'}
        
        return {'clear': True}
    
    async def _enhanced_due_diligence(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced due diligence for high-value transactions"""
        # In production, this would integrate with external KYC/AML services
        # For now, return approved with additional monitoring
        return {
            'approved': True, 
            'requires_monitoring': True,
            'risk_score': 0.3
        }
    
    async def _handle_currency_conversion(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle currency conversion if needed"""
        try:
            sender = payment_data['sender']
            recipient = payment_data['recipient']
            
            if sender['currency'] == recipient['currency']:
                return {
                    'success': True,
                    'conversion_needed': False,
                    'final_amount': Decimal(str(sender['amount']))
                }
            
            # Get exchange rate
            rate_result = await self._get_exchange_rate(sender['currency'], recipient['currency'])
            if not rate_result['success']:
                return rate_result
            
            # Calculate converted amount
            sender_amount = Decimal(str(sender['amount']))
            exchange_rate = rate_result['rate']
            
            # Apply FX margin
            final_rate = exchange_rate * (Decimal('1') - self.fx_margin)
            converted_amount = sender_amount * final_rate
            
            # Round to appropriate decimal places
            converted_amount = converted_amount.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
            
            return {
                'success': True,
                'conversion_needed': True,
                'original_amount': sender_amount,
                'converted_amount': converted_amount,
                'exchange_rate': exchange_rate,
                'final_rate': final_rate,
                'fx_margin': self.fx_margin,
                'conversion_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logging.error(f"Currency conversion error: {e}")
            return {'success': False, 'error': 'Currency conversion failed'}
    
    async def _get_exchange_rate(self, from_currency: str, to_currency: str) -> Dict[str, Any]:
        """Get real-time exchange rate from multiple sources"""
        try:
            # Check cache first
            cache_key = f"{from_currency}_{to_currency}"
            if cache_key in self.currency_rates_cache:
                cached_rate = self.currency_rates_cache[cache_key]
                if datetime.utcnow() - cached_rate.timestamp < self.rates_cache_duration:
                    return {'success': True, 'rate': cached_rate.rate, 'source': cached_rate.source}
            
            # Fetch from multiple sources for reliability
            rate_sources = [
                self._get_rate_from_central_bank(from_currency, to_currency),
                self._get_rate_from_market_data(from_currency, to_currency),
                self._get_rate_from_backup_source(from_currency, to_currency)
            ]
            
            # Execute all sources concurrently
            results = await asyncio.gather(*rate_sources, return_exceptions=True)
            
            # Find the best rate
            valid_rates = [r for r in results if isinstance(r, dict) and r.get('success')]
            if not valid_rates:
                return {'success': False, 'error': 'No exchange rate sources available'}
            
            # Use median rate for stability
            rates = [r['rate'] for r in valid_rates]
            median_rate = sorted(rates)[len(rates) // 2]
            
            # Cache the rate
            rate_obj = CurrencyRate(from_currency, to_currency, median_rate, datetime.utcnow(), 'aggregated')
            self.currency_rates_cache[cache_key] = rate_obj
            
            return {'success': True, 'rate': median_rate, 'source': 'aggregated'}
            
        except Exception as e:
            logging.error(f"Exchange rate fetch error: {e}")
            return {'success': False, 'error': 'Failed to get exchange rate'}
    
    async def _get_rate_from_central_bank(self, from_currency: str, to_currency: str) -> Dict[str, Any]:
        """Get rate from central bank APIs"""
        # Simplified implementation - in production, integrate with actual central bank APIs
        base_rates = {
            'USD': Decimal('1.0'),
            'EUR': Decimal('0.85'),
            'GBP': Decimal('0.73'),
            'INR': Decimal('83.0'),
            'JPY': Decimal('150.0'),
            'CAD': Decimal('1.35'),
            'AUD': Decimal('1.55'),
            'CHF': Decimal('0.88'),
            'CNY': Decimal('7.2'),
            'SGD': Decimal('1.35')
        }
        
        if from_currency in base_rates and to_currency in base_rates:
            rate = base_rates[to_currency] / base_rates[from_currency]
            return {'success': True, 'rate': rate, 'source': 'central_bank'}
        
        return {'success': False, 'error': 'Currency pair not supported'}
    
    async def _get_rate_from_market_data(self, from_currency: str, to_currency: str) -> Dict[str, Any]:
        """Get rate from market data providers"""
        # Simplified implementation
        try:
            # In production, integrate with Reuters, Bloomberg, etc.
            await asyncio.sleep(0.1)  # Simulate API call
            return await self._get_rate_from_central_bank(from_currency, to_currency)
        except:
            return {'success': False, 'error': 'Market data unavailable'}
    
    async def _get_rate_from_backup_source(self, from_currency: str, to_currency: str) -> Dict[str, Any]:
        """Get rate from backup source"""
        # Simplified implementation
        return await self._get_rate_from_central_bank(from_currency, to_currency)
    
    async def _route_payment(self, payment_data: Dict[str, Any], conversion_result: Dict[str, Any]) -> Dict[str, Any]:
        """Route payment through appropriate payment network"""
        try:
            sender = payment_data['sender']
            recipient = payment_data['recipient']
            payment_method = payment_data['payment_method']
            
            # Determine optimal routing
            routing_method = self._determine_routing_method(sender, recipient, payment_method)
            
            # Get routing details
            routing_details = self._get_routing_details(routing_method, sender['currency'], recipient['currency'])
            
            return {
                'success': True,
                'routing_method': routing_method,
                'routing_details': routing_details,
                'estimated_processing_time': self._get_processing_time(routing_method),
                'processing_fee': self._calculate_processing_fee(sender['amount'], routing_method)
            }
            
        except Exception as e:
            logging.error(f"Payment routing error: {e}")
            return {'success': False, 'error': 'Payment routing failed'}
    
    def _determine_routing_method(self, sender: Dict, recipient: Dict, payment_method: str) -> str:
        """Determine the best routing method for the payment"""
        sender_currency = sender['currency']
        recipient_currency = recipient['currency']
        sender_country = sender['country']
        recipient_country = recipient['country']
        
        # Priority routing logic
        if payment_method == PaymentMethod.SWIFT.value:
            return 'swift_network'
        elif sender_currency == 'EUR' and recipient_currency == 'EUR':
            return 'sepa_instant'
        elif sender_currency == 'GBP' and recipient_country == 'GB':
            return 'faster_payments'
        elif sender_currency == 'USD' and recipient_currency == 'USD':
            return 'fedwire'
        elif sender_currency == 'INR' or recipient_currency == 'INR':
            return 'correspondent_banking'
        else:
            return 'correspondent_banking'
    
    def _get_routing_details(self, routing_method: str, sender_currency: str, recipient_currency: str) -> Dict[str, Any]:
        """Get routing details for the selected method"""
        if routing_method == 'swift_network':
            return {
                'network': 'SWIFT',
                'message_type': 'MT103',
                'sender_bank': self.correspondent_banks.get(sender_currency, {}),
                'recipient_bank': self.correspondent_banks.get(recipient_currency, {}),
                'charges': 'SHA'  # Shared charges
            }
        elif routing_method == 'correspondent_banking':
            return {
                'network': 'Correspondent Banking',
                'sender_bank': self.correspondent_banks.get(sender_currency, {}),
                'recipient_bank': self.correspondent_banks.get(recipient_currency, {}),
                'settlement_method': 'nostro_vostro'
            }
        else:
            return {
                'network': routing_method,
                'details': f'Direct routing via {routing_method}'
            }
    
    def _get_processing_time(self, routing_method: str) -> str:
        """Get estimated processing time for routing method"""
        processing_times = {
            'swift_network': '1-3 business days',
            'sepa_instant': '10 seconds',
            'faster_payments': '2 minutes',
            'fedwire': '30 minutes',
            'correspondent_banking': '2-5 business days'
        }
        return processing_times.get(routing_method, '1-3 business days')
    
    def _calculate_processing_fee(self, amount: str, routing_method: str) -> Decimal:
        """Calculate processing fee based on amount and routing method"""
        amount_decimal = Decimal(str(amount))
        
        fee_structure = {
            'swift_network': {'fixed': Decimal('25'), 'percentage': Decimal('0.001')},
            'sepa_instant': {'fixed': Decimal('0.5'), 'percentage': Decimal('0.0005')},
            'faster_payments': {'fixed': Decimal('1'), 'percentage': Decimal('0.0008')},
            'fedwire': {'fixed': Decimal('15'), 'percentage': Decimal('0.0012')},
            'correspondent_banking': {'fixed': Decimal('35'), 'percentage': Decimal('0.0025')}
        }
        
        fees = fee_structure.get(routing_method, {'fixed': Decimal('20'), 'percentage': Decimal('0.002')})
        
        percentage_fee = amount_decimal * fees['percentage']
        total_fee = fees['fixed'] + percentage_fee
        
        return total_fee.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    
    async def _execute_payment(self, payment_data: Dict[str, Any], routing_result: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the payment through the selected routing method"""
        try:
            transaction_id = payment_data['transaction_id']
            routing_method = routing_result['routing_method']
            
            # Create payment instruction
            payment_instruction = self._create_payment_instruction(payment_data, routing_result)
            
            # Execute based on routing method
            if routing_method == 'swift_network':
                execution_result = await self._execute_swift_payment(payment_instruction)
            elif routing_method == 'correspondent_banking':
                execution_result = await self._execute_correspondent_payment(payment_instruction)
            else:
                execution_result = await self._execute_direct_payment(payment_instruction)
            
            if execution_result['success']:
                return {
                    'success': True,
                    'transaction_id': transaction_id,
                    'external_reference': execution_result['reference'],
                    'status': PaymentStatus.PROCESSING.value,
                    'routing_method': routing_method,
                    'processing_fee': routing_result['processing_fee'],
                    'estimated_completion': execution_result.get('estimated_completion'),
                    'tracking_id': execution_result.get('tracking_id'),
                    'processed_at': datetime.utcnow().isoformat()
                }
            else:
                return {
                    'success': False,
                    'error_code': execution_result.get('error_code', 'EXECUTION_ERROR'),
                    'error_message': execution_result.get('error_message', 'Payment execution failed')
                }
                
        except Exception as e:
            logging.error(f"Payment execution error: {e}")
            return {
                'success': False,
                'error_code': 'EXECUTION_ERROR',
                'error_message': 'Payment execution failed'
            }
    
    def _create_payment_instruction(self, payment_data: Dict[str, Any], routing_result: Dict[str, Any]) -> Dict[str, Any]:
        """Create standardized payment instruction"""
        sender = payment_data['sender']
        recipient = payment_data['recipient']
        
        return {
            'instruction_id': str(uuid.uuid4()),
            'transaction_id': payment_data['transaction_id'],
            'sender': sender,
            'recipient': recipient,
            'amount': sender['amount'],
            'currency': sender['currency'],
            'routing_details': routing_result['routing_details'],
            'purpose': payment_data.get('purpose', 'Payment'),
            'created_at': datetime.utcnow().isoformat(),
            'processing_fee': routing_result['processing_fee']
        }
    
    async def _execute_swift_payment(self, instruction: Dict[str, Any]) -> Dict[str, Any]:
        """Execute payment through SWIFT network"""
        try:
            # Simulate SWIFT message creation and transmission
            swift_reference = f"FT{datetime.utcnow().strftime('%Y%m%d')}{uuid.uuid4().hex[:8].upper()}"
            
            # In production, integrate with SWIFT Alliance or similar
            await asyncio.sleep(0.5)  # Simulate processing time
            
            return {
                'success': True,
                'reference': swift_reference,
                'tracking_id': swift_reference,
                'estimated_completion': (datetime.utcnow() + timedelta(days=1)).isoformat(),
                'network_status': 'transmitted'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error_code': 'SWIFT_ERROR',
                'error_message': f'SWIFT execution failed: {str(e)}'
            }
    
    async def _execute_correspondent_payment(self, instruction: Dict[str, Any]) -> Dict[str, Any]:
        """Execute payment through correspondent banking"""
        try:
            # Simulate correspondent bank processing
            correspondent_ref = f"CB{uuid.uuid4().hex[:12].upper()}"
            
            await asyncio.sleep(0.3)  # Simulate processing time
            
            return {
                'success': True,
                'reference': correspondent_ref,
                'tracking_id': correspondent_ref,
                'estimated_completion': (datetime.utcnow() + timedelta(days=2)).isoformat(),
                'network_status': 'queued_for_settlement'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error_code': 'CORRESPONDENT_ERROR',
                'error_message': f'Correspondent banking failed: {str(e)}'
            }
    
    async def _execute_direct_payment(self, instruction: Dict[str, Any]) -> Dict[str, Any]:
        """Execute payment through direct network connection"""
        try:
            # Simulate direct network processing
            direct_ref = f"DR{uuid.uuid4().hex[:10].upper()}"
            
            await asyncio.sleep(0.1)  # Simulate processing time
            
            return {
                'success': True,
                'reference': direct_ref,
                'tracking_id': direct_ref,
                'estimated_completion': (datetime.utcnow() + timedelta(minutes=30)).isoformat(),
                'network_status': 'processing'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error_code': 'DIRECT_ERROR',
                'error_message': f'Direct payment failed: {str(e)}'
            }
    
    async def track_payment_status(self, transaction_id: str) -> Dict[str, Any]:
        """Track cross-border payment status"""
        try:
            # In production, query actual payment networks
            # For now, simulate tracking
            status_options = [
                PaymentStatus.PROCESSING.value,
                PaymentStatus.COMPLETED.value,
                PaymentStatus.REQUIRES_VERIFICATION.value
            ]
            
            # Simulate status lookup
            await asyncio.sleep(0.1)
            
            return {
                'success': True,
                'transaction_id': transaction_id,
                'status': status_options[0],  # In production, get actual status
                'last_updated': datetime.utcnow().isoformat(),
                'network_references': [f"REF{uuid.uuid4().hex[:8].upper()}"],
                'estimated_completion': (datetime.utcnow() + timedelta(hours=24)).isoformat()
            }
            
        except Exception as e:
            logging.error(f"Payment tracking error: {e}")
            return {
                'success': False,
                'error': 'Failed to track payment status'
            }
    
    async def process_refund(self, transaction_id: str, amount: str, reason: str = "") -> Dict[str, Any]:
        """Process refund for cross-border transaction"""
        try:
            refund_id = str(uuid.uuid4())
            
            # In production, reverse the original payment routing
            refund_result = {
                'success': True,
                'refund_id': refund_id,
                'status': PaymentStatus.PROCESSING.value,
                'amount_refunded': Decimal(str(amount)),
                'estimated_completion': (datetime.utcnow() + timedelta(days=3)).isoformat(),
                'processed_at': datetime.utcnow().isoformat()
            }
            
            return refund_result
            
        except Exception as e:
            logging.error(f"Refund processing error: {e}")
            return {
                'success': False,
                'error_code': 'REFUND_ERROR',
                'error_message': 'Failed to process refund'
            }

class PaymentGatewayAPI:
    """REST API wrapper for the payment gateway"""
    
    def __init__(self, processor: CrossBorderPaymentProcessor):
        self.processor = processor
        self.api_version = "v1"
        self.rate_limiter = {}
    
    async def handle_payment_request(self, request_data: Dict[str, Any], api_key: str) -> Dict[str, Any]:
        """Handle incoming payment API request"""
        try:
            # Validate API key
            if not self._validate_api_key(api_key):
                return {
                    'success': False,
                    'error': 'Invalid API key',
                    'status_code': 401
                }
            
            # Rate limiting check
            if not self._check_rate_limit(api_key):
                return {
                    'success': False,
                    'error': 'Rate limit exceeded',
                    'status_code': 429
                }
            
            # Process payment
            result = await self.processor.process_cross_border_payment(request_data)
            
            return {
                'success': result['success'],
                'data': result,
                'status_code': 200 if result['success'] else 400
            }
            
        except Exception as e:
            logging.error(f"API request handling error: {e}")
            return {
                'success': False,
                'error': 'Internal server error',
                'status_code': 500
            }
    
    def _validate_api_key(self, api_key: str) -> bool:
        """Validate API key"""
        # In production, validate against database
        valid_keys = ['cbp_live_key_12345', 'cbp_test_key_67890']
        return api_key in valid_keys
    
    def _check_rate_limit(self, api_key: str) -> bool:
        """Check rate limiting"""
        # Simple rate limiting - 100 requests per minute
        current_time = datetime.utcnow()
        if api_key not in self.rate_limiter:
            self.rate_limiter[api_key] = {'count': 1, 'window_start': current_time}
            return True
        
        rate_data = self.rate_limiter[api_key]
        if (current_time - rate_data['window_start']).seconds > 60:
            # Reset window
            self.rate_limiter[api_key] = {'count': 1, 'window_start': current_time}
            return True
        
        if rate_data['count'] >= 100:
            return False
        
        rate_data['count'] += 1
        return True

class PaymentWebhookManager:
    """Manage webhooks for payment status updates"""
    
    def __init__(self):
        self.webhook_urls = {}
        self.webhook_secrets = {}
    
    def register_webhook(self, merchant_id: str, webhook_url: str, secret: str, events: List[str]):
        """Register webhook endpoint"""
        self.webhook_urls[merchant_id] = {
            'url': webhook_url,
            'events': events,
            'active': True
        }
        self.webhook_secrets[merchant_id] = secret
    
    async def send_webhook(self, merchant_id: str, event_type: str, data: Dict[str, Any]):
        """Send webhook notification"""
        try:
            if merchant_id not in self.webhook_urls:
                return
            
            webhook_config = self.webhook_urls[merchant_id]
            if not webhook_config['active'] or event_type not in webhook_config['events']:
                return
            
            # Create webhook payload
            payload = {
                'event': event_type,
                'data': data,
                'timestamp': datetime.utcnow().isoformat(),
                'webhook_id': str(uuid.uuid4())
            }
            
            # Sign payload
            signature = self._create_webhook_signature(merchant_id, payload)
            
            # Send webhook
            headers = {
                'Content-Type': 'application/json',
                'X-CBP-Signature': signature,
                'X-CBP-Event': event_type
            }
            
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    webhook_config['url'],
                    json=payload,
                    headers=headers
                ) as response:
                    if response.status == 200:
                        logging.info(f"Webhook sent successfully to {merchant_id}")
                    else:
                        logging.warning(f"Webhook failed for {merchant_id}: {response.status}")
                        
        except Exception as e:
            logging.error(f"Webhook sending error: {e}")
    
    def _create_webhook_signature(self, merchant_id: str, payload: Dict[str, Any]) -> str:
        """Create HMAC signature for webhook"""
        secret = self.webhook_secrets.get(merchant_id, '')
        payload_string = json.dumps(payload, sort_keys=True)
        signature = hmac.new(
            secret.encode('utf-8'),
            payload_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return f"sha256={signature}"

class PaymentReporting:
    """Generate payment reports and analytics"""
    
    def __init__(self):
        self.transactions = []  # In production, use database
    
    async def generate_transaction_report(self, date_from: datetime, date_to: datetime, 
                                        merchant_id: Optional[str] = None) -> Dict[str, Any]:
        """Generate transaction report for given period"""
        try:
            # Filter transactions
            filtered_transactions = self._filter_transactions(date_from, date_to, merchant_id)
            
            # Calculate metrics
            total_volume = sum(Decimal(str(t.get('amount', 0))) for t in filtered_transactions)
            total_transactions = len(filtered_transactions)
            successful_transactions = len([t for t in filtered_transactions if t.get('status') == 'completed'])
            
            success_rate = (successful_transactions / total_transactions * 100) if total_transactions > 0 else 0
            
            # Currency breakdown
            currency_breakdown = {}
            for transaction in filtered_transactions:
                currency = transaction.get('currency', 'USD')
                currency_breakdown[currency] = currency_breakdown.get(currency, 0) + Decimal(str(transaction.get('amount', 0)))
            
            # Country breakdown
            country_breakdown = {}
            for transaction in filtered_transactions:
                sender_country = transaction.get('sender', {}).get('country', 'Unknown')
                recipient_country = transaction.get('recipient', {}).get('country', 'Unknown')
                route = f"{sender_country}->{recipient_country}"
                country_breakdown[route] = country_breakdown.get(route, 0) + 1
            
            return {
                'period': {
                    'from': date_from.isoformat(),
                    'to': date_to.isoformat()
                },
                'summary': {
                    'total_volume': str(total_volume),
                    'total_transactions': total_transactions,
                    'successful_transactions': successful_transactions,
                    'success_rate': round(success_rate, 2)
                },
                'breakdown': {
                    'by_currency': {k: str(v) for k, v in currency_breakdown.items()},
                    'by_route': country_breakdown
                },
                'generated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logging.error(f"Report generation error: {e}")
            return {'error': 'Failed to generate report'}
    
    def _filter_transactions(self, date_from: datetime, date_to: datetime, 
                           merchant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Filter transactions based on criteria"""
        # In production, query database with proper filtering
        return self.transactions  # Simplified for example

class FraudDetectionEngine:
    """Real-time fraud detection for cross-border payments"""
    
    def __init__(self):
        self.risk_rules = self._initialize_risk_rules()
        self.ml_models = {}  # In production, load ML models
    
    def _initialize_risk_rules(self) -> List[Dict[str, Any]]:
        """Initialize fraud detection rules"""
        return [
            {
                'name': 'velocity_check',
                'description': 'Check transaction velocity per user',
                'weight': 0.3
            },
            {
                'name': 'amount_anomaly',
                'description': 'Detect unusual transaction amounts',
                'weight': 0.25
            },
            {
                'name': 'geographic_risk',
                'description': 'Assess geographic risk factors',
                'weight': 0.2
            },
            {
                'name': 'behavioral_analysis',
                'description': 'Analyze user behavior patterns',
                'weight': 0.25
            }
        ]
    
    async def analyze_transaction(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze transaction for fraud risk"""
        try:
            risk_score = Decimal('0')
            risk_factors = []
            
            # Apply risk rules
            for rule in self.risk_rules:
                rule_result = await self._apply_risk_rule(rule, payment_data)
                risk_score += Decimal(str(rule_result['score'])) * Decimal(str(rule['weight']))
                
                if rule_result['triggered']:
                    risk_factors.append({
                        'rule': rule['name'],
                        'description': rule_result['reason'],
                        'severity': rule_result['severity']
                    })
            
            # Determine action based on risk score
            if risk_score >= Decimal('0.8'):
                action = 'block'
            elif risk_score >= Decimal('0.5'):
                action = 'review'
            else:
                action = 'approve'
            
            return {
                'risk_score': float(risk_score),
                'action': action,
                'risk_factors': risk_factors,
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logging.error(f"Fraud analysis error: {e}")
            return {
                'risk_score': 0.0,
                'action': 'approve',
                'risk_factors': [],
                'error': 'Fraud analysis failed'
            }
    
    async def _apply_risk_rule(self, rule: Dict[str, Any], payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply individual risk rule"""
        rule_name = rule['name']
        
        if rule_name == 'velocity_check':
            return await self._check_velocity(payment_data)
        elif rule_name == 'amount_anomaly':
            return await self._check_amount_anomaly(payment_data)
        elif rule_name == 'geographic_risk':
            return await self._check_geographic_risk(payment_data)
        elif rule_name == 'behavioral_analysis':
            return await self._check_behavioral_patterns(payment_data)
        else:
            return {'score': 0, 'triggered': False, 'reason': '', 'severity': 'low'}
    
    async def _check_velocity(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check transaction velocity"""
        # Simplified velocity check
        user_id = payment_data.get('sender', {}).get('user_id')
        amount = Decimal(str(payment_data.get('sender', {}).get('amount', 0)))
        
        # In production, query recent transactions from database
        if amount > Decimal('10000'):  # High amount threshold
            return {
                'score': 0.6,
                'triggered': True,
                'reason': 'High amount transaction detected',
                'severity': 'medium'
            }
        
        return {'score': 0.1, 'triggered': False, 'reason': '', 'severity': 'low'}
    
    async def _check_amount_anomaly(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check for amount anomalies"""
        amount = Decimal(str(payment_data.get('sender', {}).get('amount', 0)))
        
        # Round number detection (potential money laundering)
        if amount == amount.quantize(Decimal('1000')):
            return {
                'score': 0.4,
                'triggered': True,
                'reason': 'Round amount transaction',
                'severity': 'low'
            }
        
        return {'score': 0.05, 'triggered': False, 'reason': '', 'severity': 'low'}
    
    async def _check_geographic_risk(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check geographic risk factors"""
        sender_country = payment_data.get('sender', {}).get('country', '')
        recipient_country = payment_data.get('recipient', {}).get('country', '')
        
        high_risk_countries = ['AF', 'BY', 'MM', 'KP', 'IR']
        
        if sender_country in high_risk_countries or recipient_country in high_risk_countries:
            return {
                'score': 0.8,
                'triggered': True,
                'reason': 'High-risk country involved',
                'severity': 'high'
            }
        
        return {'score': 0.1, 'triggered': False, 'reason': '', 'severity': 'low'}
    
    async def _check_behavioral_patterns(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze behavioral patterns"""
        # Simplified behavioral check
        user_id = payment_data.get('sender', {}).get('user_id')
        
        # In production, analyze historical behavior patterns
        return {'score': 0.05, 'triggered': False, 'reason': '', 'severity': 'low'}
