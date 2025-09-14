import logging
import uuid
from typing import Dict, Any, Optional
from datetime import datetime
import aiohttp
import json
import asyncio

class PaymentProcessor:
    def __init__(self):
        """Initialize payment processor with configuration"""
        self.visa_config = {
            'base_url': 'https://sandbox-api.visa.com',
            'api_key': 'YOUR_VISA_API_KEY',
            'user_id': 'YOUR_VISA_USER_ID',
            'password': 'YOUR_VISA_PASSWORD',
            'cert_path': 'path/to/visa_cert.pem',
            'key_path': 'path/to/visa_key.pem'
        }
        
        self.mastercard_config = {
            'base_url': 'https://sandbox.api.mastercard.com',
            'consumer_key': 'YOUR_MASTERCARD_CONSUMER_KEY',
            'signing_key_path': 'path/to/mastercard_signing_key.p12',
            'signing_key_password': 'YOUR_SIGNING_KEY_PASSWORD'
        }
        
        self.amex_config = {
            'base_url': 'https://api.americanexpress.com',
            'api_key': 'YOUR_AMEX_API_KEY',
            'client_id': 'YOUR_AMEX_CLIENT_ID',
            'client_secret': 'YOUR_AMEX_CLIENT_SECRET'
        }
        
        self.discover_config = {
            'base_url': 'https://api.discover.com',
            'api_key': 'YOUR_DISCOVER_API_KEY',
            'merchant_id': 'YOUR_DISCOVER_MERCHANT_ID'
        }
        
        # Default timeout for all requests
        self.timeout = 30
        
        # Default merchant ID (could be overridden per network)
        self.default_merchant_id = 'YOUR_DEFAULT_MERCHANT_ID'

    def _detect_card_network(self, card_number: str) -> str:
        """Detect card network based on card number"""
        # Remove spaces and non-digits
        card_number = ''.join(filter(str.isdigit, card_number))
        
        # Visa: starts with 4
        if card_number.startswith('4'):
            return 'visa'
        # Mastercard: starts with 5 or 2221-2720
        elif card_number.startswith('5') or (card_number.startswith('2') and 2221 <= int(card_number[:4]) <= 2720):
            return 'mastercard'
        # American Express: starts with 34 or 37
        elif card_number.startswith(('34', '37')):
            return 'amex'
        # Discover: starts with 6011, 622126-622925, 644-649, or 65
        elif (card_number.startswith('6011') or 
              card_number.startswith('65') or
              (card_number.startswith('622') and 622126 <= int(card_number[:6]) <= 622925) or
              (card_number.startswith('64') and card_number[2] in '456789')):
            return 'discover'
        else:
            return 'unknown'

    def _get_network_config(self, card_network: str) -> Dict[str, Any]:
        """Get configuration for specific card network"""
        config_map = {
            'visa': self.visa_config,
            'mastercard': self.mastercard_config,
            'amex': self.amex_config,
            'discover': self.discover_config
        }
        return config_map.get(card_network, {})

    def _prepare_network_headers(self, card_network: str) -> Dict[str, str]:
        """Prepare headers specific to card network"""
        config = self._get_network_config(card_network)
        
        if card_network == 'visa':
            return {
                'Authorization': f'Bearer {config.get("api_key")}',
                'Content-Type': 'application/json',
                'User-Agent': 'BiometricPaymentSystem/1.0'
            }
        elif card_network == 'mastercard':
            return {
                'Authorization': f'Bearer {config.get("consumer_key")}',
                'Content-Type': 'application/json',
                'User-Agent': 'BiometricPaymentSystem/1.0'
            }
        elif card_network == 'amex':
            return {
                'Authorization': f'Bearer {config.get("api_key")}',
                'Content-Type': 'application/json',
                'X-AMEX-API-KEY': config.get("api_key"),
                'User-Agent': 'BiometricPaymentSystem/1.0'
            }
        elif card_network == 'discover':
            return {
                'Authorization': f'Bearer {config.get("api_key")}',
                'Content-Type': 'application/json',
                'User-Agent': 'BiometricPaymentSystem/1.0'
            }
        else:
            # Fallback to generic headers
            return {
                'Content-Type': 'application/json',
                'User-Agent': 'BiometricPaymentSystem/1.0'
            }

    def _get_network_endpoint(self, card_network: str) -> str:
        """Get API endpoint for specific card network"""
        config = self._get_network_config(card_network)
        base_url = config.get('base_url', 'https://api.generic-gateway.com')
        
        # Each network might have different endpoint paths
        endpoint_map = {
            'visa': f"{base_url}/v1/payments",
            'mastercard': f"{base_url}/payments/v1/process",
            'amex': f"{base_url}/payments/v2/charge",
            'discover': f"{base_url}/v1/transactions"
        }
        
        return endpoint_map.get(card_network, f"{base_url}/payments")

    async def process_card_payment(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process card payment through appropriate network gateway
        
        Args:
            payment_data: Dictionary containing payment information
                - transaction_id: str
                - user_id: int
                - amount: float
                - currency: str
                - card_details: dict (for new cards)
                - saved_card: SavedCard object (for saved cards)
                - confidence: float (biometric confidence score)
        
        Returns:
            Dictionary with payment result
        """
        try:
            logging.info(f"Processing card payment for transaction: {payment_data['transaction_id']}")
            
            # Detect card network
            card_network = self._detect_card_network_from_payment(payment_data)
            logging.info(f"Detected card network: {card_network}")
            
            # Prepare payment request for specific network
            payment_request = self._prepare_network_payment_request(payment_data, card_network)
            
            # Send payment request to appropriate network gateway
            payment_result = await self._send_network_payment_request(payment_request, card_network)
            
            # Process response
            if payment_result.get('status') == 'success':
                return {
                    'success': True,
                    'external_id': payment_result.get('payment_id'),
                    'authorization_code': payment_result.get('auth_code'),
                    'gateway_response': payment_result.get('response_code'),
                    'processed_at': datetime.utcnow().isoformat(),
                    'fees': payment_result.get('processing_fee', 0),
                    'receipt_url': payment_result.get('receipt_url'),
                    'card_network': card_network
                }
            else:
                return {
                    'success': False,
                    'error_code': payment_result.get('error_code'),
                    'error_message': payment_result.get('error_message', 'Payment processing failed'),
                    'gateway_response': payment_result.get('response_code'),
                    'card_network': card_network
                }
                
        except Exception as e:
            logging.error(f"Card payment processing error: {e}")
            return {
                'success': False,
                'error_code': 'PROCESSING_ERROR',
                'error_message': 'Internal payment processing error'
            }

    def _detect_card_network_from_payment(self, payment_data: Dict[str, Any]) -> str:
        """Detect card network from payment data"""
        if payment_data.get('card_details'):
            return self._detect_card_network(payment_data['card_details']['number'])
        elif payment_data.get('saved_card'):
            # Assume saved card has network information
            return payment_data['saved_card'].card_network if hasattr(payment_data['saved_card'], 'card_network') else 'unknown'
        return 'unknown'

    def _prepare_network_payment_request(self, payment_data: Dict[str, Any], card_network: str) -> Dict[str, Any]:
        """Prepare payment request for specific network"""
        config = self._get_network_config(card_network)
        
        # Base request structure
        request_data = {
            'transaction_id': payment_data['transaction_id'],
            'amount': int(payment_data['amount'] * 100),  # Convert to cents
            'currency': payment_data['currency'],
            'description': f"Payment for user {payment_data['user_id']}",
            'metadata': {
                'user_id': payment_data['user_id'],
                'biometric_confidence': payment_data.get('confidence', 0),
                'payment_method': 'card',
                'card_network': card_network
            }
        }
        
        # Add network-specific merchant ID
        if card_network == 'visa':
            request_data['merchant_id'] = config.get('user_id', self.default_merchant_id)
        elif card_network == 'mastercard':
            request_data['merchant_id'] = config.get('consumer_key', self.default_merchant_id)
        elif card_network == 'discover':
            request_data['merchant_id'] = config.get('merchant_id', self.default_merchant_id)
        else:
            request_data['merchant_id'] = self.default_merchant_id

        # Add card information
        if payment_data.get('card_details'):
            card_details = payment_data['card_details']
            
            # Network-specific card format
            if card_network == 'amex':
                # AmEx might have different field names
                request_data['payment_method'] = {
                    'type': 'card',
                    'card': {
                        'card_number': card_details['number'],
                        'expiry_month': card_details['expiry_month'],
                        'expiry_year': card_details['expiry_year'],
                        'security_code': card_details['cvv'],
                        'cardholder_name': card_details['holder_name']
                    }
                }
            else:
                # Standard format for Visa, Mastercard, Discover
                request_data['payment_method'] = {
                    'type': 'card',
                    'card': {
                        'number': card_details['number'],
                        'exp_month': card_details['expiry_month'],
                        'exp_year': card_details['expiry_year'],
                        'cvc': card_details['cvv'],
                        'name': card_details['holder_name']
                    }
                }
        elif payment_data.get('saved_card'):
            saved_card = payment_data['saved_card']
            request_data['payment_method'] = {
                'type': 'card_token',
                'token': saved_card.card_token,
                'last_four': str(saved_card.last_four_encrypted)
            }
        
        return request_data

    async def _send_network_payment_request(self, payment_request: Dict[str, Any], card_network: str) -> Dict[str, Any]:
        """Send payment request to specific network gateway"""
        headers = self._prepare_network_headers(card_network)
        endpoint = self._get_network_endpoint(card_network)
        config = self._get_network_config(card_network)
        
        try:
            # Special handling for networks that require client certificates (like Visa)
            connector = None
            if card_network == 'visa' and config.get('cert_path') and config.get('key_path'):
                import ssl
                ssl_context = ssl.create_default_context()
                ssl_context.load_cert_chain(config['cert_path'], config['key_path'])
                connector = aiohttp.TCPConnector(ssl=ssl_context)
            
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.post(
                    endpoint,
                    json=payment_request,
                    headers=headers
                ) as response:
                    
                    response_data = await response.json()
                    
                    if response.status == 200:
                        return self._parse_network_success_response(response_data, card_network)
                    else:
                        return self._parse_network_error_response(response_data, response.status, card_network)
                        
        except asyncio.TimeoutError:
            logging.error(f"Payment gateway timeout for {card_network}")
            return {
                'status': 'error',
                'error_code': 'GATEWAY_TIMEOUT',
                'error_message': f'{card_network.title()} payment gateway timeout'
            }
        except aiohttp.ClientConnectorError as e:
            logging.error(f"Payment gateway connection error for {card_network}: {e}")
            return {
                'status': 'error',
                'error_code': 'CONNECTION_ERROR',
                'error_message': f'Failed to connect to {card_network.title()} payment gateway'
            }
        except Exception as e:
            logging.error(f"Unexpected payment gateway error for {card_network}: {e}")
            return {
                'status': 'error',
                'error_code': 'UNKNOWN_ERROR',
                'error_message': f'Unexpected {card_network.title()} payment processing error'
            }

    def _parse_network_success_response(self, response_data: Dict[str, Any], card_network: str) -> Dict[str, Any]:
        """Parse successful payment response for specific network"""
        # Different networks might have different response formats
        if card_network == 'amex':
            return {
                'status': 'success',
                'payment_id': response_data.get('transaction_id'),
                'auth_code': response_data.get('approval_code'),
                'response_code': response_data.get('response_code'),
                'processing_fee': response_data.get('fees', {}).get('processing', 0) / 100,
                'receipt_url': response_data.get('receipt_url'),
                'gateway_transaction_id': response_data.get('amex_transaction_id')
            }
        else:
            # Standard format for Visa, Mastercard, Discover
            return {
                'status': 'success',
                'payment_id': response_data.get('id'),
                'auth_code': response_data.get('authorization_code'),
                'response_code': response_data.get('response_code'),
                'processing_fee': response_data.get('fee', {}).get('amount', 0) / 100,
                'receipt_url': response_data.get('receipt_url'),
                'gateway_transaction_id': response_data.get('gateway_transaction_id')
            }

    def _parse_network_error_response(self, response_data: Dict[str, Any], status_code: int, card_network: str) -> Dict[str, Any]:
        """Parse error payment response for specific network"""
        error_mapping = {
            400: 'INVALID_REQUEST',
            401: 'UNAUTHORIZED',
            402: 'PAYMENT_REQUIRED',
            403: 'FORBIDDEN',
            404: 'NOT_FOUND',
            429: 'RATE_LIMITED',
            500: 'GATEWAY_ERROR'
        }
        
        # Network-specific error handling
        if card_network == 'amex':
            return {
                'status': 'error',
                'error_code': response_data.get('error_code', error_mapping.get(status_code, 'UNKNOWN_ERROR')),
                'error_message': response_data.get('error_description', 'AmEx payment processing failed'),
                'response_code': status_code,
                'decline_code': response_data.get('decline_code'),
                'gateway_response': response_data
            }
        else:
            return {
                'status': 'error',
                'error_code': response_data.get('error', {}).get('code', error_mapping.get(status_code, 'UNKNOWN_ERROR')),
                'error_message': response_data.get('error', {}).get('message', f'{card_network.title()} payment processing failed'),
                'response_code': status_code,
                'decline_code': response_data.get('error', {}).get('decline_code'),
                'gateway_response': response_data
            }

    # Keep existing refund and verify methods but add network-specific handling
    async def process_refund(self, transaction_id: str, amount: float, reason: str = "", card_network: str = "visa") -> Dict[str, Any]:
        """Process refund for a transaction through specific network"""
        try:
            config = self._get_network_config(card_network)
            
            refund_request = {
                'transaction_id': transaction_id,
                'amount': int(amount * 100),
                'reason': reason,
                'refund_id': str(uuid.uuid4())
            }
            
            # Add network-specific merchant ID
            if card_network == 'discover':
                refund_request['merchant_id'] = config.get('merchant_id', self.default_merchant_id)
            else:
                refund_request['merchant_id'] = self.default_merchant_id
            
            headers = self._prepare_network_headers(card_network)
            endpoint = self._get_network_endpoint(card_network).replace('/payments', '/refunds')
            
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    endpoint,
                    json=refund_request,
                    headers=headers
                ) as response:
                    
                    response_data = await response.json()
                    
                    if response.status == 200:
                        return {
                            'success': True,
                            'refund_id': response_data.get('id'),
                            'status': response_data.get('status'),
                            'amount_refunded': response_data.get('amount', 0) / 100,
                            'card_network': card_network
                        }
                    else:
                        return {
                            'success': False,
                            'error_code': response_data.get('error', {}).get('code'),
                            'error_message': response_data.get('error', {}).get('message'),
                            'card_network': card_network
                        }
                        
        except Exception as e:
            logging.error(f"Refund processing error for {card_network}: {e}")
            return {
                'success': False,
                'error_code': 'REFUND_ERROR',
                'error_message': f'Failed to process {card_network.title()} refund'
            }

    async def verify_payment_status(self, external_payment_id: str, card_network: str = "visa") -> Dict[str, Any]:
        """Verify payment status with specific network gateway"""
        try:
            headers = self._prepare_network_headers(card_network)
            endpoint = self._get_network_endpoint(card_network)
            
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    f"{endpoint}/{external_payment_id}",
                    headers=headers
                ) as response:
                    
                    if response.status == 200:
                        response_data = await response.json()
                        return {
                            'success': True,
                            'status': response_data.get('status'),
                            'amount': response_data.get('amount', 0) / 100,
                            'currency': response_data.get('currency'),
                            'created_at': response_data.get('created'),
                            'card_network': card_network
                        }
                    else:
                        return {
                            'success': False,
                            'error': f'Payment not found or verification failed for {card_network.title()}',
                            'card_network': card_network
                        }
                        
        except Exception as e:
            logging.error(f"Payment verification error for {card_network}: {e}")
            return {
                'success': False,
                'error': f'Failed to verify {card_network.title()} payment status',
                'card_network': card_network
            }