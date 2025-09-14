# Transaction Risk Analysis Engine
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import json
import hashlib
import logging
from enum import Enum
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
import requests

logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCK = "block"

class ActionType(Enum):
    APPROVE = "approve"
    STEP_UP_OTP = "step_up_otp" 
    STEP_UP_BIOMETRIC = "step_up_biometric"
    STEP_UP_DOCUMENT = "step_up_document"
    BLOCK = "block"
    REVIEW = "review"

@dataclass
class TransactionContext:
    amount: float
    currency: str
    merchant_category: str
    recipient_country: str
    user_id: str
    session_id: str
    timestamp: datetime
    last_sca_time: Optional[datetime] = None
    
@dataclass
class DeviceFingerprint:
    device_id: str
    os: str
    os_version: str
    is_rooted: bool
    is_emulator: bool
    ip_address: str
    user_agent: str
    behavioral_metrics: Dict
    
@dataclass
class RiskAssessmentResult:
    risk_score: float
    risk_level: RiskLevel
    recommended_action: ActionType
    rule_flags: List[str]
    ml_features: Dict
    reason_codes: List[str]
    fraud_indicators: List[str]

class NetworkIntelligenceService:
    """Network and geolocation intelligence"""
    
    def __init__(self):
        # Initialize GeoIP databases and threat intelligence
        self.geoip_reader = None  # geoip2.database.Reader('GeoLite2-City.mmdb')
        self.proxy_ranges = self.load_proxy_ranges()
        self.tor_exit_nodes = self.load_tor_nodes()
    
    def load_proxy_ranges(self) -> set:
        # Load known proxy/VPN IP ranges
        return set()
    
    def load_tor_nodes(self) -> set:
        # Load Tor exit node IPs
        return set()
    
    def analyze_ip(self, ip_address: str) -> Dict:
        """Analyze IP address for risk indicators"""
        analysis = {
            'is_proxy': self.is_proxy_or_vpn(ip_address),
            'is_tor': ip_address in self.tor_exit_nodes,
            'country': self.get_country(ip_address),
            'asn': self.get_asn(ip_address),
            'risk_score': 0.0
        }
        
        # Calculate IP risk score
        if analysis['is_tor']:
            analysis['risk_score'] = 0.9
        elif analysis['is_proxy']:
            analysis['risk_score'] = 0.7
        elif analysis['country'] in ['CN', 'RU', 'NG']:  # High-risk countries
            analysis['risk_score'] = 0.3
        
        return analysis
    
    def is_proxy_or_vpn(self, ip_address: str) -> bool:
        # Check against known proxy/VPN ranges
        return ip_address in self.proxy_ranges
    
    def get_country(self, ip_address: str) -> str:
        # Get country from GeoIP
        return 'US'  # Placeholder
    
    def get_asn(self, ip_address: str) -> str:
        # Get ASN information
        return 'AS1234'  # Placeholder
    
    def calculate_geovelocity(self, current_ip: str, last_location: Dict, 
                             last_timestamp: datetime) -> float:
        """Calculate impossible travel velocity"""
        current_location = self.get_location(current_ip)
        if not current_location or not last_location:
            return 0.0
        
        # Calculate distance (simplified)
        distance_km = self.haversine_distance(
            last_location['lat'], last_location['lon'],
            current_location['lat'], current_location['lon']
        )
        
        time_hours = (datetime.now() - last_timestamp).total_seconds() / 3600
        if time_hours <= 0:
            return float('inf')
        
        return distance_km / time_hours  # km/h
    
    def get_location(self, ip_address: str) -> Dict:
        # Get lat/lon from GeoIP
        return {'lat': 40.7128, 'lon': -74.0060}  # NYC placeholder
    
    def haversine_distance(self, lat1: float, lon1: float, 
                          lat2: float, lon2: float) -> float:
        """Calculate distance between two points on Earth"""
        R = 6371  # Earth's radius in kilometers
        
        lat1_rad = np.radians(lat1)
        lon1_rad = np.radians(lon1)
        lat2_rad = np.radians(lat2)
        lon2_rad = np.radians(lon2)
        
        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad
        
        a = (np.sin(dlat/2)**2 + np.cos(lat1_rad) * np.cos(lat2_rad) * 
             np.sin(dlon/2)**2)
        c = 2 * np.arcsin(np.sqrt(a))
        
        return R * c

class BehaviorAnalysisService:
    """Behavioral biometrics analysis"""
    
    def analyze_behavior(self, behavioral_metrics: Dict) -> Dict:
        """Analyze behavioral patterns for anomalies"""
        analysis = {
            'keystroke_anomaly': self.analyze_keystroke_pattern(
                behavioral_metrics.get('keystrokeTiming')
            ),
            'mouse_anomaly': self.analyze_mouse_pattern(
                behavioral_metrics.get('mouseMovement')
            ),
            'session_anomaly': self.analyze_session_metrics(
                behavioral_metrics.get('sessionMetrics')
            ),
            'bot_probability': 0.0
        }
        
        # Calculate overall bot probability
        anomaly_scores = [
            analysis['keystroke_anomaly'],
            analysis['mouse_anomaly'], 
            analysis['session_anomaly']
        ]
        
        analysis['bot_probability'] = np.mean([s for s in anomaly_scores if s > 0])
        
        return analysis
    
    def analyze_keystroke_pattern(self, keystroke_data: Optional[Dict]) -> float:
        """Analyze keystroke dynamics for bot-like behavior"""
        if not keystroke_data:
            return 0.0
        
        # Check for suspiciously regular patterns
        dwell_variance = keystroke_data.get('rhythmVariance', 0)
        avg_dwell = keystroke_data.get('avgDwellTime', 0)
        
        # Very low variance suggests automation
        if dwell_variance < 5 and avg_dwell > 0:
            return 0.8
        
        # Very high error rate suggests human confusion or takeover
        error_rate = keystroke_data.get('errorRate', 0)
        if error_rate > 0.1:
            return 0.6
        
        return 0.0
    
    def analyze_mouse_pattern(self, mouse_data: Optional[Dict]) -> float:
        """Analyze mouse movement patterns"""
        if not mouse_data:
            return 0.0
        
        # Perfectly straight lines suggest automation
        trajectory_entropy = mouse_data.get('trajectoryEntropy', 1.0)
        if trajectory_entropy < 0.1:
            return 0.9
        
        # Impossibly fast movement
        avg_velocity = mouse_data.get('avgVelocity', 0)
        if avg_velocity > 1000:  # pixels per ms
            return 0.7
        
        return 0.0
    
    def analyze_session_metrics(self, session_data: Optional[Dict]) -> float:
        """Analyze session-level behavioral patterns"""
        if not session_data:
            return 0.0
        
        # High copy/paste rate suggests form-filling bots
        copy_paste_rate = session_data.get('copyPasteRate', 0)
        if copy_paste_rate > 10:  # per minute
            return 0.8
        
        # Abnormal focus/blur patterns
        focus_blur_rate = session_data.get('focusBlurRate', 0)
        if focus_blur_rate > 20:  # per minute
            return 0.6
        
        return 0.0

class TransactionRiskAnalyzer:
    """Main risk analysis engine"""
    
    def __init__(self):
        self.network_intel = NetworkIntelligenceService()
        self.behavior_analyzer = BehaviorAnalysisService()
        self.ml_model = None  # Will be loaded
        self.reputation_store = {}  # Redis/database in production
        
        # Rule thresholds
        self.GEOVELOCITY_THRESHOLD = 500  # km/h
        self.HIGH_AMOUNT_THRESHOLD = 1000  # EUR
        self.SCA_MAX_AGE_HOURS = 24
        
    def assess_transaction_risk(self, transaction: TransactionContext,
                              device: DeviceFingerprint,
                              user_history: Dict) -> RiskAssessmentResult:
        """Main risk assessment entry point"""
        
        logger.info(f"Assessing risk for transaction {transaction.session_id}")
        
        # Step 1: Apply deterministic rules
        rule_result = self.apply_deterministic_rules(transaction, device, user_history)
        
        # Step 2: Feature engineering
        features = self.engineer_features(transaction, device, user_history)
        
        # Step 3: ML scoring (if not blocked by rules)
        ml_score = 0.0
        if rule_result['risk_score'] < 0.9:
            ml_score = self.get_ml_score(features)
        
        # Step 4: Fusion and final decision
        final_score = max(rule_result['risk_score'], ml_score)
        risk_level, action = self.determine_action(final_score, transaction.amount)
        
        return RiskAssessmentResult(
            risk_score=final_score,
            risk_level=risk_level,
            recommended_action=action,
            rule_flags=rule_result['flags'],
            ml_features=features,
            reason_codes=self.generate_reason_codes(rule_result, ml_score, features),
            fraud_indicators=rule_result['fraud_indicators']
        )
    
    def apply_deterministic_rules(self, transaction: TransactionContext,
                                device: DeviceFingerprint,
                                user_history: Dict) -> Dict:
        """Apply hard security rules"""
        
        flags = []
        fraud_indicators = []
        risk_score = 0.0
        
        # Device integrity rules
        if device.is_emulator:
            flags.append('EMULATOR_DETECTED')
            fraud_indicators.append('Running on emulator')
            risk_score = max(risk_score, 0.9)
        
        if device.is_rooted:
            flags.append('ROOTED_DEVICE')
            fraud_indicators.append('Rooted/jailbroken device')
            risk_score = max(risk_score, 0.8)
        
        # Network rules
        ip_analysis = self.network_intel.analyze_ip(device.ip_address)
        
        if ip_analysis['is_tor']:
            flags.append('TOR_NETWORK')
            fraud_indicators.append('Tor network detected')
            risk_score = max(risk_score, 0.9)
        
        if ip_analysis['is_proxy']:
            flags.append('PROXY_VPN')
            fraud_indicators.append('Proxy/VPN detected')
            risk_score = max(risk_score, 0.7)
        
        # Geovelocity check
        last_location = user_history.get('last_location')
        last_timestamp = user_history.get('last_transaction_time')
        
        if last_location and last_timestamp:
            velocity = self.network_intel.calculate_geovelocity(
                device.ip_address, last_location, last_timestamp
            )
            
            if velocity > self.GEOVELOCITY_THRESHOLD:
                flags.append('IMPOSSIBLE_TRAVEL')
                fraud_indicators.append(f'Impossible travel: {velocity:.0f} km/h')
                risk_score = max(risk_score, 0.8)
        
        # First-time device with high amount
        if self.is_first_time_device(device.device_id) and transaction.amount > self.HIGH_AMOUNT_THRESHOLD:
            flags.append('NEW_DEVICE_HIGH_AMOUNT')
            fraud_indicators.append('New device with high amount')
            risk_score = max(risk_score, 0.6)
        
        # Behavioral anomalies
        behavior_analysis = self.behavior_analyzer.analyze_behavior(
            device.behavioral_metrics
        )
        
        if behavior_analysis['bot_probability'] > 0.7:
            flags.append('BOT_BEHAVIOR')
            fraud_indicators.append('Automated behavior detected')
            risk_score = max(risk_score, 0.8)
        
        # Reputation checks
        if self.is_device_blacklisted(device.device_id):
            flags.append('DEVICE_BLACKLISTED')
            fraud_indicators.append('Device on deny list')
            risk_score = max(risk_score, 0.9)
        
        # SCA timing rules
        if transaction.last_sca_time:
            sca_age = datetime.now() - transaction.last_sca_time
            if sca_age > timedelta(hours=self.SCA_MAX_AGE_HOURS):
                flags.append('SCA_EXPIRED')
                risk_score = max(risk_score, 0.4)
        
        return {
            'risk_score': risk_score,
            'flags': flags,
            'fraud_indicators': fraud_indicators
        }
    
    def engineer_features(self, transaction: TransactionContext,
                         device: DeviceFingerprint,
                         user_history: Dict) -> Dict:
        """Engineer features for ML model"""
        
        features = {}
        
        # Transaction features
        features['amount'] = transaction.amount
        features['amount_zscore'] = self.calculate_amount_zscore(
            transaction.amount, user_history.get('amount_history', [])
        )
        features['hour_of_day'] = transaction.timestamp.hour
        features['day_of_week'] = transaction.timestamp.weekday()
        
        # Device features
        features['device_age_days'] = self.get_device_age_days(device.device_id)
        features['device_first_seen'] = 1 if features['device_age_days'] == 0 else 0
        
        # Network features
        ip_analysis = self.network_intel.analyze_ip(device.ip_address)
        features['ip_risk_score'] = ip_analysis['risk_score']
        features['is_proxy'] = 1 if ip_analysis['is_proxy'] else 0
        features['is_tor'] = 1 if ip_analysis['is_tor'] else 0
        
        # Behavioral features
        behavior_analysis = self.behavior_analyzer.analyze_behavior(
            device.behavioral_metrics
        )
        features['bot_probability'] = behavior_analysis['bot_probability']
        features['keystroke_anomaly'] = behavior_analysis['keystroke_anomaly']
        features['mouse_anomaly'] = behavior_analysis['mouse_anomaly']
        
        # Velocity features
        features['transaction_velocity_1h'] = self.get_transaction_velocity(
            user_history, hours=1
        )
        features['transaction_velocity_24h'] = self.get_transaction_velocity(
            user_history, hours=24
        )
        
        # Reputation features
        features['device_link_count'] = self.get_device_link_count(device.device_id)
        features['prior_3ds_success_rate'] = self.get_3ds_success_rate(device.device_id)
        
        return features
    
    def get_ml_score(self, features: Dict) -> float:
        """Get ML model risk score"""
        if not self.ml_model:
            return 0.0  # Model not loaded
        
        # Convert features to array format expected by model
        feature_vector = self.features_to_vector(features)
        
        try:
            # Get probability of fraud class
            fraud_probability = self.ml_model.predict_proba([feature_vector])[0][1]
            return fraud_probability
        except Exception as e:
            logger.error(f"ML scoring error: {e}")
            return 0.0
    
    def determine_action(self, risk_score: float, amount: float) -> Tuple[RiskLevel, ActionType]:
        """Determine final action based on risk score and amount"""
        
        # Adjust thresholds based on transaction amount (TRA alignment)
        if amount < 100:
            low_threshold = 0.2
            medium_threshold = 0.5
        elif amount < 500:
            low_threshold = 0.15
            medium_threshold = 0.4
        else:
            low_threshold = 0.1
            medium_threshold = 0.3
        
        if risk_score >= 0.8:
            return RiskLevel.BLOCK, ActionType.BLOCK
        elif risk_score >= 0.6:
            return RiskLevel.HIGH, ActionType.STEP_UP_DOCUMENT
        elif risk_score >= medium_threshold:
            return RiskLevel.MEDIUM, ActionType.STEP_UP_BIOMETRIC
        elif risk_score >= low_threshold:
            return RiskLevel.MEDIUM, ActionType.STEP_UP_OTP
        else:
            return RiskLevel.LOW, ActionType.APPROVE
    
    def calculate_amount_zscore(self, amount: float, history: List[float]) -> float:
        """Calculate z-score of transaction amount vs user baseline"""
        if len(history) < 3:
            return 0.0
        
        mean_amount = np.mean(history)
        std_amount = np.std(history)
        
        if std_amount == 0:
            return 0.0
        
        return (amount - mean_amount) / std_amount
    
    def get_device_age_days(self, device_id: str) -> int:
        """Get device age in days"""
        first_seen = self.reputation_store.get(f"device_first_seen:{device_id}")
        if not first_seen:
            return 0
        
        return (datetime.now() - datetime.fromisoformat(first_seen)).days
    
    def is_first_time_device(self, device_id: str) -> bool:
        """Check if this is a first-time device"""
        return self.get_device_age_days(device_id) == 0
    
    def is_device_blacklisted(self, device_id: str) -> bool:
        """Check if device is blacklisted"""
        return self.reputation_store.get(f"device_blacklist:{device_id}", False)
    
    def get_transaction_velocity(self, user_history: Dict, hours: int) -> int:
        """Get transaction count in last N hours"""
        recent_transactions = user_history.get('recent_transactions', [])
        cutoff = datetime.now() - timedelta(hours=hours)
        
        return len([t for t in recent_transactions if t['timestamp'] > cutoff])
    
    def get_device_link_count(self, device_id: str) -> int:
        """Get number of accounts linked to device"""
        return self.reputation_store.get(f"device_links:{device_id}", 0)
    
    def get_3ds_success_rate(self, device_id: str) -> float:
        """Get 3DS success rate for device"""
        return self.reputation_store.get(f"device_3ds_rate:{device_id}", 0.5)
    
    def features_to_vector(self, features: Dict) -> List[float]:
        """Convert feature dict to ML model input vector"""
        # Define feature order expected by model
        feature_names = [
            'amount', 'amount_zscore', 'hour_of_day', 'day_of_week',
            'device_age_days', 'device_first_seen', 'ip_risk_score',
            'is_proxy', 'is_tor', 'bot_probability', 'keystroke_anomaly',
            'mouse_anomaly', 'transaction_velocity_1h', 'transaction_velocity_24h',
            'device_link_count', 'prior_3ds_success_rate'
        ]
        
        return [features.get(name, 0.0) for name in feature_names]
    
    def generate_reason_codes(self, rule_result: Dict, ml_score: float, 
                            features: Dict) -> List[str]:
        """Generate human-readable reason codes"""
        reasons = []
        
        # Rule-based reasons
        if 'EMULATOR_DETECTED' in rule_result['flags']:
            reasons.append('Device integrity compromised')
        if 'TOR_NETWORK' in rule_result['flags']:
            reasons.append('Anonymous network detected')
        if 'IMPOSSIBLE_TRAVEL' in rule_result['flags']:
            reasons.append('Impossible travel detected')
        if 'BOT_BEHAVIOR' in rule_result['flags']:
            reasons.append('Automated behavior detected')
        if 'NEW_DEVICE_HIGH_AMOUNT' in rule_result['flags']:
            reasons.append('New device with high amount')
        
        # ML-based reasons (simplified interpretation)
        if ml_score > 0.5:
            if features.get('amount_zscore', 0) > 2:
                reasons.append('Amount significantly above user baseline')
            if features.get('transaction_velocity_1h', 0) > 5:
                reasons.append('High transaction velocity')
            if features.get('device_first_seen', 0) == 1:
                reasons.append('First-time device')
        
        return reasons if reasons else ['Standard risk assessment']
    
    def update_reputation(self, device_id: str, user_id: str, 
                         outcome: str, timestamp: datetime):
        """Update device and user reputation based on outcome"""
        
        # Update device first-seen
        if not self.reputation_store.get(f"device_first_seen:{device_id}"):
            self.reputation_store[f"device_first_seen:{device_id}"] = timestamp.isoformat()
        
        # Update device-user links
        current_links = self.reputation_store.get(f"device_links:{device_id}", 0)
        self.reputation_store[f"device_links:{device_id}"] = current_links + 1
        
        # Update 3DS success rate
        if outcome in ['approved', 'step_up_success']:
            current_rate = self.reputation_store.get(f"device_3ds_rate:{device_id}", 0.5)
            # Simple moving average update
            new_rate = (current_rate * 0.9) + (1.0 * 0.1)
            self.reputation_store[f"device_3ds_rate:{device_id}"] = new_rate
        elif outcome == 'declined':
            current_rate = self.reputation_store.get(f"device_3ds_rate:{device_id}", 0.5)
            new_rate = (current_rate * 0.9) + (0.0 * 0.1)
            self.reputation_store[f"device_3ds_rate:{device_id}"] = new_rate
        
        logger.info(f"Updated reputation for device {device_id}, outcome: {outcome}")


# Integration with payment flow
class FraudCheckService:
    """Service to integrate fraud checking with payment flow"""
    
    def __init__(self):
        self.risk_analyzer = TransactionRiskAnalyzer()
        
    def check_transaction_risk(self, payment_data: Dict, 
                             device_data: Dict, 
                             user_context: Dict) -> Dict:
        """
        Main entry point for fraud checking during payment flow
        """
        try:
            # Convert input data to internal formats
            transaction = TransactionContext(
                amount=payment_data['amount'],
                currency=payment_data.get('currency', 'EUR'),
                merchant_category=payment_data.get('merchant_category', 'unknown'),
                recipient_country=payment_data.get('recipient_country', 'unknown'),
                user_id=user_context['user_id'],
                session_id=user_context['session_id'],
                timestamp=datetime.now(),
                last_sca_time=user_context.get('last_sca_time')
            )
            
            device = DeviceFingerprint(
                device_id=device_data['device_id'],
                os=device_data['os'],
                os_version=device_data['os_version'],
                is_rooted=device_data.get('is_rooted', False),
                is_emulator=device_data.get('is_emulator', False),
                ip_address=device_data['ip_address'],
                user_agent=device_data['user_agent'],
                behavioral_metrics=device_data.get('behavioral_metrics', {})
            )
            
            user_history = self.get_user_history(user_context['user_id'])
            
            # Perform risk assessment
            result = self.risk_analyzer.assess_transaction_risk(
                transaction, device, user_history
            )
            
            # Log the assessment
            self.log_risk_assessment(transaction, device, result)
            
            # Return result in API format
            return {
                'risk_score': result.risk_score,
                'risk_level': result.risk_level.value,
                'action': result.recommended_action.value,
                'reason_codes': result.reason_codes,
                'fraud_indicators': result.fraud_indicators,
                'require_3ds': result.recommended_action != ActionType.APPROVE,
                'challenge_type': self.map_action_to_challenge(result.recommended_action)
            }
            
        except Exception as e:
            logger.error(f"Error in fraud check: {e}")
            # Fail secure - require step-up if error occurs
            return {
                'risk_score': 0.5,
                'risk_level': 'medium',
                'action': 'step_up_otp',
                'reason_codes': ['Risk assessment error'],
                'fraud_indicators': [],
                'require_3ds': True,
                'challenge_type': 'otp'
            }
    
    def get_user_history(self, user_id: str) -> Dict:
        """Get user transaction history and patterns"""
        # This would query your database for user history
        return {
            'amount_history': [100.0, 150.0, 200.0],  # Recent amounts
            'recent_transactions': [],  # Recent transaction timestamps
            'last_location': None,  # Last known location
            'last_transaction_time': None  # Last transaction time
        }
    
    def map_action_to_challenge(self, action: ActionType) -> Optional[str]:
        """Map internal action to 3DS challenge type"""
        mapping = {
            ActionType.APPROVE: None,
            ActionType.STEP_UP_OTP: 'otp',
            ActionType.STEP_UP_BIOMETRIC: 'biometric',
            ActionType.STEP_UP_DOCUMENT: 'document_verification',
            ActionType.BLOCK: 'block',
            ActionType.REVIEW: 'manual_review'
        }
        return mapping.get(action)
    
    def log_risk_assessment(self, transaction: TransactionContext, 
                           device: DeviceFingerprint, 
                           result: RiskAssessmentResult):
        """Log risk assessment for audit and model training"""
        audit_record = {
            'timestamp': datetime.now().isoformat(),
            'transaction_id': transaction.session_id,
            'user_id': transaction.user_id,
            'device_id': device.device_id,
            'amount': transaction.amount,
            'currency': transaction.currency,
            'risk_score': result.risk_score,
            'risk_level': result.risk_level.value,
            'action': result.recommended_action.value,
            'rule_flags': result.rule_flags,
            'reason_codes': result.reason_codes,
            'fraud_indicators': result.fraud_indicators,
            'ml_features': result.ml_features
        }
        
        # Log to audit system
        logger.info(f"Risk assessment: {json.dumps(audit_record)}")
        
        # Store for model training and analysis
        # self.store_audit_record(audit_record)
    
    # def update_outcome(self, session_id: str, outcome: str):
    #     """Update risk assessment with actual outcome for learning"""
    #     # This would be called after payment completion
    #     # to update reputation and model training data
    #     pass