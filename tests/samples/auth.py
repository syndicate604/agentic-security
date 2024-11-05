import bcrypt
import jwt
import re
import secrets
import hmac
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Union
from functools import wraps
from time import time

class TokenError(Exception):
    """Custom exception for token-related errors"""
    pass

class AuthenticationError(Exception):
    """Custom exception for authentication-related errors"""
    pass

import logging
from redis import Redis
from typing import Optional

# Secure configuration
_MAX_ATTEMPTS = 5
_LOCKOUT_TIME = 300  # 5 minutes in seconds
_REDIS_KEY_PREFIX = "auth_attempt:"

# Setup secure logging
logger = logging.getLogger('security')
logger.setLevel(logging.INFO)

# Redis connection for rate limiting
_redis_client: Optional[Redis] = None

def _get_redis() -> Redis:
    """Get Redis connection with lazy initialization"""
    global _redis_client
    if _redis_client is None:
        _redis_client = Redis(host='localhost', port=6379, db=0, ssl=True)
    return _redis_client

def _check_rate_limit(username: str) -> None:
    """Check if authentication attempts are within allowed limits using Redis"""
    if not isinstance(username, str) or not username.strip():
        raise AuthenticationError("Invalid username format")
        
    redis_key = f"{_REDIS_KEY_PREFIX}{username}"
    redis = _get_redis()
    
    try:
        attempts = int(redis.get(redis_key) or 0)
        current_time = time()
        
        if attempts >= _MAX_ATTEMPTS:
            lockout_remaining = redis.ttl(redis_key)
            if lockout_remaining > 0:
                logger.warning(f"Rate limit exceeded for user: {username}")
                raise AuthenticationError(
                    f"Account temporarily locked. Try again in {lockout_remaining} seconds."
                )
        
        # Increment attempts and set expiry
        redis.incr(redis_key)
        redis.expire(redis_key, _LOCKOUT_TIME)
        
    except (ValueError, ConnectionError) as e:
        logger.error(f"Rate limiting error: {str(e)}")
        raise AuthenticationError("Service temporarily unavailable")

def authenticate_user(username: str, password: str, stored_hash: bytes) -> bool:
    """Secure authentication with bcrypt and rate limiting"""
    if not isinstance(password, str) or not isinstance(stored_hash, bytes):
        raise AuthenticationError("Invalid input format")
        
    try:
        _check_rate_limit(username)
        # Use constant-time comparison
        is_valid = hmac.compare_digest(
            bcrypt.hashpw(password.encode(), stored_hash),
            stored_hash
        )
        if not is_valid:
            raise AuthenticationError("Invalid credentials")
        return True
    except AuthenticationError:
        raise
    except Exception as e:
        raise AuthenticationError("Authentication failed")

def hash_password(password: str) -> bytes:
    """Secure password hashing with bcrypt and validation"""
    if not isinstance(password, str):
        raise ValueError("Password must be a string")
        
    # Validate password complexity
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long")
    if not re.search(r'[A-Z]', password):
        raise ValueError("Password must contain uppercase letters")
    if not re.search(r'[a-z]', password):
        raise ValueError("Password must contain lowercase letters")
    if not re.search(r'\d', password):
        raise ValueError("Password must contain numbers")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValueError("Password must contain special characters")
        
    # Use stronger work factor for bcrypt
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt)

def generate_token(user_data: Dict, expiry_hours: int = 24, audience: str = None) -> Tuple[str, str]:
    """
    Secure token generation with enhanced security measures and claims
    
    Args:
        user_data: User information dictionary
        expiry_hours: Token validity period in hours
        audience: Expected token audience (e.g., 'web', 'mobile')
    """
    if not isinstance(user_data, dict):
        raise ValueError("User data must be a dictionary")
    if not isinstance(expiry_hours, int) or expiry_hours <= 0:
        raise ValueError("Expiry hours must be a positive integer")
    if audience and not isinstance(audience, str):
        raise ValueError("Audience must be a string")
        
    # Create a safe copy of user data with strict validation
    required_fields = {'user_id', 'username', 'role'}
    if not all(field in user_data for field in required_fields):
        raise ValueError("Missing required user data fields")
    
    current_time = datetime.utcnow()
    safe_data = {
        'user_id': str(user_data['user_id']),
        'username': str(user_data['username']),
        'role': str(user_data['role']),
        'jti': secrets.token_hex(32),  # Increased to 256-bit unique ID
        'iat': current_time,
        'exp': current_time + timedelta(hours=expiry_hours),
        'nbf': current_time,
        'iss': 'auth_service',  # Token issuer
        'aud': audience or 'default',  # Token audience
        'sub': str(user_data['user_id']),  # Token subject
        'ip': user_data.get('ip_address'),  # Client IP if available
        'device': user_data.get('device_info'),  # Device information
    }
    
    # Use secure key management
    secret = _get_or_generate_secret()
    
    # Use more secure JWT options with additional headers
    token = jwt.encode(
        safe_data,
        secret,
        algorithm='HS512',
        headers={
            'kid': secrets.token_hex(8),
            'typ': 'JWT',
            'cty': 'JWT',
            'alg': 'HS512',
            'enc': 'none'
        }
    )
    return token, secret

def verify_token(token: str, secret: str) -> Optional[Dict]:
    """
    Secure token verification with expiration check and safe deserialization
    
    Args:
        token: JWT token string
        secret: Secret key used for token verification
        
    Returns:
        Dict containing verified token data or None if verification fails
        
    Raises:
        TokenError: If token format or content is invalid
    """
    if not isinstance(token, str) or not isinstance(secret, str):
        raise TokenError("Invalid token or secret format")
        
    try:
        # Decode with explicit type verification
        data = jwt.decode(
            token, 
            secret, 
            algorithms=['HS512'],
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_nbf': True,
                'verify_iat': True,
                'verify_aud': True,
                'require': ['exp', 'iat', 'nbf']
            }
        )
        
        # Validate expected data structure
        if not isinstance(data, dict):
            raise TokenError("Invalid token payload structure")
            
        # Verify required fields and types
        required_fields = {
            'user_id': str,
            'username': str,
            'role': str,
            'exp': (int, float)  # exp can be int or float timestamp
        }
        
        for field, expected_type in required_fields.items():
            if field not in data:
                raise TokenError(f"Missing required field: {field}")
            if not isinstance(data[field], expected_type):
                raise TokenError(f"Invalid type for field: {field}")
                
        return data
        
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception as e:
        raise TokenError(f"Token verification failed: {str(e)}")
import os
import secrets
from cryptography.fernet import Fernet
from pathlib import Path

class KeyManager:
    """Secure key management for authentication tokens"""
    
    _instance = None
    _KEY_FILE = "secret.key"
    _KEY_DIR = Path("/opt/secure/keys")
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        self._key_path = self._KEY_DIR / self._KEY_FILE
        self._current_key = None
        self._fernet = None
        self._initialize()
    
    def _initialize(self):
        """Initialize key storage with secure permissions"""
        if not self._KEY_DIR.exists():
            self._KEY_DIR.mkdir(parents=True, mode=0o700)
        
        if not self._key_path.exists():
            self._generate_new_key()
        else:
            self._load_key()
    
    def _generate_new_key(self):
        """Generate and store a new secret key"""
        key = secrets.token_bytes(64)  # 512-bit key
        
        # Encrypt the key before storing
        if not self._fernet:
            self._fernet = Fernet(Fernet.generate_key())
        
        encrypted_key = self._fernet.encrypt(key)
        
        # Secure file permissions
        with open(self._key_path, 'wb') as f:
            f.write(encrypted_key)
        os.chmod(self._key_path, 0o600)
        
        self._current_key = key
    
    def _load_key(self):
        """Load the existing secret key"""
        try:
            with open(self._key_path, 'rb') as f:
                encrypted_key = f.read()
            
            if not self._fernet:
                self._fernet = Fernet(Fernet.generate_key())
                
            self._current_key = self._fernet.decrypt(encrypted_key)
            
        except Exception as e:
            raise RuntimeError(f"Failed to load secret key: {str(e)}")
    
    def get_current_key(self) -> bytes:
        """Get the current secret key"""
        if not self._current_key:
            self._load_key()
        return self._current_key
    
    def rotate_key(self) -> None:
        """Rotate the secret key"""
        self._generate_new_key()

# Global key manager instance
_key_manager = KeyManager()

def _get_or_generate_secret() -> bytes:
    """Get the current secret key or generate a new one"""
    return _key_manager.get_current_key()
