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

# Rate limiting storage
_auth_attempts = {}
_MAX_ATTEMPTS = 5
_LOCKOUT_TIME = 300  # 5 minutes in seconds

def _check_rate_limit(username: str) -> None:
    """Check if authentication attempts are within allowed limits"""
    current_time = time()
    if username in _auth_attempts:
        attempts, lockout_time = _auth_attempts[username]
        if current_time < lockout_time:
            raise AuthenticationError("Too many attempts. Please try again later.")
        if current_time - lockout_time > _LOCKOUT_TIME:
            _auth_attempts[username] = (1, current_time)
        else:
            if attempts >= _MAX_ATTEMPTS:
                _auth_attempts[username] = (attempts, current_time)
                raise AuthenticationError("Too many attempts. Please try again later.")
            _auth_attempts[username] = (attempts + 1, current_time)
    else:
        _auth_attempts[username] = (1, current_time)

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

def generate_token(user_data: Dict, expiry_hours: int = 24) -> Tuple[str, str]:
    """Secure token generation with enhanced security measures"""
    if not isinstance(user_data, dict):
        raise ValueError("User data must be a dictionary")
    if not isinstance(expiry_hours, int) or expiry_hours <= 0:
        raise ValueError("Expiry hours must be a positive integer")
        
    # Create a safe copy of user data with strict validation
    required_fields = {'user_id', 'username', 'role'}
    if not all(field in user_data for field in required_fields):
        raise ValueError("Missing required user data fields")
        
    safe_data = {
        'user_id': str(user_data['user_id']),
        'username': str(user_data['username']),
        'role': str(user_data['role']),
        'jti': secrets.token_hex(16),  # Add unique token ID
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=expiry_hours),
        'nbf': datetime.utcnow()  # Not valid before current time
    }
    
    # Use stronger secret generation
    secret = secrets.token_bytes(64)  # 512-bit secret
    
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
