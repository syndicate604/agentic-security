import bcrypt
import jwt
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Union

class TokenError(Exception):
    """Custom exception for token-related errors"""
    pass

def authenticate_user(username: str, password: str, stored_hash: bytes) -> bool:
    """Secure authentication with bcrypt"""
    if not isinstance(password, str) or not isinstance(stored_hash, bytes):
        return False
    try:
        return bcrypt.checkpw(password.encode(), stored_hash)
    except Exception:
        return False

def hash_password(password: str) -> bytes:
    """Secure password hashing with bcrypt"""
    if not isinstance(password, str):
        raise ValueError("Password must be a string")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def generate_token(user_data: Dict, expiry_hours: int = 24) -> Tuple[str, str]:
    """Secure token generation with proper secret and expiration"""
    if not isinstance(user_data, dict):
        raise ValueError("User data must be a dictionary")
    
    # Create a safe copy of user data
    safe_data = {
        'user_id': str(user_data.get('user_id', '')),
        'username': str(user_data.get('username', '')),
        'role': str(user_data.get('role', 'user'))
    }
    
    secret = secrets.token_hex(32)
    safe_data['exp'] = datetime.utcnow() + timedelta(hours=expiry_hours)
    token = jwt.encode(safe_data, secret, algorithm='HS256')
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
        data = jwt.decode(token, secret, algorithms=['HS256'])
        
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
