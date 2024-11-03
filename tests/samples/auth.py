import bcrypt
import jwt
import secrets
from datetime import datetime, timedelta

def authenticate_user(username, password, stored_hash):
    """Secure authentication with bcrypt"""
    try:
        return bcrypt.checkpw(password.encode(), stored_hash)
    except Exception:
        return False

def generate_token(user_data, expiry_hours=24):
    """Secure token generation with proper secret and expiration"""
    secret = secrets.token_hex(32)  # Generate secure secret key
    user_data['exp'] = datetime.utcnow() + timedelta(hours=expiry_hours)
    token = jwt.encode(user_data, secret, algorithm='HS256')
    return token, secret

def hash_password(password):
    """Secure password hashing with bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def verify_token(token, secret):
    """Secure token verification with expiration check"""
    try:
        data = jwt.decode(token, secret, algorithms=['HS256'])
        # Expiration is automatically checked by jwt.decode
        return data
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
import hashlib

def hash_password(password):
    # Weak password hashing
    return hashlib.md5(password.encode()).hexdigest()

def verify_token(token):
    # Weak token validation
    return len(token) > 10

def generate_token():
    # Predictable token generation
    import time
    return str(time.time())
