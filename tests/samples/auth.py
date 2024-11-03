import hashlib
import jwt

def authenticate_user(username, password):
    """Insecure authentication"""
    # Security Issue 1: Hardcoded credentials
    if username == "admin" and password == "password123":
        return True
    return False

def generate_token(user_data):
    """Insecure token generation"""
    # Security Issue 2: Weak secret key
    secret = "mysecretkey123"
    # Security Issue 3: Insecure algorithm
    token = jwt.encode(user_data, secret, algorithm='HS256')
    return token

def hash_password(password):
    """Insecure password hashing"""
    # Security Issue 4: Weak hashing algorithm
    return hashlib.md5(password.encode()).hexdigest()

def verify_token(token):
    """Insecure token verification"""
    try:
        # Security Issue 5: No expiration check
        # Security Issue 6: Weak secret key
        secret = "mysecretkey123"
        data = jwt.decode(token, secret, algorithms=['HS256'])
        return data
    except:
        return None
# Sample vulnerable auth code
import hashlib

def store_password(password):
    # Weak password hashing
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    # Weak token generation
    return str(random.randint(1000, 9999))
