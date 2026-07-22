import os
import datetime
import hashlib
import secrets
import jwt

JWT_SECRET = os.environ.get("JWT_SECRET", "f3a74932d8471c6d2d421a8d11cbe812dfa149c71b00e34a6ef5a882a8848fef")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    pwd_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    hashed = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt_bytes, 100000)
    return f"pbkdf2_sha256$100000${salt}${hashed.hex()}"

def verify_password(password: str, hashed_password: str) -> bool:
    if not hashed_password or '$' not in hashed_password:
        return False
    try:
        parts = hashed_password.split('$')
        if len(parts) != 4:
            return False
        algo, iterations, salt, hash_hex = parts
        if algo != 'pbkdf2_sha256':
            return False
        pwd_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        hashed = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt_bytes, int(iterations))
        return secrets.compare_digest(hashed.hex(), hash_hex)
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: datetime.timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
