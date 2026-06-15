import bcrypt
import re
import html

# HASHING
def encode(password):
    password_bytes = password.encode("utf-8")
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed.decode("utf-8")

def check_password(hashed, entered): # Returns True if password matches hash
    try:
        if isinstance(entered, str):
            entered = entered.encode("utf-8")
        if isinstance(hashed, str):
            hashed = hashed.encode("utf-8")
        return bcrypt.checkpw(entered, hashed)
    except (ValueError, TypeError, AttributeError):
        return False

# PASSWORD VALIDATION 
def simple_check_password(password: str) -> bool: # Criteria check for password
    if not isinstance(password, str):
        return False
    if len(password) < 8 or len(password) > 20:
        return False
    if re.search(r"[ ]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[@$!%*?&]", password):
        return False
    return True

def password_bytes(password: str) -> bytes: # Convert password to bytes for hashing (if criteria met)
    if not isinstance(password, str):
        raise TypeError("Expected string")
    if len(password) < 8:
        raise ValueError("Too short")
    if len(password) > 20:
        raise ValueError("Too long")
    if re.search(r"[ ]", password):
        raise ValueError("Contains space")
    if not re.search(r"[A-Z]", password):
        raise ValueError("No uppercase")
    if not re.search(r"[a-z]", password):
        raise ValueError("No lowercase")
    if not re.search(r"[0-9]", password):
        raise ValueError("No digit")
    if not re.search(r"[@$!%*?&]", password):
        raise ValueError("No special char")
    return password.encode()

# XSS / Sanitization
def make_web_safe(string: str) -> str: # Simple sanitization using html.escape, html.escape is sufficient for basic XSS prevention in this context
    return html.escape(string)