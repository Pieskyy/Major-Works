import sqlite3 as sql

from hash import encode, check_password, make_web_safe, password_bytes


# Ensure database schema exists for users
def _ensure_schema():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY autoincrement, username TEXT NOT NULL, password TEXT NOT NULL, dateOfBirth TEXT, twofa_secret TEXT)"
    )
    con.commit()
    con.close()


# Ensure schema on import
_ensure_schema()


# USER MANAGEMENT
def insertUser(username, password, DoB): # Insert user with hashed password, SQL injection safe
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    
    # Check if username already exists - PREVENT DUPLICATES
    cur.execute("SELECT username FROM users WHERE username = ?", (username,))
    if cur.fetchone() is not None:
        con.close()
        raise ValueError("Username already exists. Please choose a different username.")
    
    hashed_password = encode(password)  # HASHING
    cur.execute("INSERT INTO users (username, password, dateOfBirth) VALUES (?, ?, ?)",
        (username, hashed_password, DoB),
    )
    con.commit()
    con.close()

def retrieveUsers(username, password): # Retrieve user and check password, SQL injection safe
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = cur.fetchone()
    if result is None:
        con.close()
        return False
    storedHash = result[0]
    if isinstance(storedHash, (bytes, bytearray)):
        storedHash = storedHash.decode("utf-8", errors="ignore")
    match = check_password(storedHash, password)  # HASHING check
    con.close()
    return match

def getUserTwoFASecret(username): # 2Fa
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("SELECT twofa_secret FROM users WHERE username = ?", (username,))
    result = cur.fetchone()
    con.close()
    if result and result[0]:
        return result[0]
    return None

def setUserTwoFASecret(username, secret): # 2FA
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("UPDATE users SET twofa_secret = ? WHERE username = ?", (secret, username))
    con.commit()
    con.close()

def validate_password(password): # Password validation with exceptions
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one number")
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        raise ValueError("Password must contain at least one special character")
