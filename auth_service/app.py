import datetime
import hashlib
import logging
import os
import re
import secrets
import time
import uuid
from typing import Optional, Tuple

import jwt
import psycopg2
import requests
from flask import Flask, jsonify, request, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from psycopg2 import OperationalError
from werkzeug.security import check_password_hash, generate_password_hash

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static')

# Security: Limit request size (prevent DoS)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB

# Config
DATABASE_URL = os.environ.get("DATABASE_URL")
SECRET_KEY = os.environ.get("SECRET_KEY")
RECAPTCHA_SECRET_KEY = os.environ.get("RECAPTCHA_SECRET_KEY", "")
VERIFICATION_SERVICE_URL = os.environ.get("VERIFICATION_SERVICE_URL", "http://verification_service:5000")
MFA_SERVICE_URL = os.environ.get("MFA_SERVICE_URL", "http://mfa_service:5000")

# Rate Limiter Setup (in-memory storage for simplicity)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


# ==================== RECAPTCHA VERIFICATION ====================

def verify_recaptcha(recaptcha_response):
    """
    Verify reCAPTCHA response with Google's API.
    Returns True if valid, False otherwise.
    """
    if not RECAPTCHA_SECRET_KEY:
        # If no secret key configured, skip verification (dev mode)
        logger.warning("reCAPTCHA secret key not configured, skipping verification")
        return True
    
    if not recaptcha_response:
        logger.debug("reCAPTCHA token is empty")
        return False
    
    try:
        logger.debug("Verifying reCAPTCHA token with Google API")
        result = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={
                "secret": RECAPTCHA_SECRET_KEY,
                "response": recaptcha_response,
                "remoteip": request.remote_addr
            },
            timeout=5
        )
        response_data = result.json()
        # Only log success status, not full response (avoid leaking sensitive data)
        logger.debug(f"reCAPTCHA verification result: {response_data.get('success', False)}")
        return response_data.get("success", False)
    except Exception as e:
        logger.error(f"reCAPTCHA verification error: {e}")
        return False



# ==================== INPUT VALIDATION ====================

def validate_username(username: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Validate username: 3-30 characters, alphanumeric and underscore only.
    
    Args:
        username: The username to validate.
        
    Returns:
        Tuple of (is_valid, error_message). error_message is None if valid.
    """
    if not username:
        return False, "Username is required"
    
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    
    if len(username) > 30:
        return False, "Username must not exceed 30 characters"
    
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    
    return True, None


def validate_password(password: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Validate password: 15+ chars with complexity requirements.
    
    Args:
        password: The password to validate.
        
    Returns:
        Tuple of (is_valid, error_message). error_message is None if valid.
    """
    if not password:
        return False, "Password is required"
    
    if len(password) < 15:
        return False, "Password must be at least 15 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/~`]', password):
        return False, "Password must contain at least one special character"
    
    return True, None


def validate_email(email: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Validate email format using RFC 5322 compliant regex.
    
    Args:
        email: The email address to validate.
        
    Returns:
        Tuple of (is_valid, error_message). error_message is None if valid.
    """
    if not email:
        return False, "Email is required"
    
    # RFC 5322 compliant email regex (simplified but robust)
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    
    if len(email) > 254:
        return False, "Email must not exceed 254 characters"
    
    return True, None


# ==================== DATABASE ====================

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn


def init_db():
    """Initialize all auth tables if they don't exist."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Create users table with email and role fields
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                email VARCHAR(254) NOT NULL,
                password_hash TEXT NOT NULL,
                role VARCHAR(20) DEFAULT 'user' NOT NULL
            );
        """)
        
        # Add role column if it doesn't exist (for existing installations)
        cur.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users' AND column_name = 'role'
                ) THEN
                    ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'user' NOT NULL;
                END IF;
            END $$;
        """)
        
        # Create refresh tokens table for session management
        cur.execute("""
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token_hash VARCHAR(128) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                revoked BOOLEAN DEFAULT FALSE,
                user_agent TEXT,
                ip_address VARCHAR(45)
            );
            CREATE INDEX IF NOT EXISTS idx_refresh_token_hash ON refresh_tokens(token_hash);
            CREATE INDEX IF NOT EXISTS idx_refresh_user_id ON refresh_tokens(user_id);
        """)
        
        # Create token blacklist for logout before JWT expiry
        cur.execute("""
            CREATE TABLE IF NOT EXISTS token_blacklist (
                id SERIAL PRIMARY KEY,
                jti VARCHAR(64) UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_blacklist_jti ON token_blacklist(jti);
        """)
        
        # Create password reset tokens table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                email VARCHAR(254) NOT NULL,
                token_hash VARCHAR(128) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE
            );
            CREATE INDEX IF NOT EXISTS idx_reset_token_hash ON password_reset_tokens(token_hash);
        """)
        
        conn.commit()
        cur.close()
        conn.close()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Error initializing DB: {e}")


# Run DB init on startup
with app.app_context():
    # Wait for DB to be ready in a real scenario, or let Docker restart handle it
    pass
    # Note: In production, use migrations (Alembic). For this simple setup,
    # we will call init_db inside the request or a pre-start script.
    # To keep it simple here, we'll try to init on first request or just rely on manual init.
    # Better yet, let's just run it:
    # (In a real container, this might fail if DB isn't up yet, but Docker restart policy helps)


# ==================== TOKEN MANAGEMENT ====================

# Token expiry constants
ACCESS_TOKEN_EXPIRY_MINUTES = 15
REFRESH_TOKEN_EXPIRY_DAYS = 7
PASSWORD_RESET_TOKEN_EXPIRY_HOURS = 1


def hash_token(token: str) -> str:
    """Hash a token for secure storage using SHA-256."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_access_token(user_id, username, role='user'):
    """Generate a short-lived JWT access token with JTI for blacklisting."""
    jti = str(uuid.uuid4())
    token = jwt.encode(
        {
            "user_id": user_id,
            "username": username,
            "role": role,
            "jti": jti,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRY_MINUTES),
            "iat": datetime.datetime.utcnow(),
        },
        SECRET_KEY,
        algorithm="HS256",
    )
    return token, jti


def generate_refresh_token(user_id, user_agent=None, ip_address=None):
    """Generate a cryptographically secure refresh token and store in database."""
    token = secrets.token_urlsafe(48)
    token_hash = hash_token(token)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS)
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent, ip_address)
               VALUES (%s, %s, %s, %s, %s)""",
            (user_id, token_hash, expires_at, user_agent, ip_address)
        )
        conn.commit()
        cur.close()
        conn.close()
        return token
    except Exception as e:
        logger.error(f"Error generating refresh token: {e}")
        return None


def verify_refresh_token(token):
    """Verify a refresh token and return user_id if valid."""
    token_hash = hash_token(token)
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """SELECT user_id, expires_at, revoked FROM refresh_tokens
               WHERE token_hash = %s""",
            (token_hash,)
        )
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        if not result:
            return None, "Invalid refresh token"
        
        user_id, expires_at, revoked = result
        
        if revoked:
            return None, "Token has been revoked"
        
        if expires_at < datetime.datetime.utcnow():
            return None, "Token has expired"
        
        return user_id, None
    except Exception as e:
        logger.error(f"Error verifying refresh token: {e}")
        return None, "Token verification failed"


def revoke_refresh_token(token):
    """Revoke a single refresh token."""
    token_hash = hash_token(token)
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = %s",
            (token_hash,)
        )
        conn.commit()
        cur.close()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error revoking refresh token: {e}")
        return False


def revoke_all_user_tokens(user_id):
    """Revoke all refresh tokens for a user (logout all sessions)."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = %s AND revoked = FALSE",
            (user_id,)
        )
        conn.commit()
        cur.close()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error revoking all user tokens: {e}")
        return False


def blacklist_access_token(jti, expires_at):
    """Add a JWT ID to the blacklist."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO token_blacklist (jti, expires_at) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (jti, expires_at)
        )
        conn.commit()
        cur.close()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error blacklisting token: {e}")
        return False


def is_token_blacklisted(jti):
    """Check if a JWT ID is blacklisted."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM token_blacklist WHERE jti = %s", (jti,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        return result is not None
    except Exception as e:
        logger.error(f"Error checking token blacklist: {e}")
        return True  # Fail-closed: assume blacklisted on error


def generate_password_reset_token(user_id, email):
    """Generate a password reset token."""
    token = secrets.token_urlsafe(48)
    token_hash = hash_token(token)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=PASSWORD_RESET_TOKEN_EXPIRY_HOURS)
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Invalidate any existing unused tokens for this user
        cur.execute(
            "UPDATE password_reset_tokens SET used = TRUE WHERE user_id = %s AND used = FALSE",
            (user_id,)
        )
        # Create new token
        cur.execute(
            """INSERT INTO password_reset_tokens (user_id, email, token_hash, expires_at)
               VALUES (%s, %s, %s, %s)""",
            (user_id, email, token_hash, expires_at)
        )
        conn.commit()
        cur.close()
        conn.close()
        return token
    except Exception as e:
        logger.error(f"Error generating password reset token: {e}")
        return None


def verify_password_reset_token(token):
    """Verify a password reset token and return user_id if valid."""
    token_hash = hash_token(token)
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """SELECT id, user_id, expires_at, used FROM password_reset_tokens
               WHERE token_hash = %s""",
            (token_hash,)
        )
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        if not result:
            return None, "Invalid reset token"
        
        token_id, user_id, expires_at, used = result
        
        if used:
            return None, "Token has already been used"
        
        if expires_at < datetime.datetime.utcnow():
            return None, "Token has expired"
        
        return user_id, None
    except Exception as e:
        logger.error(f"Error verifying password reset token: {e}")
        return None, "Token verification failed"


def mark_reset_token_used(token):
    """Mark a password reset token as used."""
    token_hash = hash_token(token)
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE password_reset_tokens SET used = TRUE WHERE token_hash = %s",
            (token_hash,)
        )
        conn.commit()
        cur.close()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error marking reset token as used: {e}")
        return False


def get_user_by_email(email):
    """Get user by email address."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, email FROM users WHERE email = %s",
            (email.lower(),)
        )
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        if result:
            return {"id": result[0], "username": result[1], "email": result[2]}
        return None
    except Exception as e:
        logger.error(f"Error getting user by email: {e}")
        return None


def update_user_password(user_id, new_password_hash):
    """Update a user's password."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (new_password_hash, user_id)
        )
        conn.commit()
        cur.close()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error updating user password: {e}")
        return False


# ==================== STATIC FILE SERVING ====================

@app.route("/static/")
@app.route("/static/index.html")
def serve_index():
    """Serve the auth frontend index page."""
    return send_from_directory('static', 'index.html')


@app.route("/static/<path:subpath>")
def serve_static(subpath):
    """Serve static files (CSS, JS) for auth frontend."""
    return send_from_directory('static', subpath)


@app.route("/health", methods=["GET"])
def health_check():
    status = {"service": "auth_service", "database": "unknown"}
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1;")
        cur.close()
        conn.close()
        status["database"] = "connected"
        return jsonify(status), 200
    except OperationalError as e:
        status["database"] = "disconnected"
        status["error"] = str(e)
        return jsonify(status), 500


@app.route("/auth/register", methods=["POST"])
@limiter.limit("3 per minute")
def register():
    data = request.json
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    # Verify reCAPTCHA first
    recaptcha_response = data.get("recaptcha_token", "")
    if not verify_recaptcha(recaptcha_response):
        return jsonify({"error": "reCAPTCHA verification failed"}), 400
    
    username = data.get("username", "").strip()
    password = data.get("password", "")
    email = data.get("email", "").strip().lower()

    # Validate all inputs
    errors = []
    
    is_valid, error = validate_username(username)
    if not is_valid:
        errors.append(error)
    
    is_valid, error = validate_password(password)
    if not is_valid:
        errors.append(error)
    
    is_valid, error = validate_email(email)
    if not is_valid:
        errors.append(error)
    
    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 400

    # 1. Init DB ensures table exists (lazy initialization for simplicity)
    init_db()

    # 2. Hash the password
    hashed_password = generate_password_hash(password)

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # 3. Insert user with email
        cur.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id;",
            (username, email, hashed_password),
        )
        user_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        
        # 4. Send verification email via verification_service
        try:
            verify_response = requests.post(
                f"{VERIFICATION_SERVICE_URL}/verify/send",
                json={"user_id": user_id, "email": email, "username": username},
                timeout=10
            )
            if verify_response.status_code != 200:
                logger.warning(f"Failed to send verification email: {verify_response.status_code}")
        except Exception as e:
            logger.error(f"Error calling verification service: {e}")
        
        return jsonify({
            "message": "User created. Please check your email to verify your account.",
            "user_id": user_id,
            "verification_required": True
        }), 201
    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "Username already exists"}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/auth/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.json
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    # Verify reCAPTCHA first
    recaptcha_response = data.get("recaptcha_token", "")
    if not verify_recaptcha(recaptcha_response):
        return jsonify({"error": "reCAPTCHA verification failed"}), 400
    
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # 1. Fetch user with role
        cur.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = %s;",
            (username,),
        )
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user:
            stored_hash = user[2]
            user_role = user[3] if len(user) > 3 else 'user'
            # 2. Check Password
            if check_password_hash(stored_hash, password):
                # 3. Check if email is verified
                try:
                    verify_response = requests.get(
                        f"{VERIFICATION_SERVICE_URL}/verify/status/{user[0]}",
                        timeout=5
                    )
                    if verify_response.status_code == 200:
                        verify_data = verify_response.json()
                        if not verify_data.get("verified", False):
                            return jsonify({
                                "error": "Email not verified. Please check your email for the verification link.",
                                "verification_required": True,
                                "user_id": user[0]
                            }), 403
                    else:
                        # Fail-closed: if verification service returns error, deny login
                        logger.error(f"Verification service returned status {verify_response.status_code}")
                        return jsonify({
                            "error": "Unable to verify account status. Please try again later."
                        }), 503
                except Exception as e:
                    # Fail-closed: deny login if verification service is unavailable
                    logger.error(f"Verification service unavailable: {e}")
                    return jsonify({
                        "error": "Unable to verify account status. Please try again later."
                    }), 503
                
                # 4. Check if MFA is enabled for this user
                try:
                    mfa_response = requests.get(
                        f"{MFA_SERVICE_URL}/mfa/status/{user[0]}",
                        timeout=5
                    )
                    if mfa_response.status_code == 200:
                        mfa_data = mfa_response.json()
                        if mfa_data.get("mfa_enabled", False):
                            # MFA is enabled - return partial auth requiring MFA verification
                            # Generate a temporary MFA token (short-lived)
                            mfa_token = jwt.encode(
                                {
                                    "user_id": user[0],
                                    "username": user[1],
                                    "mfa_pending": True,
                                    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
                                    "iat": datetime.datetime.utcnow(),
                                },
                                SECRET_KEY,
                                algorithm="HS256",
                            )
                            return jsonify({
                                "message": "MFA verification required",
                                "mfa_required": True,
                                "mfa_token": mfa_token,
                                "user": username
                            }), 200
                except Exception as e:
                    # If MFA service is down, allow login without MFA (fail-open for MFA)
                    # This is a design choice - could also be fail-closed
                    logger.warning(f"MFA service unavailable, proceeding without MFA: {e}")
                
                # 5. Generate tokens (only if verified and no MFA required)
                access_token, jti = generate_access_token(user[0], user[1], user_role)
                
                # Generate refresh token
                user_agent = request.headers.get("User-Agent", "")[:500]  # Limit length
                ip_address = request.remote_addr
                refresh_token = generate_refresh_token(user[0], user_agent, ip_address)
                
                if not refresh_token:
                    logger.error("Failed to generate refresh token")
                    return jsonify({"error": "Login failed. Please try again."}), 500

                return jsonify({
                    "message": "Login successful",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "Bearer",
                    "expires_in": ACCESS_TOKEN_EXPIRY_MINUTES * 60,
                    "user": username
                }), 200

        # Add delay on failed login to slow down brute-force attacks
        time.sleep(0.5)
        return jsonify({"error": "Invalid credentials"}), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/auth/login/mfa", methods=["POST"])
@limiter.limit("10 per minute")
def login_mfa():
    """
    Complete login after MFA verification.
    Requires the mfa_token from the initial login and a valid TOTP code.
    """
    data = request.json
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    mfa_token = data.get("mfa_token")
    totp_code = data.get("totp_code", "").strip()
    
    if not mfa_token:
        return jsonify({"error": "MFA token is required"}), 400
    if not totp_code:
        return jsonify({"error": "TOTP code is required"}), 400
    
    try:
        # Verify the MFA token
        payload = jwt.decode(mfa_token, SECRET_KEY, algorithms=["HS256"])
        
        if not payload.get("mfa_pending"):
            return jsonify({"error": "Invalid MFA token"}), 401
        
        user_id = payload.get("user_id")
        username = payload.get("username")
        
        if not user_id or not username:
            return jsonify({"error": "Invalid MFA token"}), 401
        
        # Verify the TOTP code with MFA service
        try:
            mfa_response = requests.post(
                f"{MFA_SERVICE_URL}/mfa/verify",
                json={"user_id": user_id, "totp_code": totp_code},
                timeout=10
            )
            
            if mfa_response.status_code != 200:
                mfa_data = mfa_response.json()
                error_msg = mfa_data.get("error", "MFA verification failed")
                return jsonify({"error": error_msg}), 401
            
            mfa_data = mfa_response.json()
            if not mfa_data.get("verified"):
                return jsonify({"error": "Invalid verification code"}), 401
                
        except requests.exceptions.RequestException as e:
            logger.error(f"MFA service request failed: {e}")
            return jsonify({"error": "MFA service unavailable. Please try again."}), 503
        
        # Fetch user role for token generation
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
            role_result = cur.fetchone()
            cur.close()
            conn.close()
            user_role = role_result[0] if role_result else 'user'
        except Exception as e:
            logger.error(f"Error fetching user role: {e}")
            user_role = 'user'
        
        # MFA verified successfully - generate full auth tokens
        access_token, jti = generate_access_token(user_id, username, user_role)
        
        user_agent = request.headers.get("User-Agent", "")[:500]
        ip_address = request.remote_addr
        refresh_token = generate_refresh_token(user_id, user_agent, ip_address)
        
        if not refresh_token:
            logger.error("Failed to generate refresh token after MFA")
            return jsonify({"error": "Login failed. Please try again."}), 500
        
        logger.info(f"MFA login completed successfully for user: {username}")
        
        return jsonify({
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_EXPIRY_MINUTES * 60,
            "user": username
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "MFA token has expired. Please login again."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid MFA token"}), 401
    except Exception as e:
        logger.error(f"MFA login error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/auth/logout", methods=["POST"])
@limiter.limit("10 per minute")
def logout():
    """Logout: Revoke refresh token and blacklist access token."""
    data = request.json
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    refresh_token = data.get("refresh_token")
    
    # Get access token from Authorization header
    auth_header = request.headers.get("Authorization", "")
    access_token = None
    if auth_header.startswith("Bearer "):
        access_token = auth_header[7:]
    
    # Revoke refresh token
    if refresh_token:
        revoke_refresh_token(refresh_token)
    
    # Blacklist access token if provided
    if access_token:
        try:
            # Decode without verification to get JTI and expiry
            payload = jwt.decode(access_token, SECRET_KEY, algorithms=["HS256"])
            jti = payload.get("jti")
            exp = payload.get("exp")
            if jti and exp:
                expires_at = datetime.datetime.fromtimestamp(exp)
                blacklist_access_token(jti, expires_at)
        except jwt.ExpiredSignatureError:
            # Token already expired, no need to blacklist
            pass
        except jwt.InvalidTokenError:
            # Invalid token, ignore
            pass
    
    return jsonify({"message": "Logged out successfully"}), 200


@app.route("/auth/refresh", methods=["POST"])
@limiter.limit("30 per minute")
def refresh():
    """Exchange a valid refresh token for a new access token."""
    data = request.json
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    refresh_token = data.get("refresh_token")
    if not refresh_token:
        return jsonify({"error": "Refresh token is required"}), 400
    
    # Verify refresh token
    user_id, error = verify_refresh_token(refresh_token)
    if error:
        return jsonify({"error": error}), 401
    
    # Get username and role for the user
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT username, role FROM users WHERE id = %s", (user_id,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        if not result:
            return jsonify({"error": "User not found"}), 404
        
        username = result[0]
        user_role = result[1] if len(result) > 1 else 'user'
    except Exception as e:
        logger.error(f"Error fetching user: {e}")
        return jsonify({"error": "Token refresh failed"}), 500
    
    # Generate new access token
    access_token, jti = generate_access_token(user_id, username, user_role)
    
    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRY_MINUTES * 60
    }), 200


@app.route("/auth/logout-all", methods=["POST"])
@limiter.limit("3 per minute")
def logout_all():
    """Revoke all sessions for the current user."""
    # Get access token from Authorization header
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization header required"}), 401
    
    access_token = auth_header[7:]
    
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=["HS256"])
        
        # Check if token is blacklisted
        jti = payload.get("jti")
        if jti and is_token_blacklisted(jti):
            return jsonify({"error": "Token has been revoked"}), 401
        
        user_id = payload.get("user_id")
        if not user_id:
            return jsonify({"error": "Invalid token"}), 401
        
        # Revoke all refresh tokens for this user
        if revoke_all_user_tokens(user_id):
            # Also blacklist current access token
            exp = payload.get("exp")
            if jti and exp:
                expires_at = datetime.datetime.fromtimestamp(exp)
                blacklist_access_token(jti, expires_at)
            
            return jsonify({"message": "All sessions logged out successfully"}), 200
        else:
            return jsonify({"error": "Failed to logout all sessions"}), 500
            
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


@app.route("/auth/forgot-password", methods=["POST"])
@limiter.limit("3 per minute")
def forgot_password():
    """Request a password reset email."""
    data = request.json
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    email = data.get("email", "").strip().lower()
    
    # Validate email format
    is_valid, error = validate_email(email)
    if not is_valid:
        return jsonify({"error": error}), 400
    
    # Verify reCAPTCHA
    recaptcha_response = data.get("recaptcha_token", "")
    if not verify_recaptcha(recaptcha_response):
        return jsonify({"error": "reCAPTCHA verification failed"}), 400
    
    # Always return success to prevent email enumeration
    # But only send email if user exists
    user = get_user_by_email(email)
    
    if user:
        # Generate reset token
        token = generate_password_reset_token(user["id"], email)
        
        if token:
            # Send reset email via verification service
            try:
                response = requests.post(
                    f"{VERIFICATION_SERVICE_URL}/verify/send-reset",
                    json={
                        "email": email,
                        "username": user["username"],
                        "token": token
                    },
                    timeout=10
                )
                if response.status_code != 200:
                    logger.warning(f"Failed to send password reset email: {response.status_code}")
            except Exception as e:
                logger.error(f"Error sending password reset email: {e}")
    
    # Same response regardless of whether user exists (anti-enumeration)
    return jsonify({
        "message": "If an account with that email exists, a password reset link has been sent."
    }), 200


@app.route("/auth/reset-password", methods=["POST"])
@limiter.limit("5 per minute")
def reset_password():
    """Reset password using a valid reset token."""
    data = request.json
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    token = data.get("token", "").strip()
    new_password = data.get("password", "")
    
    if not token:
        return jsonify({"error": "Reset token is required"}), 400
    
    # Validate new password
    is_valid, error = validate_password(new_password)
    if not is_valid:
        return jsonify({"error": error}), 400
    
    # Verify reset token
    user_id, error = verify_password_reset_token(token)
    if error:
        return jsonify({"error": error}), 400
    
    # Update password
    new_password_hash = generate_password_hash(new_password)
    if not update_user_password(user_id, new_password_hash):
        return jsonify({"error": "Failed to update password"}), 500
    
    # Mark token as used
    mark_reset_token_used(token)
    
    # Revoke all existing sessions for security
    revoke_all_user_tokens(user_id)
    
    logger.info(f"Password reset successful for user_id: {user_id}")
    
    return jsonify({
        "message": "Password reset successful. Please log in with your new password."
    }), 200


@app.route("/auth/resend-verification", methods=["POST"])
@limiter.limit("3 per minute")
def resend_verification():
    """
    Allow unverified users to request a new verification email.
    Requires username, email (for verification), and reCAPTCHA.
    Anti-enumeration: returns same response regardless of user existence.
    """
    data = request.json
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    
    # Validate inputs
    is_valid, error = validate_username(username)
    if not is_valid:
        return jsonify({"error": error}), 400
    
    is_valid, error = validate_email(email)
    if not is_valid:
        return jsonify({"error": error}), 400
    
    # Verify reCAPTCHA
    recaptcha_response = data.get("recaptcha_token", "")
    if not verify_recaptcha(recaptcha_response):
        return jsonify({"error": "reCAPTCHA verification failed"}), 400
    
    # Generic success message (anti-enumeration)
    success_message = "If an unverified account with those details exists, a new verification email has been sent."
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Look up user by username AND email (both must match)
        cur.execute(
            "SELECT id, username, email FROM users WHERE username = %s AND email = %s",
            (username, email)
        )
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        if not user:
            # No user found with that username+email combination
            # Return same success message (anti-enumeration)
            logger.info(f"Resend verification: no user found for username={username}")
            return jsonify({"message": success_message}), 200
        
        user_id, db_username, db_email = user
        
        # Check if already verified
        try:
            verify_response = requests.get(
                f"{VERIFICATION_SERVICE_URL}/verify/status/{user_id}",
                timeout=5
            )
            if verify_response.status_code == 200:
                verify_data = verify_response.json()
                if verify_data.get("verified", False):
                    # Already verified - inform the user
                    return jsonify({
                        "message": "Your email is already verified. You can log in.",
                        "already_verified": True
                    }), 200
        except Exception as e:
            logger.error(f"Error checking verification status: {e}")
            return jsonify({"error": "Unable to check verification status. Please try again."}), 503
        
        # Send new verification email
        try:
            verify_response = requests.post(
                f"{VERIFICATION_SERVICE_URL}/verify/send",
                json={"user_id": user_id, "email": db_email, "username": db_username},
                timeout=10
            )
            if verify_response.status_code == 200:
                logger.info(f"Resend verification: email sent to {db_email} for user_id={user_id}")
            else:
                logger.warning(f"Failed to resend verification email: {verify_response.status_code}")
        except Exception as e:
            logger.error(f"Error calling verification service: {e}")
            return jsonify({"error": "Failed to send verification email. Please try again."}), 503
        
        return jsonify({"message": success_message}), 200
        
    except Exception as e:
        logger.error(f"Resend verification error: {e}")
        return jsonify({"error": "An error occurred. Please try again."}), 500


@app.route("/auth/verify-token", methods=["POST"])
@limiter.limit("30 per minute")
def verify_token():
    """Verify if an access token is valid (not expired, not blacklisted)."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"valid": False, "error": "Authorization header required"}), 401
    
    access_token = auth_header[7:]
    
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=["HS256"])
        
        # Check if token is blacklisted
        jti = payload.get("jti")
        if jti and is_token_blacklisted(jti):
            return jsonify({"valid": False, "error": "Token has been revoked"}), 401
        
        return jsonify({
            "valid": True,
            "user_id": payload.get("user_id"),
            "username": payload.get("username"),
            "expires_at": payload.get("exp")
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"valid": False, "error": "Invalid token"}), 401


if __name__ == "__main__":
    # Try to init DB immediately
    # In a real microservice, use a separate migration job.
    init_db()
    app.run(host="0.0.0.0", port=5000)
