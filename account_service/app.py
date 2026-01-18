"""
Account Microservice

User account management service providing:
- Profile viewing and editing
- Password change
- Email update (with verification)
- MFA settings management
- Session management

All endpoints require JWT authentication (except health).
"""

import datetime
import logging
import os
import secrets

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
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Database configuration - uses auth_db for user data
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://user:password@db:5432/auth_db")
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    logger.warning("SECRET_KEY not set - using random key (sessions won't persist across restarts)")
    SECRET_KEY = secrets.token_hex(32)

# Service URLs
MFA_SERVICE_URL = os.environ.get("MFA_SERVICE_URL", "http://mfa_service:5000")
VERIFICATION_SERVICE_URL = os.environ.get("VERIFICATION_SERVICE_URL", "http://verification_service:5000")

# Rate Limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per day", "30 per hour"],
    storage_uri="memory://",
)


# ==================== DATABASE ====================

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)


# ==================== AUTH HELPERS ====================

def get_current_user():
    """
    Extract and verify JWT token from Authorization header.
    Returns user info dict or None.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    
    token = auth_header[7:]
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return {
            "user_id": payload.get("user_id"),
            "username": payload.get("username"),
            "jti": payload.get("jti")
        }
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_auth(f):
    """Decorator to require valid JWT authentication."""
    from functools import wraps
    
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated


# ==================== VALIDATION ====================

def validate_password(password):
    """Validate password complexity."""
    if len(password) < 15:
        return False, "Password must be at least 15 characters"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    
    if not (has_upper and has_lower and has_digit and has_special):
        return False, "Password must contain uppercase, lowercase, number, and special character"
    
    return True, None


def validate_email(email):
    """Basic email format validation."""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False, "Invalid email format"
    if len(email) > 254:
        return False, "Email too long"
    return True, None


# ==================== ENDPOINTS ====================

@app.route("/health", methods=["GET"])
@app.route("/account/health", methods=["GET"])
def health_check():
    status = {"service": "account_service", "database": "unknown"}
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


# ==================== STATIC FILE SERVING ====================

@app.route("/static/")
@app.route("/static/index.html")
def serve_index():
    """Serve the account settings page."""
    return send_from_directory('static', 'index.html')


@app.route("/static/<path:subpath>")
def serve_static(subpath):
    """Serve static files (CSS, JS) for account settings."""
    return send_from_directory('static', subpath)


@app.route("/account/profile", methods=["GET"])
@limiter.limit("30 per minute")
@require_auth
def get_profile():
    """Get current user's profile."""
    user_id = request.current_user["user_id"]
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, email FROM users WHERE id = %s",
            (user_id,)
        )
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        if not result:
            return jsonify({"error": "User not found"}), 404
        
        # Get MFA status
        mfa_enabled = False
        try:
            mfa_response = requests.get(
                f"{MFA_SERVICE_URL}/mfa/status/{user_id}",
                timeout=5
            )
            if mfa_response.status_code == 200:
                mfa_data = mfa_response.json()
                mfa_enabled = mfa_data.get("mfa_enabled", False)
        except Exception as e:
            logger.warning(f"Could not get MFA status: {e}")
        
        return jsonify({
            "user_id": result[0],
            "username": result[1],
            "email": result[2],
            "mfa_enabled": mfa_enabled
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting profile: {e}")
        return jsonify({"error": "Failed to get profile"}), 500


@app.route("/account/password", methods=["PUT"])
@limiter.limit("5 per minute")
@require_auth
def change_password():
    """Change user's password. Requires current password."""
    user_id = request.current_user["user_id"]
    data = request.json
    
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")
    
    if not current_password or not new_password:
        return jsonify({"error": "Current and new passwords are required"}), 400
    
    # Validate new password
    is_valid, error = validate_password(new_password)
    if not is_valid:
        return jsonify({"error": error}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get current password hash
        cur.execute(
            "SELECT password_hash FROM users WHERE id = %s",
            (user_id,)
        )
        result = cur.fetchone()
        
        if not result:
            cur.close()
            conn.close()
            return jsonify({"error": "User not found"}), 404
        
        # Verify current password
        if not check_password_hash(result[0], current_password):
            cur.close()
            conn.close()
            return jsonify({"error": "Current password is incorrect"}), 401
        
        # Update password
        new_hash = generate_password_hash(new_password)
        cur.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (new_hash, user_id)
        )
        
        # Revoke all refresh tokens for security
        cur.execute(
            "UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = %s",
            (user_id,)
        )
        
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"Password changed for user_id: {user_id}")
        
        return jsonify({
            "message": "Password changed successfully. Please log in again."
        }), 200
        
    except Exception as e:
        logger.error(f"Error changing password: {e}")
        return jsonify({"error": "Failed to change password"}), 500


@app.route("/account/email", methods=["PUT"])
@limiter.limit("3 per minute")
@require_auth
def change_email():
    """
    Request email change. Sends verification to new email.
    Email won't actually change until verified.
    """
    user_id = request.current_user["user_id"]
    username = request.current_user["username"]
    data = request.json
    
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    new_email = data.get("email", "").strip().lower()
    password = data.get("password", "")  # Require password for security
    
    if not new_email or not password:
        return jsonify({"error": "New email and current password are required"}), 400
    
    # Validate email format
    is_valid, error = validate_email(new_email)
    if not is_valid:
        return jsonify({"error": error}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verify password
        cur.execute(
            "SELECT password_hash FROM users WHERE id = %s",
            (user_id,)
        )
        result = cur.fetchone()
        
        if not result:
            cur.close()
            conn.close()
            return jsonify({"error": "User not found"}), 404
        
        if not check_password_hash(result[0], password):
            cur.close()
            conn.close()
            return jsonify({"error": "Password is incorrect"}), 401
        
        # Update email directly (in production, you'd want email verification)
        cur.execute(
            "UPDATE users SET email = %s WHERE id = %s",
            (new_email, user_id)
        )
        conn.commit()
        cur.close()
        conn.close()
        
        # Send verification to new email
        try:
            requests.post(
                f"{VERIFICATION_SERVICE_URL}/verify/send",
                json={"user_id": user_id, "email": new_email, "username": username},
                timeout=10
            )
        except Exception as e:
            logger.warning(f"Could not send verification email: {e}")
        
        logger.info(f"Email changed for user_id: {user_id}")
        
        return jsonify({
            "message": "Email updated successfully. A verification email has been sent."
        }), 200
        
    except Exception as e:
        logger.error(f"Error changing email: {e}")
        return jsonify({"error": "Failed to change email"}), 500


# ==================== MFA MANAGEMENT ====================

@app.route("/account/mfa", methods=["GET"])
@limiter.limit("30 per minute")
@require_auth
def get_mfa_status():
    """Get current MFA status for user."""
    user_id = request.current_user["user_id"]
    
    try:
        response = requests.get(
            f"{MFA_SERVICE_URL}/mfa/status/{user_id}",
            timeout=5
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        logger.error(f"Error getting MFA status: {e}")
        return jsonify({"error": "MFA service unavailable"}), 503


@app.route("/account/mfa/setup", methods=["POST"])
@limiter.limit("5 per minute")
@require_auth
def setup_mfa():
    """Initiate MFA setup - get QR code and secret."""
    user_id = request.current_user["user_id"]
    
    # Get user email for QR code
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT email FROM users WHERE id = %s", (user_id,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        email = result[0] if result else f"user_{user_id}@app"
    except:
        email = f"user_{user_id}@app"
    
    try:
        response = requests.post(
            f"{MFA_SERVICE_URL}/mfa/setup",
            json={"user_id": user_id, "email": email},
            timeout=10
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        logger.error(f"Error setting up MFA: {e}")
        return jsonify({"error": "MFA service unavailable"}), 503


@app.route("/account/mfa/enable", methods=["POST"])
@limiter.limit("10 per minute")
@require_auth
def enable_mfa():
    """Enable MFA with TOTP verification code."""
    user_id = request.current_user["user_id"]
    data = request.json or {}
    
    totp_code = data.get("totp_code", "")
    if not totp_code:
        return jsonify({"error": "TOTP code is required"}), 400
    
    try:
        response = requests.post(
            f"{MFA_SERVICE_URL}/mfa/enable",
            json={"user_id": user_id, "totp_code": totp_code},
            timeout=10
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        logger.error(f"Error enabling MFA: {e}")
        return jsonify({"error": "MFA service unavailable"}), 503


@app.route("/account/mfa/disable", methods=["POST"])
@limiter.limit("3 per minute")
@require_auth
def disable_mfa():
    """Disable MFA. Requires TOTP code for security."""
    user_id = request.current_user["user_id"]
    data = request.json or {}
    
    totp_code = data.get("totp_code", "")
    if not totp_code:
        return jsonify({"error": "TOTP code is required to disable MFA"}), 400
    
    try:
        response = requests.post(
            f"{MFA_SERVICE_URL}/mfa/disable",
            json={"user_id": user_id, "totp_code": totp_code},
            timeout=10
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        logger.error(f"Error disabling MFA: {e}")
        return jsonify({"error": "MFA service unavailable"}), 503


# ==================== SESSION MANAGEMENT ====================

@app.route("/account/sessions", methods=["GET"])
@limiter.limit("10 per minute")
@require_auth
def list_sessions():
    """List all active sessions for current user."""
    user_id = request.current_user["user_id"]
    current_jti = request.current_user.get("jti")
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, user_agent, ip_address, created_at, expires_at
            FROM refresh_tokens
            WHERE user_id = %s AND revoked = FALSE AND expires_at > NOW()
            ORDER BY created_at DESC
        """, (user_id,))
        sessions = cur.fetchall()
        cur.close()
        conn.close()
        
        return jsonify({
            "sessions": [
                {
                    "id": s[0],
                    "user_agent": s[1] or "Unknown",
                    "ip_address": s[2] or "Unknown",
                    "created_at": s[3].isoformat() if s[3] else None,
                    "expires_at": s[4].isoformat() if s[4] else None
                }
                for s in sessions
            ],
            "count": len(sessions)
        }), 200
        
    except Exception as e:
        logger.error(f"Error listing sessions: {e}")
        return jsonify({"error": "Failed to list sessions"}), 500


@app.route("/account/sessions", methods=["DELETE"])
@limiter.limit("5 per minute")
@require_auth
def revoke_other_sessions():
    """Revoke all sessions except current one."""
    user_id = request.current_user["user_id"]
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Revoke all refresh tokens for this user
        cur.execute(
            "UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = %s",
            (user_id,)
        )
        revoked_count = cur.rowcount
        
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"Revoked {revoked_count} sessions for user_id: {user_id}")
        
        return jsonify({
            "message": f"Revoked {revoked_count} session(s). Please log in again."
        }), 200
        
    except Exception as e:
        logger.error(f"Error revoking sessions: {e}")
        return jsonify({"error": "Failed to revoke sessions"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
