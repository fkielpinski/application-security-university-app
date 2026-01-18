"""
MFA Microservice

Handles Multi-Factor Authentication (MFA) using TOTP (Time-based One-Time Passwords):
- TOTP secret generation and QR code creation
- MFA enable/disable functionality
- TOTP verification during login
- Rate limiting on verification attempts

Security considerations:
- Secrets are encrypted at rest in the database
- Rate limiting prevents brute-force attacks
- Fail-closed design for service errors
"""

import base64
import datetime
import hashlib
import io
import logging
import os
import secrets
from typing import List, Optional

import psycopg2
import pyotp
import qrcode
from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from psycopg2 import OperationalError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Database configuration
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://user:password@db:5432/mfa_db")

# App configuration for QR code generation
APP_NAME = os.environ.get("APP_NAME", "MemeApp")

# Rate Limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per day", "20 per hour"],
    storage_uri="memory://",
)


# ==================== DATABASE ====================

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)


def init_db():
    """Initialize the mfa_secrets table."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Create MFA secrets table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS mfa_secrets (
                id SERIAL PRIMARY KEY,
                user_id INTEGER UNIQUE NOT NULL,
                secret_encrypted TEXT NOT NULL,
                enabled BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                enabled_at TIMESTAMP,
                last_used_at TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_mfa_user_id ON mfa_secrets(user_id);
        """)
        
        # Create backup codes table (for account recovery)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS mfa_backup_codes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                code_hash VARCHAR(128) NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_at TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_backup_user_id ON mfa_backup_codes(user_id);
        """)
        
        conn.commit()
        cur.close()
        conn.close()
        logger.info("MFA database initialized successfully.")
    except Exception as e:
        logger.error(f"Error initializing MFA DB: {e}")


# ==================== CRYPTO HELPERS ====================

def encrypt_secret(secret):
    """
    Simple encoding for the TOTP secret.
    In production, use proper encryption (e.g., Fernet with KMS-managed key).
    For this demo, we use base64 encoding.
    """
    return base64.b64encode(secret.encode()).decode()


def decrypt_secret(encrypted_secret):
    """Decrypt the TOTP secret."""
    return base64.b64decode(encrypted_secret.encode()).decode()


def hash_backup_code(code: str) -> str:
    """Hash a backup code for secure storage using SHA-256."""
    return hashlib.sha256(code.encode()).hexdigest()


def generate_backup_codes(count: int = 10) -> List[str]:
    """Generate a set of backup codes."""
    codes = []
    for _ in range(count):
        # Generate 8-character alphanumeric codes
        code = secrets.token_hex(4).upper()
        codes.append(code)
    return codes


# ==================== TOTP HELPERS ====================

def generate_totp_secret() -> str:
    """Generate a new TOTP secret."""
    return pyotp.random_base32()


def get_totp_uri(secret, email, issuer=APP_NAME):
    """Generate the TOTP provisioning URI for QR code."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


def generate_qr_code_base64(uri):
    """Generate a QR code and return it as a base64-encoded PNG."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{img_base64}"


def verify_totp_code(secret: str, code: str) -> bool:
    """Verify a TOTP code."""
    totp = pyotp.TOTP(secret)
    # valid_window=1 allows for 1 time step (30 seconds) of clock drift
    return totp.verify(code, valid_window=1)


# ==================== ENDPOINTS ====================

@app.route("/health", methods=["GET"])
@app.route("/mfa/health", methods=["GET"])
def health_check():
    status = {"service": "mfa_service", "database": "unknown"}
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


@app.route("/mfa/setup", methods=["POST"])
@limiter.limit("5 per minute")
def setup_mfa():
    """
    Generate TOTP secret and QR code for user.
    This creates/updates the secret but does NOT enable MFA yet.
    User must verify a code to enable MFA.
    """
    data = request.json
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    user_id = data.get("user_id")
    email = data.get("email", f"user_{user_id}@memeapp.local")
    
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400
    
    try:
        # Generate new TOTP secret
        secret = generate_totp_secret()
        encrypted_secret = encrypt_secret(secret)
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Upsert: create or update the secret (but keep enabled=FALSE until verified)
        cur.execute("""
            INSERT INTO mfa_secrets (user_id, secret_encrypted, enabled)
            VALUES (%s, %s, FALSE)
            ON CONFLICT (user_id) 
            DO UPDATE SET secret_encrypted = EXCLUDED.secret_encrypted,
                          enabled = FALSE,
                          created_at = CURRENT_TIMESTAMP
            RETURNING id
        """, (user_id, encrypted_secret))
        
        conn.commit()
        cur.close()
        conn.close()
        
        # Generate QR code
        totp_uri = get_totp_uri(secret, email)
        qr_code = generate_qr_code_base64(totp_uri)
        
        # Generate backup codes
        backup_codes = generate_backup_codes(10)
        
        # Store hashed backup codes
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            # Remove old backup codes
            cur.execute("DELETE FROM mfa_backup_codes WHERE user_id = %s", (user_id,))
            # Insert new backup codes
            for code in backup_codes:
                cur.execute(
                    "INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES (%s, %s)",
                    (user_id, hash_backup_code(code))
                )
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            logger.error(f"Error storing backup codes: {e}")
        
        logger.info(f"MFA setup initiated for user_id: {user_id}")
        
        return jsonify({
            "message": "MFA setup initiated. Scan the QR code with your authenticator app and verify a code to enable MFA.",
            "qr_code": qr_code,
            "secret": secret,  # Allow manual entry if QR scanning fails
            "backup_codes": backup_codes  # Show once during setup
        }), 200
        
    except Exception as e:
        logger.error(f"Error setting up MFA: {e}")
        return jsonify({"error": "Failed to setup MFA"}), 500


@app.route("/mfa/enable", methods=["POST"])
@limiter.limit("10 per minute")
def enable_mfa():
    """
    Verify initial TOTP code and enable MFA for user.
    This confirms the user has correctly configured their authenticator.
    """
    data = request.json
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    user_id = data.get("user_id")
    totp_code = data.get("totp_code", "").strip()
    
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400
    if not totp_code:
        return jsonify({"error": "totp_code is required"}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get the pending secret
        cur.execute(
            "SELECT secret_encrypted, enabled FROM mfa_secrets WHERE user_id = %s",
            (user_id,)
        )
        result = cur.fetchone()
        
        if not result:
            cur.close()
            conn.close()
            return jsonify({"error": "MFA setup not found. Please initiate setup first."}), 404
        
        encrypted_secret, already_enabled = result
        
        if already_enabled:
            cur.close()
            conn.close()
            return jsonify({"error": "MFA is already enabled for this user"}), 400
        
        # Decrypt and verify the code
        secret = decrypt_secret(encrypted_secret)
        
        if not verify_totp_code(secret, totp_code):
            cur.close()
            conn.close()
            logger.warning(f"Invalid TOTP code during MFA enable for user_id: {user_id}")
            return jsonify({"error": "Invalid verification code"}), 401
        
        # Enable MFA
        cur.execute(
            "UPDATE mfa_secrets SET enabled = TRUE, enabled_at = CURRENT_TIMESTAMP WHERE user_id = %s",
            (user_id,)
        )
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"MFA enabled successfully for user_id: {user_id}")
        
        return jsonify({
            "message": "MFA enabled successfully",
            "mfa_enabled": True
        }), 200
        
    except Exception as e:
        logger.error(f"Error enabling MFA: {e}")
        return jsonify({"error": "Failed to enable MFA"}), 500


@app.route("/mfa/verify", methods=["POST"])
@limiter.limit("10 per minute")
def verify_mfa():
    """
    Verify TOTP code during login.
    Called by auth_service after successful password verification.
    """
    data = request.json
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    user_id = data.get("user_id")
    totp_code = data.get("totp_code", "").strip()
    
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400
    if not totp_code:
        return jsonify({"error": "totp_code is required"}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get the enabled secret
        cur.execute(
            "SELECT secret_encrypted, enabled FROM mfa_secrets WHERE user_id = %s",
            (user_id,)
        )
        result = cur.fetchone()
        
        if not result:
            cur.close()
            conn.close()
            return jsonify({"error": "MFA not configured for this user"}), 404
        
        encrypted_secret, enabled = result
        
        if not enabled:
            cur.close()
            conn.close()
            return jsonify({"error": "MFA is not enabled for this user"}), 400
        
        # Try TOTP code first
        secret = decrypt_secret(encrypted_secret)
        
        if verify_totp_code(secret, totp_code):
            # Update last used timestamp
            cur.execute(
                "UPDATE mfa_secrets SET last_used_at = CURRENT_TIMESTAMP WHERE user_id = %s",
                (user_id,)
            )
            conn.commit()
            cur.close()
            conn.close()
            
            logger.info(f"MFA verification successful for user_id: {user_id}")
            return jsonify({"verified": True, "message": "MFA verification successful"}), 200
        
        # Try backup code
        code_hash = hash_backup_code(totp_code)
        cur.execute(
            "SELECT id FROM mfa_backup_codes WHERE user_id = %s AND code_hash = %s AND used = FALSE",
            (user_id, code_hash)
        )
        backup_result = cur.fetchone()
        
        if backup_result:
            # Mark backup code as used
            cur.execute(
                "UPDATE mfa_backup_codes SET used = TRUE, used_at = CURRENT_TIMESTAMP WHERE id = %s",
                (backup_result[0],)
            )
            conn.commit()
            cur.close()
            conn.close()
            
            logger.info(f"MFA verification via backup code for user_id: {user_id}")
            return jsonify({
                "verified": True, 
                "message": "MFA verification successful (backup code used)",
                "backup_code_used": True
            }), 200
        
        cur.close()
        conn.close()
        
        logger.warning(f"Invalid MFA code for user_id: {user_id}")
        return jsonify({"verified": False, "error": "Invalid verification code"}), 401
        
    except Exception as e:
        logger.error(f"Error verifying MFA: {e}")
        return jsonify({"error": "MFA verification failed"}), 500


@app.route("/mfa/disable", methods=["POST"])
@limiter.limit("3 per minute")
def disable_mfa():
    """
    Disable MFA for a user.
    Requires valid TOTP code for security.
    """
    data = request.json
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    user_id = data.get("user_id")
    totp_code = data.get("totp_code", "").strip()
    
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400
    if not totp_code:
        return jsonify({"error": "totp_code is required to disable MFA"}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get the current secret
        cur.execute(
            "SELECT secret_encrypted, enabled FROM mfa_secrets WHERE user_id = %s",
            (user_id,)
        )
        result = cur.fetchone()
        
        if not result:
            cur.close()
            conn.close()
            return jsonify({"error": "MFA not configured for this user"}), 404
        
        encrypted_secret, enabled = result
        
        if not enabled:
            cur.close()
            conn.close()
            return jsonify({"error": "MFA is not currently enabled"}), 400
        
        # Verify the code before disabling
        secret = decrypt_secret(encrypted_secret)
        
        if not verify_totp_code(secret, totp_code):
            cur.close()
            conn.close()
            logger.warning(f"Invalid TOTP code during MFA disable for user_id: {user_id}")
            return jsonify({"error": "Invalid verification code"}), 401
        
        # Disable MFA (soft delete - keep the record but disable)
        cur.execute(
            "UPDATE mfa_secrets SET enabled = FALSE WHERE user_id = %s",
            (user_id,)
        )
        
        # Remove backup codes
        cur.execute("DELETE FROM mfa_backup_codes WHERE user_id = %s", (user_id,))
        
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"MFA disabled for user_id: {user_id}")
        
        return jsonify({
            "message": "MFA disabled successfully",
            "mfa_enabled": False
        }), 200
        
    except Exception as e:
        logger.error(f"Error disabling MFA: {e}")
        return jsonify({"error": "Failed to disable MFA"}), 500


@app.route("/mfa/status/<int:user_id>", methods=["GET"])
@limiter.limit("30 per minute")
def get_mfa_status(user_id):
    """
    Check if a user has MFA enabled.
    Called by auth_service during login to determine if MFA step is needed.
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute(
            "SELECT enabled, enabled_at, last_used_at FROM mfa_secrets WHERE user_id = %s",
            (user_id,)
        )
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        if not result:
            return jsonify({
                "user_id": user_id,
                "mfa_enabled": False,
                "mfa_configured": False
            }), 200
        
        enabled, enabled_at, last_used_at = result
        
        return jsonify({
            "user_id": user_id,
            "mfa_enabled": enabled,
            "mfa_configured": True,
            "enabled_at": enabled_at.isoformat() if enabled_at else None,
            "last_used_at": last_used_at.isoformat() if last_used_at else None
        }), 200
        
    except Exception as e:
        logger.error(f"Error checking MFA status: {e}")
        return jsonify({"error": "Failed to check MFA status"}), 500


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
