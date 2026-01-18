"""
Registration Verification Microservice

Handles email verification for user registration with security-focused design:
- Time-limited tokens (24h expiry)
- Rate limiting on all endpoints
- Secure token generation (secrets.token_urlsafe)
- Anti-enumeration protection
"""

import datetime
import html
import logging
import os
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Tuple

import psycopg2
from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from psycopg2 import OperationalError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates', static_folder='static')

# Security: Limit request size
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB

# Config
DATABASE_URL = os.environ.get("DATABASE_URL")
SMTP_HOST = os.environ.get("SMTP_HOST", "mailhog")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 1025))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@memeapp.local")
APP_URL = os.environ.get("APP_URL", "http://localhost")

# Token expiry in hours
TOKEN_EXPIRY_HOURS = 24

# Rate Limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per day", "20 per hour"],
    storage_uri="memory://",
)


# ==================== DATABASE ====================

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn


def init_db():
    """Initialize the verification_tokens table."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS verification_tokens (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                email VARCHAR(254) NOT NULL,
                token VARCHAR(64) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                verified_at TIMESTAMP DEFAULT NULL,
                attempts INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_token ON verification_tokens(token);
            CREATE INDEX IF NOT EXISTS idx_user_id ON verification_tokens(user_id);
        """)
        
        # Add verified_at column if it doesn't exist (for existing DBs)
        cur.execute("""
            DO $$ 
            BEGIN 
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'verification_tokens' AND column_name = 'verified_at'
                ) THEN 
                    ALTER TABLE verification_tokens ADD COLUMN verified_at TIMESTAMP DEFAULT NULL;
                END IF;
            END $$;
        """)
        conn.commit()
        cur.close()
        conn.close()
        logger.info("Verification database initialized successfully.")
    except Exception as e:
        logger.error(f"Error initializing verification DB: {e}")


# ==================== EMAIL ====================

def send_verification_email(email: str, token: str, username: str) -> bool:
    """Send verification email with secure token.
    
    Args:
        email: Recipient email address.
        token: Verification token to include in link.
        username: Username for personalization.
        
    Returns:
        True if email sent successfully, False otherwise.
    """""
    verification_url = f"{APP_URL}/verify/confirm/{token}"
    
    subject = "Verify your Meme App account"
    html_body = f"""
    <html>
    <head>
        <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600&family=Inter:wght@300;400;500&display=swap" rel="stylesheet">
    </head>
    <body style="font-family: 'Inter', sans-serif; max-width: 600px; margin: 0 auto; background-color: #ffffff; color: #111111; line-height: 1.6;">
        <div style="padding: 40px 20px; border: 1px solid #e5e5e5; margin-top: 20px;">
            <h1 style="font-family: 'Playfair Display', serif; font-size: 28px; margin-bottom: 20px; text-align: center; color: #000000; font-weight: 400;">Welcome, {username}</h1>
            
            <p style="text-align: center; margin-bottom: 30px; color: #666666;">
                Verify your email to continue to the Meme App.
            </p>
            
            <div style="text-align: center; margin: 40px 0;">
                <a href="{verification_url}" 
                   style="background: #000000; color: #ffffff; padding: 16px 32px; 
                          text-decoration: none; display: inline-block; text-transform: uppercase; letter-spacing: 2px; font-size: 12px;">
                    Verify Account
                </a>
            </div>
            
            <p style="text-align: center; font-size: 12px; color: #999999; margin-top: 40px; border-top: 1px solid #e5e5e5; padding-top: 20px;">
                Link expires in {TOKEN_EXPIRY_HOURS} hours.<br>
                <a href="{verification_url}" style="color: #666666; text-decoration: underline;">{verification_url}</a>
            </p>
        </div>
    </body>
    </html>
    """
    
    text_body = f"""
    Welcome to Meme App, {username}!
    
    Please verify your email by visiting:
    {verification_url}
    
    This link expires in {TOKEN_EXPIRY_HOURS} hours.
    If you didn't create an account, you can ignore this email.
    """
    
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = email
    
    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))
    
    try:
        # For Mailhog, no authentication needed
        if SMTP_USER and SMTP_PASSWORD:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_FROM, email, msg.as_string())
        else:
            # Mailhog mode - no auth
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.sendmail(SMTP_FROM, email, msg.as_string())
        
        logger.info(f"Verification email sent to {email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False


# Password reset token expiry
PASSWORD_RESET_EXPIRY_HOURS = 1


def send_password_reset_email(email: str, token: str, username: str) -> bool:
    """Send password reset email with secure token.
    
    Args:
        email: Recipient email address.
        token: Reset token to include in link.
        username: Username for personalization.
        
    Returns:
        True if email sent successfully, False otherwise.
    """""
    reset_url = f"{APP_URL}/auth/reset-password?token={token}"
    
    subject = "Reset your Meme App password"
    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #6366f1;">Password Reset Request</h2>
        <p>Hi {html.escape(username)},</p>
        <p>We received a request to reset your password. Click the button below to set a new password:</p>
        <p style="text-align: center; margin: 30px 0;">
            <a href="{reset_url}" 
               style="background: #6366f1; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 6px; display: inline-block;">
                Reset Password
            </a>
        </p>
        <p style="color: #666; font-size: 14px;">
            Or copy this link: <br>
            <code style="background: #f0f0f0; padding: 4px 8px;">{reset_url}</code>
        </p>
        <p style="color: #999; font-size: 12px;">
            This link expires in {PASSWORD_RESET_EXPIRY_HOURS} hour.<br>
            If you didn't request a password reset, you can ignore this email.
            Your password will remain unchanged.
        </p>
        <p style="color: #ff6b6b; font-size: 12px; margin-top: 20px;">
            <strong>Security Note:</strong> Never share this link with anyone. 
            Meme App will never ask for your password via email.
        </p>
    </body>
    </html>
    """
    
    text_body = f"""
    Password Reset Request
    
    Hi {username},
    
    We received a request to reset your password.
    
    Reset your password by visiting:
    {reset_url}
    
    This link expires in {PASSWORD_RESET_EXPIRY_HOURS} hour.
    If you didn't request a password reset, you can ignore this email.
    Your password will remain unchanged.
    
    Security Note: Never share this link with anyone.
    """
    
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = email
    
    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))
    
    try:
        if SMTP_USER and SMTP_PASSWORD:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_FROM, email, msg.as_string())
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.sendmail(SMTP_FROM, email, msg.as_string())
        
        logger.info(f"Password reset email sent to {email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send password reset email: {e}")
        return False


# ==================== ENDPOINTS ====================

@app.route("/verify/static/<path:subpath>")
def serve_static(subpath):
    """Serve static files (CSS, JS) for verification pages."""
    return send_from_directory('static', subpath)


@app.route("/health", methods=["GET"])
def health_check():
    status = {"service": "verification_service", "database": "unknown"}
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


@app.route("/verify/send", methods=["POST"])
@limiter.limit("5 per minute")  # Strict rate limit to prevent abuse
def send_verification():
    """
    Send verification email to a newly registered user.
    Called internally by auth_service after registration.
    """
    data = request.json
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    user_id = data.get("user_id")
    email = data.get("email")
    username = data.get("username")
    
    if not all([user_id, email, username]):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Initialize DB
    init_db()
    
    # Generate secure token
    token = secrets.token_urlsafe(48)  # 64 characters, cryptographically secure
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_EXPIRY_HOURS)
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Delete any existing unused tokens for this user (don't mark as used - that would falsely indicate verification)
        cur.execute(
            "DELETE FROM verification_tokens WHERE user_id = %s AND used = FALSE;",
            (user_id,)
        )
        
        # Create new token
        cur.execute(
            """INSERT INTO verification_tokens (user_id, email, token, expires_at) 
               VALUES (%s, %s, %s, %s) RETURNING id;""",
            (user_id, email, token, expires_at)
        )
        token_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        
        # Send email
        if send_verification_email(email, token, username):
            return jsonify({
                "message": "Verification email sent",
                "expires_in_hours": TOKEN_EXPIRY_HOURS
            }), 200
        else:
            return jsonify({"error": "Failed to send verification email"}), 500
            
    except Exception as e:
        logger.error(f"Error creating verification token: {e}")
        return jsonify({"error": "Failed to create verification token"}), 500


@app.route("/verify/send-reset", methods=["POST"])
@limiter.limit("5 per minute")
def send_reset():
    """
    Send password reset email.
    Called internally by auth_service after forgot-password request.
    """
    data = request.json
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    email = data.get("email")
    username = data.get("username")
    token = data.get("token")
    
    if not all([email, username, token]):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Send email
    if send_password_reset_email(email, token, username):
        return jsonify({
            "message": "Password reset email sent",
            "expires_in_hours": PASSWORD_RESET_EXPIRY_HOURS
        }), 200
    else:
        return jsonify({"error": "Failed to send password reset email"}), 500


@app.route("/verify/confirm/<token>", methods=["GET"])
@limiter.limit("10 per minute")  # Rate limit to prevent token bruteforce
def confirm_verification(token):
    """
    Confirm email verification.
    Returns HTML page for user-friendly experience.
    """
    if not token or len(token) < 32:
        return create_response_page("Invalid Link", "This verification link is invalid.", False)
    
    init_db()
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Find token and check validity
        cur.execute(
            """SELECT id, user_id, email, expires_at, used, attempts 
               FROM verification_tokens WHERE token = %s;""",
            (token,)
        )
        result = cur.fetchone()
        
        if not result:
            cur.close()
            conn.close()
            # Anti-enumeration: same message for invalid token
            return create_response_page(
                "Invalid or Expired", 
                "This verification link is invalid or has expired. Please request a new one.",
                False
            )
        
        token_id, user_id, email, expires_at, used, attempts = result
        
        # Update attempt counter (for security logging)
        cur.execute(
            "UPDATE verification_tokens SET attempts = attempts + 1 WHERE id = %s;",
            (token_id,)
        )
        conn.commit()
        
        # Check if already used
        if used:
            cur.close()
            conn.close()
            return create_response_page(
                "Already Verified",
                "Your email has already been verified. You can log in now.",
                True
            )
        
        # Check expiry
        if datetime.datetime.utcnow() > expires_at:
            cur.close()
            conn.close()
            return create_response_page(
                "Link Expired",
                "This verification link has expired. Please request a new one.",
                False
            )
        
        # Mark token as used and set verified timestamp
        cur.execute(
            "UPDATE verification_tokens SET used = TRUE, verified_at = CURRENT_TIMESTAMP WHERE id = %s;",
            (token_id,)
        )
        conn.commit()
        cur.close()
        conn.close()
        
        # Return success page with auto-redirect
        return create_success_page(email)
        
    except Exception as e:
        logger.error(f"Verification error: {e}")
        return create_response_page(
            "Error",
            "An error occurred during verification. Please try again.",
            False
        )


@app.route("/verify/resend", methods=["POST"])
@limiter.limit("3 per minute")  # Very strict to prevent spam
def resend_verification():
    """
    Resend verification email.
    Requires user_id to prevent email enumeration.
    """
    data = request.json
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    
    user_id = data.get("user_id")
    email = data.get("email")
    username = data.get("username")
    
    if not all([user_id, email, username]):
        return jsonify({"error": "Missing required fields"}), 400
    
    init_db()
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check for recent send (prevent spam)
        cur.execute(
            """SELECT created_at FROM verification_tokens 
               WHERE user_id = %s AND used = FALSE 
               ORDER BY created_at DESC LIMIT 1;""",
            (user_id,)
        )
        recent = cur.fetchone()
        
        if recent:
            created_at = recent[0]
            # Require at least 2 minutes between resends
            if datetime.datetime.utcnow() - created_at < datetime.timedelta(minutes=2):
                cur.close()
                conn.close()
                return jsonify({
                    "error": "Please wait before requesting another verification email",
                    "retry_after_seconds": 120
                }), 429
        
        cur.close()
        conn.close()
        
        # Use the send endpoint logic (calls send_verification internally)
        return send_verification()
        
    except Exception as e:
        logger.error(f"Resend error: {e}")
        return jsonify({"error": "Failed to resend verification email"}), 500


@app.route("/verify/status/<int:user_id>", methods=["GET"])
@limiter.limit("20 per minute")
def check_verification_status(user_id):
    """
    Check if a user has verified their email.
    Used by auth_service to check before allowing login.
    A user is verified only if they have a token with verified_at set (clicked the link).
    """
    init_db()
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check for a token that was actually verified (verified_at is set)
        cur.execute(
            """SELECT verified_at FROM verification_tokens 
               WHERE user_id = %s AND verified_at IS NOT NULL 
               LIMIT 1;""",
            (user_id,)
        )
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        is_verified = result is not None
        
        return jsonify({
            "user_id": user_id,
            "verified": is_verified
        }), 200
        
    except Exception as e:
        logger.error(f"Status check error: {e}")
        return jsonify({"error": "Failed to check verification status"}), 500


# ==================== HELPERS ====================

def create_response_page(title: str, message: str, success: bool) -> Tuple[str, int]:
    """Create user-friendly HTML response page using template.
    
    Args:
        title: Page title.
        message: Message to display.
        success: Whether this is a success or error page.
        
    Returns:
        Tuple of (rendered HTML, status code).
    """
    # XSS Prevention: Jinja2 auto-escapes by default
    status_code = 200 if success else 400
    return render_template(
        'response.html',
        title=title,
        message=message,
        success=success
    ), status_code


def create_success_page(email):
    """Create success page with auto-redirect to login using template."""
    # XSS Prevention: Jinja2 auto-escapes by default
    return render_template('success.html', email=email), 200


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
