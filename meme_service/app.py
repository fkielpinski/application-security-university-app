"""
Meme Service - Content Management Microservice

Provides secure meme content management with:
- Role-based access control (Guest, User, Admin)
- Secure file uploads with validation
- Comments and ratings system
- Protection against SQL injection, XSS, and IDOR

Security Features:
- JWT authentication with role verification
- Parameterized SQL queries (no string concatenation)
- HTML escaping for all user content
- MIME type validation via magic bytes
- UUID filenames to prevent path traversal
- Rate limiting on all endpoints
"""

import datetime
import hashlib
import html
import logging
import mimetypes
import os
import re
import uuid
from functools import wraps
from typing import Any, Dict, Optional, Tuple

import jwt
import psycopg2
from flask import Flask, jsonify, request, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from psycopg2 import OperationalError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder="static")

# Security: Limit request size (5MB for file uploads)
MAX_UPLOAD_SIZE = int(os.environ.get("MAX_UPLOAD_SIZE", 5 * 1024 * 1024))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE

# Configuration
DATABASE_URL = os.environ.get("DATABASE_URL")
SECRET_KEY = os.environ.get("SECRET_KEY")
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "/app/uploads")

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Rate Limiter Setup
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "100 per hour"],
    storage_uri="memory://",
)

# Allowed file types with magic bytes for validation
ALLOWED_MIME_TYPES = {
    "image/jpeg": [b"\xff\xd8\xff"],
    "image/png": [b"\x89PNG\r\n\x1a\n"],
    "image/gif": [b"GIF87a", b"GIF89a"],
    "image/webp": [b"RIFF", b"WEBP"],  # RIFF....WEBP
}

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}


# ==================== DATABASE ====================

def get_db_connection():
    """Get database connection."""
    conn = psycopg2.connect(DATABASE_URL)
    return conn


def init_db():
    """Initialize meme service tables."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Memes table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS memes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                username VARCHAR(80) NOT NULL,
                title VARCHAR(200) NOT NULL,
                description TEXT,
                image_filename VARCHAR(255),
                image_mimetype VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_memes_user_id ON memes(user_id);
            CREATE INDEX IF NOT EXISTS idx_memes_created_at ON memes(created_at DESC);
        """)
        
        # Comments table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS comments (
                id SERIAL PRIMARY KEY,
                meme_id INTEGER NOT NULL REFERENCES memes(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL,
                username VARCHAR(80) NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_comments_meme_id ON comments(meme_id);
            CREATE INDEX IF NOT EXISTS idx_comments_user_id ON comments(user_id);
        """)
        
        # Ratings table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ratings (
                id SERIAL PRIMARY KEY,
                meme_id INTEGER NOT NULL REFERENCES memes(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL,
                rating SMALLINT NOT NULL CHECK (rating >= 1 AND rating <= 5),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(meme_id, user_id)
            );
            CREATE INDEX IF NOT EXISTS idx_ratings_meme_id ON ratings(meme_id);
        """)
        
        conn.commit()
        cur.close()
        conn.close()
        logger.info("Meme database initialized successfully.")
    except Exception as e:
        logger.error(f"Error initializing meme DB: {e}")


# Initialize DB on startup
with app.app_context():
    try:
        init_db()
    except Exception as e:
        logger.warning(f"DB init deferred: {e}")


# ==================== AUTHENTICATION & RBAC ====================

def get_current_user() -> Optional[Dict[str, Any]]:
    """
    Extract and verify JWT token from Authorization header.
    
    Returns:
        User info dict with user_id, username, role, jti or None if invalid.
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
            "role": payload.get("role", "user"),
            "jti": payload.get("jti")
        }
    except jwt.ExpiredSignatureError:
        logger.debug("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.debug(f"Invalid token: {e}")
        return None


def require_auth(f):
    """Decorator to require valid JWT authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Decorator to require admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        if user.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        request.current_user = user
        return f(*args, **kwargs)
    return decorated


# ==================== INPUT VALIDATION ====================

def sanitize_text(text: Optional[str], max_length: Optional[int] = None) -> Optional[str]:
    """
    Sanitize user input: strip whitespace and HTML escape.
    
    Args:
        text: Input text to sanitize.
        max_length: Optional maximum length to truncate to.
        
    Returns:
        Sanitized text or None if input is None/empty.
    """
    if not text:
        return None
    text = str(text).strip()
    if max_length:
        text = text[:max_length]
    # HTML escape to prevent XSS
    return html.escape(text)


def validate_title(title: Optional[str]) -> Tuple[bool, Optional[str]]:
    """Validate meme title: 1-200 chars."""
    if not title or len(title.strip()) < 1:
        return False, "Title is required"
    if len(title) > 200:
        return False, "Title must not exceed 200 characters"
    return True, None


def validate_description(description: Optional[str]) -> Tuple[bool, Optional[str]]:
    """Validate description: 0-2000 chars."""
    if description and len(description) > 2000:
        return False, "Description must not exceed 2000 characters"
    return True, None


def validate_comment(content):
    """Validate comment: 1-1000 chars."""
    if not content or len(content.strip()) < 1:
        return False, "Comment content is required"
    if len(content) > 1000:
        return False, "Comment must not exceed 1000 characters"
    return True, None


def validate_rating(rating):
    """Validate rating: integer 1-5."""
    try:
        rating = int(rating)
        if rating < 1 or rating > 5:
            return False, "Rating must be between 1 and 5"
        return True, None
    except (TypeError, ValueError):
        return False, "Rating must be a valid integer"


def validate_search_query(query):
    """Validate search query: 1-100 chars."""
    if not query or len(query.strip()) < 1:
        return False, "Search query is required"
    if len(query) > 100:
        return False, "Search query must not exceed 100 characters"
    return True, None


# ==================== FILE UPLOAD SECURITY ====================

def allowed_file(filename):
    """Check if file extension is allowed."""
    if not filename:
        return False
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_file_magic(file_data, declared_mimetype):
    """
    Validate file by checking magic bytes.
    This prevents uploading malicious files disguised as images.
    """
    if declared_mimetype not in ALLOWED_MIME_TYPES:
        return False
    
    magic_signatures = ALLOWED_MIME_TYPES[declared_mimetype]
    for sig in magic_signatures:
        if file_data.startswith(sig):
            return True
    
    # Special handling for WebP (RIFF....WEBP format)
    if declared_mimetype == "image/webp":
        if file_data[:4] == b"RIFF" and len(file_data) > 11:
            if file_data[8:12] == b"WEBP":
                return True
    
    return False


def secure_save_file(file):
    """
    Securely save uploaded file with validation.
    Returns (filename, mimetype) or (None, error_message).
    """
    if not file or file.filename == "":
        return None, "No file provided"
    
    # Check file extension
    if not allowed_file(file.filename):
        return None, "File type not allowed. Supported: JPEG, PNG, GIF, WebP"
    
    # Read file content
    file.seek(0)
    file_data = file.read()
    file.seek(0)
    
    # Check file size
    if len(file_data) > MAX_UPLOAD_SIZE:
        return None, f"File too large. Maximum size: {MAX_UPLOAD_SIZE // (1024*1024)}MB"
    
    # Detect MIME type
    original_ext = file.filename.rsplit(".", 1)[1].lower()
    mime_type = mimetypes.guess_type(file.filename)[0]
    
    if not mime_type or mime_type not in ALLOWED_MIME_TYPES:
        return None, "Invalid file type"
    
    # Validate magic bytes
    if not validate_file_magic(file_data, mime_type):
        logger.warning(f"Magic byte validation failed for upload: {file.filename}")
        return None, "File content does not match declared type"
    
    # Generate secure UUID filename (prevents path traversal)
    secure_filename = f"{uuid.uuid4().hex}.{original_ext}"
    filepath = os.path.join(UPLOAD_FOLDER, secure_filename)
    
    # Save file
    try:
        with open(filepath, "wb") as f:
            f.write(file_data)
        logger.info(f"File saved: {secure_filename}")
        return secure_filename, mime_type
    except Exception as e:
        logger.error(f"Error saving file: {e}")
        return None, "Failed to save file"


# ==================== STATIC FILE SERVING ====================

@app.route("/static/")
@app.route("/static/index.html")
def serve_index():
    """Serve the meme dashboard index page."""
    return send_from_directory("static", "index.html")


@app.route("/static/<path:subpath>")
def serve_static(subpath):
    """Serve static files (CSS, JS) for meme dashboard."""
    return send_from_directory("static", subpath)


@app.route("/uploads/<filename>")
def serve_upload(filename):
    """Serve uploaded images securely."""
    # Validate filename format (UUID + extension only)
    if not re.match(r'^[a-f0-9]{32}\.(jpg|jpeg|png|gif|webp)$', filename):
        return jsonify({"error": "Invalid filename"}), 400
    return send_from_directory(UPLOAD_FOLDER, filename)


# ==================== HEALTH CHECK ====================

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    status = {"service": "meme_service", "database": "unknown"}
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


# ==================== MEME ENDPOINTS ====================

@app.route("/memes", methods=["GET"])
@limiter.limit("60 per minute")
def get_memes():
    """
    List all memes (public endpoint).
    Supports pagination with offset and limit.
    """
    try:
        offset = max(0, int(request.args.get("offset", 0)))
        limit = min(50, max(1, int(request.args.get("limit", 20))))
    except ValueError:
        offset, limit = 0, 20
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get memes with average rating
        cur.execute("""
            SELECT m.id, m.user_id, m.username, m.title, m.description,
                   m.image_filename, m.created_at,
                   COALESCE(AVG(r.rating), 0) as avg_rating,
                   COUNT(DISTINCT r.id) as rating_count,
                   COUNT(DISTINCT c.id) as comment_count
            FROM memes m
            LEFT JOIN ratings r ON m.id = r.meme_id
            LEFT JOIN comments c ON m.id = c.meme_id
            GROUP BY m.id
            ORDER BY m.created_at DESC
            LIMIT %s OFFSET %s
        """, (limit, offset))
        
        memes = []
        for row in cur.fetchall():
            memes.append({
                "id": row[0],
                "user_id": row[1],
                "username": row[2],
                "title": row[3],
                "description": row[4],
                "image_url": f"/memes/uploads/{row[5]}" if row[5] else None,
                "created_at": row[6].isoformat() if row[6] else None,
                "avg_rating": round(float(row[7]), 1),
                "rating_count": row[8],
                "comment_count": row[9]
            })
        
        # Get total count
        cur.execute("SELECT COUNT(*) FROM memes")
        total = cur.fetchone()[0]
        
        cur.close()
        conn.close()
        
        return jsonify({
            "memes": memes,
            "total": total,
            "offset": offset,
            "limit": limit
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching memes: {e}")
        return jsonify({"error": "Failed to fetch memes"}), 500


@app.route("/memes/<int:meme_id>", methods=["GET"])
@limiter.limit("60 per minute")
def get_meme(meme_id):
    """Get single meme with comments (public endpoint)."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get meme
        cur.execute("""
            SELECT m.id, m.user_id, m.username, m.title, m.description,
                   m.image_filename, m.image_mimetype, m.created_at,
                   COALESCE(AVG(r.rating), 0) as avg_rating,
                   COUNT(DISTINCT r.id) as rating_count
            FROM memes m
            LEFT JOIN ratings r ON m.id = r.meme_id
            WHERE m.id = %s
            GROUP BY m.id
        """, (meme_id,))
        
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            return jsonify({"error": "Meme not found"}), 404
        
        meme = {
            "id": row[0],
            "user_id": row[1],
            "username": row[2],
            "title": row[3],
            "description": row[4],
            "image_url": f"/memes/uploads/{row[5]}" if row[5] else None,
            "image_mimetype": row[6],
            "created_at": row[7].isoformat() if row[7] else None,
            "avg_rating": round(float(row[8]), 1),
            "rating_count": row[9]
        }
        
        # Get comments
        cur.execute("""
            SELECT id, user_id, username, content, created_at
            FROM comments
            WHERE meme_id = %s
            ORDER BY created_at ASC
        """, (meme_id,))
        
        comments = []
        for crow in cur.fetchall():
            comments.append({
                "id": crow[0],
                "user_id": crow[1],
                "username": crow[2],
                "content": crow[3],
                "created_at": crow[4].isoformat() if crow[4] else None
            })
        
        meme["comments"] = comments
        
        cur.close()
        conn.close()
        
        return jsonify(meme), 200
        
    except Exception as e:
        logger.error(f"Error fetching meme {meme_id}: {e}")
        return jsonify({"error": "Failed to fetch meme"}), 500


@app.route("/memes/search", methods=["GET"])
@limiter.limit("30 per minute")
def search_memes():
    """
    Search memes by keyword (public endpoint).
    Uses parameterized queries to prevent SQL injection.
    """
    query = request.args.get("q", "").strip()
    
    is_valid, error = validate_search_query(query)
    if not is_valid:
        return jsonify({"error": error}), 400
    
    try:
        offset = max(0, int(request.args.get("offset", 0)))
        limit = min(50, max(1, int(request.args.get("limit", 20))))
    except ValueError:
        offset, limit = 0, 20
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Parameterized search query (ILIKE for case-insensitive)
        # Using %s placeholder - NEVER string concatenation
        search_pattern = f"%{query}%"
        
        cur.execute("""
            SELECT m.id, m.user_id, m.username, m.title, m.description,
                   m.image_filename, m.created_at,
                   COALESCE(AVG(r.rating), 0) as avg_rating,
                   COUNT(DISTINCT r.id) as rating_count
            FROM memes m
            LEFT JOIN ratings r ON m.id = r.meme_id
            WHERE m.title ILIKE %s OR m.description ILIKE %s
            GROUP BY m.id
            ORDER BY m.created_at DESC
            LIMIT %s OFFSET %s
        """, (search_pattern, search_pattern, limit, offset))
        
        memes = []
        for row in cur.fetchall():
            memes.append({
                "id": row[0],
                "user_id": row[1],
                "username": row[2],
                "title": row[3],
                "description": row[4],
                "image_url": f"/memes/uploads/{row[5]}" if row[5] else None,
                "created_at": row[6].isoformat() if row[6] else None,
                "avg_rating": round(float(row[7]), 1),
                "rating_count": row[8]
            })
        
        # Get search result count
        cur.execute("""
            SELECT COUNT(*) FROM memes
            WHERE title ILIKE %s OR description ILIKE %s
        """, (search_pattern, search_pattern))
        total = cur.fetchone()[0]
        
        cur.close()
        conn.close()
        
        return jsonify({
            "memes": memes,
            "query": query,
            "total": total,
            "offset": offset,
            "limit": limit
        }), 200
        
    except Exception as e:
        logger.error(f"Error searching memes: {e}")
        return jsonify({"error": "Search failed"}), 500


@app.route("/memes", methods=["POST"])
@require_auth
@limiter.limit("10 per minute")
def create_meme():
    """
    Create new meme (authenticated users only).
    Supports optional image upload.
    """
    user = request.current_user
    
    # Handle both JSON and multipart form data
    if request.content_type and "multipart/form-data" in request.content_type:
        title = request.form.get("title")
        description = request.form.get("description")
        image = request.files.get("image")
    else:
        data = request.json or {}
        title = data.get("title")
        description = data.get("description")
        image = None
    
    # Validate title
    is_valid, error = validate_title(title)
    if not is_valid:
        return jsonify({"error": error}), 400
    
    # Validate description
    is_valid, error = validate_description(description)
    if not is_valid:
        return jsonify({"error": error}), 400

    # Require image
    if not image:
        return jsonify({"error": "Image upload is required"}), 400
    
    # Sanitize inputs (HTML escape)
    safe_title = sanitize_text(title, 200)
    safe_description = sanitize_text(description, 2000)
    
    # Handle file upload
    image_filename = None
    image_mimetype = None
    if image:
        result, mime_or_error = secure_save_file(image)
        if result is None:
            return jsonify({"error": mime_or_error}), 400
        image_filename = result
        image_mimetype = mime_or_error
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            INSERT INTO memes (user_id, username, title, description, 
                              image_filename, image_mimetype)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id, created_at
        """, (user["user_id"], user["username"], safe_title, safe_description,
              image_filename, image_mimetype))
        
        result = cur.fetchone()
        meme_id = result[0]
        created_at = result[1]
        
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"Meme created: {meme_id} by user {user['username']}")
        
        return jsonify({
            "message": "Meme created successfully",
            "meme": {
                "id": meme_id,
                "title": safe_title,
                "description": safe_description,
                "image_url": f"/memes/uploads/{image_filename}" if image_filename else None,
                "created_at": created_at.isoformat() if created_at else None
            }
        }), 201
        
    except Exception as e:
        logger.error(f"Error creating meme: {e}")
        # Clean up uploaded file on error
        if image_filename:
            try:
                os.remove(os.path.join(UPLOAD_FOLDER, image_filename))
            except:
                pass
        return jsonify({"error": "Failed to create meme"}), 500


@app.route("/memes/<int:meme_id>", methods=["DELETE"])
@require_auth
@limiter.limit("10 per minute")
def delete_meme(meme_id):
    """
    Delete meme (owner or admin only).
    Implements IDOR protection via server-side ownership check.
    """
    user = request.current_user
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Fetch meme to check ownership
        cur.execute("SELECT user_id, image_filename FROM memes WHERE id = %s", (meme_id,))
        meme = cur.fetchone()
        
        if not meme:
            cur.close()
            conn.close()
            return jsonify({"error": "Meme not found"}), 404
        
        meme_owner_id = meme[0]
        image_filename = meme[1]
        
        # RBAC: Check if user is owner or admin
        if user["user_id"] != meme_owner_id and user["role"] != "admin":
            cur.close()
            conn.close()
            logger.warning(f"Unauthorized delete attempt: user {user['user_id']} on meme {meme_id}")
            return jsonify({"error": "Not authorized to delete this meme"}), 403
        
        # Delete meme (cascade deletes comments and ratings)
        cur.execute("DELETE FROM memes WHERE id = %s", (meme_id,))
        conn.commit()
        cur.close()
        conn.close()
        
        # Delete image file
        if image_filename:
            try:
                os.remove(os.path.join(UPLOAD_FOLDER, image_filename))
            except Exception as e:
                logger.warning(f"Failed to delete image file: {e}")
        
        logger.info(f"Meme {meme_id} deleted by user {user['username']} (role: {user['role']})")
        
        return jsonify({"message": "Meme deleted successfully"}), 200
        
    except Exception as e:
        logger.error(f"Error deleting meme {meme_id}: {e}")
        return jsonify({"error": "Failed to delete meme"}), 500


# ==================== COMMENT ENDPOINTS ====================

@app.route("/memes/<int:meme_id>/comments", methods=["POST"])
@require_auth
@limiter.limit("20 per minute")
def add_comment(meme_id):
    """Add comment to a meme (authenticated users only)."""
    user = request.current_user
    data = request.json or {}
    
    content = data.get("content")
    
    is_valid, error = validate_comment(content)
    if not is_valid:
        return jsonify({"error": error}), 400
    
    # Sanitize content (HTML escape to prevent XSS)
    safe_content = sanitize_text(content, 1000)
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if meme exists
        cur.execute("SELECT id FROM memes WHERE id = %s", (meme_id,))
        if not cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"error": "Meme not found"}), 404
        
        # Insert comment
        cur.execute("""
            INSERT INTO comments (meme_id, user_id, username, content)
            VALUES (%s, %s, %s, %s)
            RETURNING id, created_at
        """, (meme_id, user["user_id"], user["username"], safe_content))
        
        result = cur.fetchone()
        comment_id = result[0]
        created_at = result[1]
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({
            "message": "Comment added",
            "comment": {
                "id": comment_id,
                "user_id": user["user_id"],
                "content": safe_content,
                "username": user["username"],
                "created_at": created_at.isoformat() if created_at else None
            }
        }), 201
        
    except Exception as e:
        logger.error(f"Error adding comment: {e}")
        return jsonify({"error": "Failed to add comment"}), 500


@app.route("/memes/<int:meme_id>/comments/<int:comment_id>", methods=["DELETE"])
@require_auth
@limiter.limit("10 per minute")
def delete_comment(meme_id, comment_id):
    """Delete comment (owner or admin only)."""
    user = request.current_user
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Fetch comment to check ownership
        cur.execute("""
            SELECT user_id FROM comments 
            WHERE id = %s AND meme_id = %s
        """, (comment_id, meme_id))
        comment = cur.fetchone()
        
        if not comment:
            cur.close()
            conn.close()
            return jsonify({"error": "Comment not found"}), 404
        
        comment_owner_id = comment[0]
        
        # RBAC: Check if user is owner or admin
        if int(user["user_id"]) != comment_owner_id and user["role"] != "admin":
            cur.close()
            conn.close()
            return jsonify({"error": "Not authorized to delete this comment"}), 403
        
        # Delete comment
        cur.execute("DELETE FROM comments WHERE id = %s", (comment_id,))
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({"message": "Comment deleted"}), 200
        
    except Exception as e:
        logger.error(f"Error deleting comment: {e}")
        return jsonify({"error": "Failed to delete comment"}), 500


# ==================== RATING ENDPOINTS ====================

@app.route("/memes/<int:meme_id>/rate", methods=["POST"])
@require_auth
@limiter.limit("30 per minute")
def rate_meme(meme_id):
    """
    Rate a meme (authenticated users only).
    One rating per user per meme (upsert).
    """
    user = request.current_user
    data = request.json or {}
    
    rating = data.get("rating")
    
    is_valid, error = validate_rating(rating)
    if not is_valid:
        return jsonify({"error": error}), 400
    
    rating = int(rating)
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if meme exists
        cur.execute("SELECT id FROM memes WHERE id = %s", (meme_id,))
        if not cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"error": "Meme not found"}), 404
        
        # Upsert rating (insert or update on conflict)
        cur.execute("""
            INSERT INTO ratings (meme_id, user_id, rating)
            VALUES (%s, %s, %s)
            ON CONFLICT (meme_id, user_id)
            DO UPDATE SET rating = EXCLUDED.rating, created_at = CURRENT_TIMESTAMP
            RETURNING id
        """, (meme_id, user["user_id"], rating))
        
        rating_id = cur.fetchone()[0]
        
        # Get new average
        cur.execute("""
            SELECT AVG(rating), COUNT(*) FROM ratings WHERE meme_id = %s
        """, (meme_id,))
        result = cur.fetchone()
        avg_rating = round(float(result[0]), 1) if result[0] else 0
        rating_count = result[1]
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({
            "message": "Rating saved",
            "your_rating": rating,
            "avg_rating": avg_rating,
            "rating_count": rating_count
        }), 200
        
    except Exception as e:
        logger.error(f"Error rating meme: {e}")
        return jsonify({"error": "Failed to save rating"}), 500


# ==================== ADMIN ENDPOINTS ====================

@app.route("/admin/users", methods=["GET"])
@require_admin
@limiter.limit("30 per minute")
def list_users():
    """List all users (admin only)."""
    # Note: This queries auth_db, but we're connected to meme_db
    # For proper separation, this should call auth_service API
    # For this lab, we return a message about accessing auth_service
    return jsonify({
        "message": "User management requires accessing auth_service",
        "endpoint": "/admin/users",
        "note": "Implement via auth_service API call in production"
    }), 200


@app.route("/admin/memes", methods=["GET"])
@require_admin
@limiter.limit("30 per minute")
def admin_list_memes():
    """List all memes with admin view (includes user details)."""
    try:
        offset = max(0, int(request.args.get("offset", 0)))
        limit = min(100, max(1, int(request.args.get("limit", 50))))
    except ValueError:
        offset, limit = 0, 50
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT m.id, m.user_id, m.username, m.title, 
                   m.image_filename, m.created_at,
                   COUNT(DISTINCT c.id) as comment_count,
                   COUNT(DISTINCT r.id) as rating_count
            FROM memes m
            LEFT JOIN comments c ON m.id = c.meme_id
            LEFT JOIN ratings r ON m.id = r.meme_id
            GROUP BY m.id
            ORDER BY m.created_at DESC
            LIMIT %s OFFSET %s
        """, (limit, offset))
        
        memes = []
        for row in cur.fetchall():
            memes.append({
                "id": row[0],
                "user_id": row[1],
                "username": row[2],
                "title": row[3],
                "has_image": row[4] is not None,
                "created_at": row[5].isoformat() if row[5] else None,
                "comment_count": row[6],
                "rating_count": row[7]
            })
        
        cur.execute("SELECT COUNT(*) FROM memes")
        total = cur.fetchone()[0]
        
        cur.close()
        conn.close()
        
        return jsonify({
            "memes": memes,
            "total": total,
            "offset": offset,
            "limit": limit
        }), 200
        
    except Exception as e:
        logger.error(f"Admin list memes error: {e}")
        return jsonify({"error": "Failed to fetch memes"}), 500


@app.route("/admin/memes/<int:meme_id>", methods=["DELETE"])
@require_admin
@limiter.limit("10 per minute")
def admin_delete_meme(meme_id):
    """Force delete any meme (admin only)."""
    user = request.current_user
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get meme data for logging and cleanup
        cur.execute("SELECT user_id, username, image_filename FROM memes WHERE id = %s", (meme_id,))
        meme = cur.fetchone()
        
        if not meme:
            cur.close()
            conn.close()
            return jsonify({"error": "Meme not found"}), 404
        
        image_filename = meme[2]
        
        # Delete meme
        cur.execute("DELETE FROM memes WHERE id = %s", (meme_id,))
        conn.commit()
        cur.close()
        conn.close()
        
        # Delete image file
        if image_filename:
            try:
                os.remove(os.path.join(UPLOAD_FOLDER, image_filename))
            except:
                pass
        
        logger.info(f"Admin {user['username']} deleted meme {meme_id} (owner: {meme[1]})")
        
        return jsonify({"message": "Meme deleted by admin"}), 200
        
    except Exception as e:
        logger.error(f"Admin delete meme error: {e}")
        return jsonify({"error": "Failed to delete meme"}), 500


@app.route("/admin/comments/<int:comment_id>", methods=["DELETE"])
@require_admin
@limiter.limit("10 per minute")
def admin_delete_comment(comment_id):
    """Force delete any comment (admin only)."""
    user = request.current_user
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT meme_id, user_id, username FROM comments WHERE id = %s", (comment_id,))
        comment = cur.fetchone()
        
        if not comment:
            cur.close()
            conn.close()
            return jsonify({"error": "Comment not found"}), 404
        
        cur.execute("DELETE FROM comments WHERE id = %s", (comment_id,))
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"Admin {user['username']} deleted comment {comment_id} (owner: {comment[2]})")
        
        return jsonify({"message": "Comment deleted by admin"}), 200
        
    except Exception as e:
        logger.error(f"Admin delete comment error: {e}")
        return jsonify({"error": "Failed to delete comment"}), 500


# ==================== UPLOADS ROUTE ====================

@app.route("/memes/uploads/<filename>")
def serve_meme_upload(filename):
    """Serve uploaded meme images."""
    # Validate filename format (UUID + extension only)
    if not re.match(r'^[a-f0-9]{32}\.(jpg|jpeg|png|gif|webp)$', filename):
        return jsonify({"error": "Invalid filename"}), 400
    return send_from_directory(UPLOAD_FOLDER, filename)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
