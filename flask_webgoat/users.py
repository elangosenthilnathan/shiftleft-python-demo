import sqlite3

from flask import Blueprint, jsonify, session, request

from . import query_db

bp = Blueprint("users", __name__)


@bp.route("/create_user", methods=["POST"])
def create_user():
    user_info = session.get("user_info", None)
    if user_info is None:
def validate_access_level(access_level):
    """Validate access level to ensure it's within expected numeric ranges."""
    # SECURE: Input validation to prevent SQL injection and ensure data integrity
    try:
        level = int(access_level)
        # Assuming valid access levels are 0-10
        if level < 0 or level > 10:
            return False
        return True
    except (ValueError, TypeError):
        return False

            jsonify(
                {
def create_user():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"}), 401

    access_level = user_info[2]
    if access_level != 0:
        return jsonify({"error": "access level of 0 is required for this action"}), 403
    
    username = request.form.get("username")
    password = request.form.get("password")
    access_level_param = request.form.get("access_level")
    
    if username is None or password is None or access_level_param is None:
        return (
            jsonify(
                {
                    "error": "username, password and access_level parameters have to be provided"
                }
            ),
            400,
        )
    
    # SECURE: Validate username format
def validate_username(username):
    """Validate username to allow only alphanumeric characters, underscores, and hyphens."""
    # SECURE: Input validation to prevent SQL injection
    if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
        return False
    return True

            jsonify({"error": "username must be 3-20 characters and contain only alphanumeric characters, underscores, or hyphens"}),
            400,
        )
    
    # SECURE: Validate access level
    if not validate_access_level(access_level_param):
        return (
            jsonify({"error": "access level must be a valid integer between 0 and 10"}),
            400,
        )
    
    if len(password) < 3:
        return (
            jsonify({"error": "the password needs to be at least 3 characters long"}),
            400,
        )
    
    # SECURE: Enforce schema-level constraints at application layer
    # This prevents database errors and provides clearer error messages
    MAX_USERNAME_LENGTH = 20  # Must match database schema
    MAX_PASSWORD_LENGTH = 100  # Must match database schema
    
    # SECURE: Additional length validation matching database constraints
    if len(username) > MAX_USERNAME_LENGTH:
        return (
            jsonify({"error": f"username must not exceed {MAX_USERNAME_LENGTH} characters"}),
            400,
        )
    
    if len(password) > MAX_PASSWORD_LENGTH:
        return (
            jsonify({"error": f"password must not exceed {MAX_PASSWORD_LENGTH} characters"}),
            400,
        )
    
    # SECURE: Explicitly convert access_level to int with bounds checking
    try:
        access_level_int = int(access_level_param)
        if not (0 <= access_level_int <= 10):
            raise ValueError("Access level out of range")
    except (ValueError, TypeError):
        return (
            jsonify({"error": "access level must be a valid integer between 0 and 10"}),
            400,
        )

    # SECURE: Use parameterized query with placeholders to prevent SQL injection
    query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
    
    try:
        # SECURE: Pass parameters with guaranteed types to prevent injection
        query_db(query, (str(username), str(password), access_level_int), False, True)
        return jsonify({"success": True}), 201
    except sqlite3.IntegrityError as e:
        # SECURE: Distinguish between different integrity violations
        error_msg = str(e).lower()
        if 'unique' in error_msg or 'username' in error_msg:
            return jsonify({"error": "username already exists"}), 409
        else:
            return jsonify({"error": "data integrity constraint violated"}), 400
    except sqlite3.DatabaseError as e:
        # SECURE: Handle database-level errors separately from operational errors
        print(f"Database error creating user: {e}")
        return jsonify({"error": "database operation failed"}), 500
    except Exception as e:
        # SECURE: Catch-all for unexpected errors without exposing details
        print(f"Unexpected error creating user: {type(e).__name__}")
        return jsonify({"error": "could not create user due to unexpected error"}), 500
