import os
from flask import Flask
from dotenv import load_dotenv
import os

load_dotenv()  # Load environment variables from .env file
from flask_login import current_user, login_user, logout_user, login_required, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
import secrets
import pymysql
from flask_wtf.csrf import CSRFProtect
from flask_limiter.errors import RateLimitExceeded

# Import extensions
from extensions import db, login_manager, bcrypt, limiter

# Load environment variables
load_dotenv()

# Initialize CSRF protection
csrf = CSRFProtect()

# MySQL connection
pymysql.install_as_MySQLdb()

# Create Flask application
def create_app():
    app = Flask(__name__)
#==================================================================================================  
# Log Missing SECRET_KEY if SECRET_KEY isn’t set, warn developers.
    if 'SECRET_KEY' not in os.environ:
        print("WARNING: SECRET_KEY not set. Using insecure random key.")
    # Secure Data Storage: SECRET_KEY is critical for session signing and encryption.
    # Ensure it is set securely in environment variables and never hardcoded.
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(16)

    # Session Management: Set secure session cookie flags to protect session cookies.
    app.config['SESSION_COOKIE_SECURE'] = True  # Ensures cookies are sent over HTTPS only.
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevents JavaScript access to cookies.
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Helps prevent CSRF attacks.

    # Session Management: Set session timeout to 30 minutes to reduce risk of hijacking.
    from datetime import timedelta
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
#==================================================================================================  

    # CSRF Protection: Initialize CSRF protection to secure forms against CSRF attacks.
    csrf.init_app(app)

    # Database configuration

    # Construct the MySQL URL from individual environment variables if DATABASE_URL is not provided
    # Use defaults to avoid None values
#==================================================================================================    
# Improve Environment Variable Handling to avoid silent failures if a required environment variable is not set.
    required_env_vars = ['MYSQL_USER', 'MYSQL_PASSWORD', 'MYSQL_HOST', 'MYSQL_DATABASE']
    missing = [var for var in required_env_vars if not os.environ.get(var)]
    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

    mysql_user = os.environ['MYSQL_USER']
    mysql_password = os.environ['MYSQL_PASSWORD']
    mysql_host = os.environ['MYSQL_HOST']
    mysql_port = os.environ.get('MYSQL_PORT', '3306')
    mysql_database = os.environ['MYSQL_DATABASE']
#==================================================================================================
    
    # Make sure all values are strings
    mysql_port = str(mysql_port)
    
    # Check if required parameters are set
    if not mysql_host or not mysql_user or not mysql_database:
        print(f"WARNING: Missing database configuration. Host: {mysql_host}, User: {mysql_user}, Database: {mysql_database}")
    
    db_uri = f"mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}:{mysql_port}/{mysql_database}"
    print(f"Database URI: {db_uri}")
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    # Authentication and Authorization: Enable strong session protection to prevent session fixation.
    login_manager.session_protection = "strong"  # Enable strong session protection
    bcrypt.init_app(app)
    limiter.init_app(app)
    
    # Rate Limiting: Register custom error handler for rate limiting to handle abuse gracefully.
    @app.errorhandler(RateLimitExceeded)
    def handle_rate_limit_exceeded(e):
        # Check if it's an API request (expecting JSON)
        if request.path.startswith('/api/') or request.headers.get('Accept') == 'application/json':
            return jsonify({"error": "Rate limit exceeded", "message": str(e)}), 429
        # Otherwise, return the HTML template
        return render_template('rate_limit_error.html', message=str(e)), 429

    # Error Handling: Global error handler for unhandled exceptions to avoid exposing sensitive info.
    @app.errorhandler(Exception)
    def handle_exception(e):
        app.logger.error(f"Unhandled exception: {e}", exc_info=True)
        # Return generic error message without sensitive details
        if request.path.startswith('/api/') or request.headers.get('Accept') == 'application/json':
            return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred."}), 500
        return render_template('error.html', message="An unexpected error occurred."), 500

    # Error Handling: Handle 404 errors with custom response.
    @app.errorhandler(404)
    def handle_404(e):
        if request.path.startswith('/api/') or request.headers.get('Accept') == 'application/json':
            return jsonify({"error": "Not Found", "message": "The requested resource was not found."}), 404
        return render_template('404.html'), 404

    return app

# Create Flask app
app = create_app()

# Import models - must be after db initialization
from models import User, Transaction

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Import routes after app creation
from routes import *

# Database initialization function
def init_db():
    """Initialize the database with required tables and default admin user."""
    with app.app_context():
        db.create_all()
        # Check if there are admin users, if not create one
        admin = User.query.filter_by(is_admin=True).first()
        if not admin:
            admin_user = User(
                username="admin",
                email="admin@bankapp.com",
                account_number="0000000001",
                status="active",
                is_admin=True,
                balance=0.0
            )
            admin_user.set_password("admin123")
            db.session.add(admin_user)
            db.session.commit()
            print("Created admin user with username 'admin' and password 'admin123'")

if __name__ == '__main__':
    # Print environment variables for debugging
    print(f"Environment variables:")
    print(f"MYSQL_HOST: {os.environ.get('MYSQL_HOST')}")
    print(f"MYSQL_USER: {os.environ.get('MYSQL_USER')}")
    print(f"MYSQL_DATABASE: {os.environ.get('MYSQL_DATABASE')}")
    
    with app.app_context():
        db.create_all()
    app.run(debug=True) 