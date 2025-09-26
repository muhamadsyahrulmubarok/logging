#!/usr/bin/env python3
"""
Log Monitor Web UI
Flask-based web interface for the log monitoring application
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
import mysql.connector
from mysql.connector import Error
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, is_active=True):
        self.id = id
        self.username = username
        self.email = email
        self._is_active = is_active
    
    @property
    def is_active(self):
        return self._is_active
    
    @is_active.setter
    def is_active(self, value):
        self._is_active = value

@login_manager.user_loader
def load_user(user_id):
    """Load user from database"""
    if not db_manager.connect():
        return None
    
    cursor = db_manager.connection.cursor(dictionary=True)
    try:
        query = "SELECT id, username, email, is_active FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))
        user_data = cursor.fetchone()
        
        if user_data:
            return User(
                id=user_data['id'],
                username=user_data['username'],
                email=user_data['email'],
                is_active=user_data['is_active']
            )
    except Error as e:
        logging.error(f"Error loading user: {e}")
    finally:
        cursor.close()
    
    return None

# Load SITE_URL from environment or config
def get_site_url():
    """Get SITE_URL from environment or config file"""
    site_url = os.getenv('SITE_URL', '').rstrip('/')
    if not site_url and os.path.exists('config.json'):
        try:
            with open('config.json', 'r') as f:
                config = json.load(f)
                site_url = config.get('site_url', '').rstrip('/')
        except Exception:
            pass
    return site_url

SITE_URL = get_site_url()

# Custom template function for full URLs
def full_url_for(endpoint, **values):
    """Generate full URL with SITE_URL prefix"""
    if SITE_URL:
        # Ensure SITE_URL doesn't have trailing slash and url_for result starts with /
        site_url = SITE_URL.rstrip('/')
        url_path = url_for(endpoint, **values)
        return f"{site_url}{url_path}"
    return url_for(endpoint, **values)

class WebDatabaseManager:
    """Database manager for web interface"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.connection = None
        
    def connect(self):
        """Establish database connection"""
        try:
            self.connection = mysql.connector.connect(
                host=self.config['host'],
                database=self.config['database'],
                user=self.config['user'],
                password=self.config['password'],
                port=self.config.get('port', 3306)
            )
            return self.connection.is_connected()
        except Error as e:
            logging.error(f"Error connecting to MySQL: {e}")
            return False
    
    def get_apps_overview(self) -> List[Dict]:
        """Get overview of monitored applications"""
        cursor = self.connection.cursor(dictionary=True)
        
        try:
            query = """
            SELECT 
                app_name,
                last_log_timestamp,
                total_logs,
                status,
                created_at,
                updated_at
            FROM monitored_apps 
            ORDER BY last_log_timestamp DESC
            """
            cursor.execute(query)
            return cursor.fetchall()
        except Error as e:
            logging.error(f"Error fetching apps overview: {e}")
            return []
        finally:
            cursor.close()
    
    def get_recent_logs(self, limit: int = 50, app_name: str = None, log_type: str = None) -> List[Dict]:
        """Get recent log entries"""
        cursor = self.connection.cursor(dictionary=True)
        
        try:
            query = """
            SELECT 
                id, app_name, log_type, timestamp, file_name, 
                file_size, processed_at
            FROM log_entries 
            WHERE 1=1
            """
            params = []
            
            if app_name:
                query += " AND app_name = %s"
                params.append(app_name)
            
            if log_type:
                query += " AND log_type = %s"
                params.append(log_type)
            
            query += " ORDER BY timestamp DESC LIMIT %s"
            params.append(limit)
            
            cursor.execute(query, params)
            return cursor.fetchall()
        except Error as e:
            logging.error(f"Error fetching recent logs: {e}")
            return []
        finally:
            cursor.close()
    
    def get_log_details(self, log_id: int) -> Optional[Dict]:
        """Get detailed log entry"""
        cursor = self.connection.cursor(dictionary=True)
        
        try:
            query = """
            SELECT 
                id, app_name, log_type, timestamp, file_name, 
                file_hash, log_content, file_size, processed_at
            FROM log_entries 
            WHERE id = %s
            """
            cursor.execute(query, (log_id,))
            return cursor.fetchone()
        except Error as e:
            logging.error(f"Error fetching log details: {e}")
            return None
        finally:
            cursor.close()
    
    def get_log_stats(self, days: int = 7) -> Dict:
        """Get log statistics for the specified period"""
        cursor = self.connection.cursor(dictionary=True)
        
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            
            # Total logs in period
            query = "SELECT COUNT(*) as total FROM log_entries WHERE timestamp >= %s"
            cursor.execute(query, (cutoff_date,))
            total_logs = cursor.fetchone()['total']
            
            # Logs by type
            query = """
            SELECT log_type, COUNT(*) as count 
            FROM log_entries 
            WHERE timestamp >= %s 
            GROUP BY log_type
            """
            cursor.execute(query, (cutoff_date,))
            logs_by_type = {row['log_type']: row['count'] for row in cursor.fetchall()}
            
            # Logs by app
            query = """
            SELECT app_name, COUNT(*) as count 
            FROM log_entries 
            WHERE timestamp >= %s 
            GROUP BY app_name 
            ORDER BY count DESC 
            LIMIT 10
            """
            cursor.execute(query, (cutoff_date,))
            logs_by_app = {row['app_name']: row['count'] for row in cursor.fetchall()}
            
            # Daily log counts
            query = """
            SELECT DATE(timestamp) as date, COUNT(*) as count 
            FROM log_entries 
            WHERE timestamp >= %s 
            GROUP BY DATE(timestamp) 
            ORDER BY date DESC
            """
            cursor.execute(query, (cutoff_date,))
            daily_logs = {str(row['date']): row['count'] for row in cursor.fetchall()}
            
            return {
                'total_logs': total_logs,
                'logs_by_type': logs_by_type,
                'logs_by_app': logs_by_app,
                'daily_logs': daily_logs
            }
        except Error as e:
            logging.error(f"Error fetching log stats: {e}")
            return {}
        finally:
            cursor.close()
    
    def search_logs(self, search_term: str, app_name: str = None, log_type: str = None, 
                   start_date: str = None, end_date: str = None, limit: int = 100) -> List[Dict]:
        """Search logs with filters"""
        cursor = self.connection.cursor(dictionary=True)
        
        try:
            query = """
            SELECT 
                id, app_name, log_type, timestamp, file_name, 
                file_size, processed_at
            FROM log_entries 
            WHERE 1=1
            """
            params = []
            
            if search_term:
                query += " AND (log_content LIKE %s OR file_name LIKE %s)"
                params.extend([f"%{search_term}%", f"%{search_term}%"])
            
            if app_name:
                query += " AND app_name = %s"
                params.append(app_name)
            
            if log_type:
                query += " AND log_type = %s"
                params.append(log_type)
            
            if start_date:
                query += " AND timestamp >= %s"
                params.append(start_date)
            
            if end_date:
                query += " AND timestamp <= %s"
                params.append(end_date)
            
            query += " ORDER BY timestamp DESC LIMIT %s"
            params.append(limit)
            
            cursor.execute(query, params)
            return cursor.fetchall()
        except Error as e:
            logging.error(f"Error searching logs: {e}")
            return []
        finally:
            cursor.close()
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate user with username and password"""
        cursor = self.connection.cursor(dictionary=True)
        
        try:
            query = """
            SELECT id, username, password_hash, email, is_active 
            FROM users 
            WHERE username = %s AND is_active = TRUE
            """
            cursor.execute(query, (username,))
            user_data = cursor.fetchone()
            
            if user_data and check_password_hash(user_data['password_hash'], password):
                # Update last login
                update_query = "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s"
                cursor.execute(update_query, (user_data['id'],))
                self.connection.commit()
                
                return {
                    'id': user_data['id'],
                    'username': user_data['username'],
                    'email': user_data['email'],
                    'is_active': user_data['is_active']
                }
        except Error as e:
            logging.error(f"Error authenticating user: {e}")
        finally:
            cursor.close()
        
        return None
    
    def create_user(self, username: str, password: str, email: str = None) -> bool:
        """Create a new user"""
        cursor = self.connection.cursor()
        
        try:
            password_hash = generate_password_hash(password)
            query = """
            INSERT INTO users (username, password_hash, email, is_active)
            VALUES (%s, %s, %s, TRUE)
            """
            cursor.execute(query, (username, password_hash, email))
            self.connection.commit()
            return True
        except Error as e:
            logging.error(f"Error creating user: {e}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()
    
    def update_user_profile(self, user_id: int, username: str = None, email: str = None) -> bool:
        """Update user profile information"""
        cursor = self.connection.cursor()
        
        try:
            updates = []
            params = []
            
            if username is not None:
                updates.append("username = %s")
                params.append(username)
            
            if email is not None:
                updates.append("email = %s")
                params.append(email)
            
            if not updates:
                return True
            
            updates.append("updated_at = CURRENT_TIMESTAMP")
            params.append(user_id)
            
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = %s"
            cursor.execute(query, params)
            self.connection.commit()
            return cursor.rowcount > 0
            
        except Error as e:
            logging.error(f"Error updating user profile: {e}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()
    
    def change_user_password(self, user_id: int, current_password: str, new_password: str) -> bool:
        """Change user password"""
        cursor = self.connection.cursor(dictionary=True)
        
        try:
            # First verify current password
            query = "SELECT password_hash FROM users WHERE id = %s"
            cursor.execute(query, (user_id,))
            user_data = cursor.fetchone()
            
            if not user_data or not check_password_hash(user_data['password_hash'], current_password):
                return False
            
            # Update password
            new_password_hash = generate_password_hash(new_password)
            update_query = "UPDATE users SET password_hash = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s"
            cursor.execute(update_query, (new_password_hash, user_id))
            self.connection.commit()
            return cursor.rowcount > 0
            
        except Error as e:
            logging.error(f"Error changing password: {e}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()

# Load configuration
def load_config():
    """Load configuration from config.json or use defaults"""
    default_config = {
        "database": {
            "host": "localhost",
            "database": "log_monitor",
            "user": "root",
            "password": "root",
            "port": 3306
        }
    }
    
    if os.path.exists('config.json'):
        try:
            with open('config.json', 'r') as f:
                user_config = json.load(f)
                if 'database' in user_config:
                    default_config['database'].update(user_config['database'])
        except Exception as e:
            logging.error(f"Error loading config: {e}")
    
    return default_config

# Initialize database manager
config = load_config()
db_manager = WebDatabaseManager(config['database'])

# Make SITE_URL, full_url_for, and datetime available in all templates
@app.context_processor
def inject_site_url():
    from flask_login import current_user, AnonymousUserMixin
    
    # Safely get current_user, return AnonymousUserMixin if not available
    try:
        user = current_user
        # Ensure user has is_authenticated attribute
        if not hasattr(user, 'is_authenticated'):
            user = AnonymousUserMixin()
    except:
        user = AnonymousUserMixin()
    
    return dict(
        site_url=SITE_URL, 
        full_url_for=full_url_for, 
        datetime=datetime, 
        current_user=user
    )

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')
        
        if not db_manager.connect():
            flash('Database connection failed. Please try again later.', 'error')
            return render_template('login.html')
        
        user_data = db_manager.authenticate_user(username, password)
        
        if user_data:
            user = User(
                id=user_data['id'],
                username=user_data['username'],
                email=user_data['email'],
                is_active=user_data['is_active']
            )
            login_user(user)
            flash(f'Welcome back, {user.username}!', 'success')
            
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email = request.form.get('email')
        
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html')
        
        if not db_manager.connect():
            flash('Database connection failed. Please try again later.', 'error')
            return render_template('register.html')
        
        if db_manager.create_user(username, password, email):
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration failed. Username may already exist.', 'error')
    
    return render_template('register.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile/settings page"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if not db_manager.connect():
            flash('Database connection failed. Please try again later.', 'error')
            return render_template('profile.html')
        
        if action == 'update_profile':
            username = request.form.get('username')
            email = request.form.get('email')
            
            if not username:
                flash('Username is required.', 'error')
                return render_template('profile.html')
            
            if db_manager.update_user_profile(current_user.id, username, email):
                flash('Profile updated successfully!', 'success')
                # Update current user object
                current_user.username = username
                current_user.email = email
                # Note: is_active is handled by the property setter
            else:
                flash('Failed to update profile. Username may already be taken.', 'error')
        
        elif action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not current_password or not new_password:
                flash('All password fields are required.', 'error')
                return render_template('profile.html')
            
            if new_password != confirm_password:
                flash('New passwords do not match.', 'error')
                return render_template('profile.html')
            
            if len(new_password) < 6:
                flash('New password must be at least 6 characters long.', 'error')
                return render_template('profile.html')
            
            if db_manager.change_user_password(current_user.id, current_password, new_password):
                flash('Password changed successfully!', 'success')
            else:
                flash('Failed to change password. Current password may be incorrect.', 'error')
    
    return render_template('profile.html')

# Global error handler
@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors"""
    logging.error(f"Internal server error: {error}")
    return render_template('error.html', error="An internal server error occurred. Please try again later.")

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    return render_template('error.html', error="The requested page was not found.")

@app.route('/')
@login_required
def index():
    """Main dashboard"""
    try:
        if not db_manager.connect():
            return render_template('error.html', 
                                  error="Database connection failed. Please check your configuration.")
        
        apps = db_manager.get_apps_overview()
        recent_logs = db_manager.get_recent_logs(limit=20)
        stats = db_manager.get_log_stats(days=7)
        
        return render_template('dashboard.html', 
                             apps=apps, 
                             recent_logs=recent_logs, 
                             stats=stats)
    except Exception as e:
        logging.error(f"Error in index route: {e}")
        return render_template('error.html', error=str(e))

@app.route('/logs')
@login_required
def logs():
    """Logs listing page"""
    if not db_manager.connect():
        return render_template('error.html', 
                              error="Database connection failed.")
    
    try:
        # Get filter parameters
        app_name = request.args.get('app_name')
        log_type = request.args.get('log_type')
        search = request.args.get('search')
        page = int(request.args.get('page', 1))
        per_page = 50
        
        # Get logs
        logs = db_manager.search_logs(
            search_term=search,
            app_name=app_name,
            log_type=log_type,
            limit=per_page
        )
        
        # Get apps for filter dropdown
        apps = db_manager.get_apps_overview()
        
        return render_template('logs.html', 
                             logs=logs, 
                             apps=apps,
                             current_app=app_name,
                             current_type=log_type,
                             current_search=search)
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/log/<int:log_id>')
@login_required
def log_detail(log_id):
    """Log detail page"""
    if not db_manager.connect():
        return render_template('error.html', 
                              error="Database connection failed.")
    
    try:
        log = db_manager.get_log_details(log_id)
        if not log:
            return render_template('error.html', error="Log entry not found.")
        
        return render_template('log_detail.html', log=log)
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/apps')
@login_required
def apps():
    """Applications overview page"""
    if not db_manager.connect():
        return render_template('error.html', 
                              error="Database connection failed.")
    
    try:
        apps = db_manager.get_apps_overview()
        return render_template('apps.html', apps=apps)
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/api/stats')
@login_required
def api_stats():
    """API endpoint for statistics"""
    if not db_manager.connect():
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        days = int(request.args.get('days', 7))
        stats = db_manager.get_log_stats(days)
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
@login_required
def api_logs():
    """API endpoint for logs"""
    if not db_manager.connect():
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        app_name = request.args.get('app_name')
        log_type = request.args.get('log_type')
        search = request.args.get('search')
        limit = int(request.args.get('limit', 50))
        
        logs = db_manager.search_logs(
            search_term=search,
            app_name=app_name,
            log_type=log_type,
            limit=limit
        )
        
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
