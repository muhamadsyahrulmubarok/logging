#!/usr/bin/env python3
"""
Log Monitor Web UI
Flask-based web interface for the log monitoring application
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
import mysql.connector
from mysql.connector import Error
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging

app = Flask(__name__)

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
        return f"{SITE_URL}{url_for(endpoint, **values)}"
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
    return dict(site_url=SITE_URL, full_url_for=full_url_for, datetime=datetime)

@app.route('/')
def index():
    """Main dashboard"""
    if not db_manager.connect():
        return render_template('error.html', 
                              error="Database connection failed. Please check your configuration.")
    
    try:
        apps = db_manager.get_apps_overview()
        recent_logs = db_manager.get_recent_logs(limit=20)
        stats = db_manager.get_log_stats(days=7)
        
        return render_template('dashboard.html', 
                             apps=apps, 
                             recent_logs=recent_logs, 
                             stats=stats)
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/logs')
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
