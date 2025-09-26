#!/usr/bin/env python3
"""
Complete Log Monitor Application with Web UI
Combines log monitoring functionality with Flask web interface
Monitors log files from multiple applications and provides web dashboard
"""

import os
import re
import gzip
import mysql.connector
from mysql.connector import Error
import logging
from datetime import datetime, timedelta
import time
import json
from pathlib import Path
import hashlib
from typing import Dict, List, Optional, Tuple
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import queue
from dotenv import load_dotenv

# Flask imports
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

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

# ============================================================================
# DATABASE MANAGEMENT
# ============================================================================

class DatabaseManager:
    """Manages MySQL database operations for log storage"""
    
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
            
            if self.connection.is_connected():
                logging.info("Connected to MySQL database")
                self._create_tables()
                return True
                
        except Error as e:
            logging.error(f"Error connecting to MySQL: {e}")
            return False
    
    def _create_tables(self):
        """Create necessary tables if they don't exist"""
        cursor = self.connection.cursor()
        
        # Table for log entries
        create_logs_table = """
        CREATE TABLE IF NOT EXISTS log_entries (
            id INT AUTO_INCREMENT PRIMARY KEY,
            app_name VARCHAR(255) NOT NULL,
            log_type VARCHAR(50) NOT NULL,
            timestamp DATETIME NOT NULL,
            file_name VARCHAR(500) NOT NULL,
            file_hash VARCHAR(64) UNIQUE,
            log_content LONGTEXT,
            file_size BIGINT,
            processed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_app_timestamp (app_name, timestamp),
            INDEX idx_file_hash (file_hash),
            INDEX idx_processed_at (processed_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        
        # Table for monitoring apps
        create_apps_table = """
        CREATE TABLE IF NOT EXISTS monitored_apps (
            id INT AUTO_INCREMENT PRIMARY KEY,
            app_name VARCHAR(255) UNIQUE NOT NULL,
            last_log_timestamp DATETIME,
            total_logs INT DEFAULT 0,
            status VARCHAR(50) DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        
        # Table for file processing status
        create_files_table = """
        CREATE TABLE IF NOT EXISTS processed_files (
            id INT AUTO_INCREMENT PRIMARY KEY,
            file_path VARCHAR(1000) NOT NULL,
            file_hash VARCHAR(64) UNIQUE,
            file_size BIGINT,
            processed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(50) DEFAULT 'processed',
            error_message TEXT,
            INDEX idx_file_path (file_path(255)),
            INDEX idx_processed_at (processed_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        
        try:
            cursor.execute(create_logs_table)
            cursor.execute(create_apps_table)
            cursor.execute(create_files_table)
            self.connection.commit()
            logging.info("Database tables created/verified successfully")
        except Error as e:
            logging.error(f"Error creating tables: {e}")
        finally:
            cursor.close()
    
    def insert_log_entry(self, app_name: str, log_type: str, timestamp: datetime, 
                        file_name: str, file_hash: str, log_content: str, file_size: int):
        """Insert a log entry into the database"""
        cursor = self.connection.cursor()
        
        try:
            query = """
            INSERT INTO log_entries 
            (app_name, log_type, timestamp, file_name, file_hash, log_content, file_size)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE processed_at = CURRENT_TIMESTAMP
            """
            
            cursor.execute(query, (app_name, log_type, timestamp, file_name, 
                                 file_hash, log_content, file_size))
            
            # Update monitored apps
            self.update_app_stats(app_name, timestamp)
            
            self.connection.commit()
            return cursor.lastrowid
            
        except Error as e:
            logging.error(f"Error inserting log entry: {e}")
            self.connection.rollback()
            return None
        finally:
            cursor.close()
    
    def update_app_stats(self, app_name: str, last_timestamp: datetime):
        """Update application statistics"""
        cursor = self.connection.cursor()
        
        try:
            query = """
            INSERT INTO monitored_apps (app_name, last_log_timestamp, total_logs)
            VALUES (%s, %s, 1)
            ON DUPLICATE KEY UPDATE
            last_log_timestamp = GREATEST(last_log_timestamp, %s),
            total_logs = total_logs + 1,
            updated_at = CURRENT_TIMESTAMP
            """
            
            cursor.execute(query, (app_name, last_timestamp, last_timestamp))
            self.connection.commit()
            
        except Error as e:
            logging.error(f"Error updating app stats: {e}")
        finally:
            cursor.close()
    
    def mark_file_processed(self, file_path: str, file_hash: str, file_size: int, 
                           status: str = 'processed', error_message: str = None):
        """Mark a file as processed"""
        cursor = self.connection.cursor()
        
        try:
            query = """
            INSERT INTO processed_files (file_path, file_hash, file_size, status, error_message)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            status = VALUES(status),
            error_message = VALUES(error_message),
            processed_at = CURRENT_TIMESTAMP
            """
            
            cursor.execute(query, (file_path, file_hash, file_size, status, error_message))
            self.connection.commit()
            
        except Error as e:
            logging.error(f"Error marking file processed: {e}")
        finally:
            cursor.close()
    
    def is_file_processed(self, file_hash: str) -> bool:
        """Check if a file has already been processed"""
        cursor = self.connection.cursor()
        
        try:
            query = "SELECT id FROM processed_files WHERE file_hash = %s AND status = 'processed'"
            cursor.execute(query, (file_hash,))
            result = cursor.fetchone()
            return result is not None
            
        except Error as e:
            logging.error(f"Error checking file status: {e}")
            return False
        finally:
            cursor.close()
    
    def cleanup_old_logs(self, days_to_keep: int = 90):
        """Clean up old log entries to manage database size"""
        cursor = self.connection.cursor()
        
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            
            # Delete old log entries
            query = "DELETE FROM log_entries WHERE processed_at < %s"
            cursor.execute(query, (cutoff_date,))
            deleted_logs = cursor.rowcount
            
            # Delete old processed file records
            query = "DELETE FROM processed_files WHERE processed_at < %s"
            cursor.execute(query, (cutoff_date,))
            deleted_files = cursor.rowcount
            
            self.connection.commit()
            
            logging.info(f"Cleaned up {deleted_logs} old log entries and {deleted_files} file records")
            
        except Error as e:
            logging.error(f"Error during cleanup: {e}")
        finally:
            cursor.close()
    
    # Web UI specific methods
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

# ============================================================================
# LOG PARSING AND PROCESSING
# ============================================================================

class LogParser:
    """Parses log file names and extracts information"""
    
    @staticmethod
    def parse_filename(filename: str) -> Optional[Tuple[str, str, datetime]]:
        """
        Parse filename to extract app name, log type, and timestamp
        Expected format: api-nbagroup-error__2025-09-22_14-00-00.log.gz
        Returns: (app_name, log_type, timestamp)
        """
        # Remove .gz extension if present
        if filename.endswith('.gz'):
            filename = filename[:-3]
        
        # Remove .log extension if present
        if filename.endswith('.log'):
            filename = filename[:-4]
        
        # Pattern to match the filename format
        pattern = r'^(.+?)-(error|out|info|debug|warn)__(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})$'
        match = re.match(pattern, filename)
        
        if match:
            app_name = match.group(1)
            log_type = match.group(2)
            timestamp_str = match.group(3)
            
            try:
                # Parse timestamp
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d_%H-%M-%S')
                return app_name, log_type, timestamp
            except ValueError as e:
                logging.error(f"Error parsing timestamp from {filename}: {e}")
                return None
        
        logging.warning(f"Filename format not recognized: {filename}")
        return None

class LogFileProcessor:
    """Processes individual log files"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file contents"""
        hasher = hashlib.sha256()
        
        try:
            if file_path.endswith('.gz'):
                with gzip.open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hasher.update(chunk)
            else:
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hasher.update(chunk)
                        
            return hasher.hexdigest()
            
        except Exception as e:
            logging.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def read_log_content(self, file_path: str, max_size_mb: int = 10) -> Optional[str]:
        """Read log file content, handling compressed files"""
        max_size_bytes = max_size_mb * 1024 * 1024
        
        try:
            file_size = os.path.getsize(file_path)
            if file_size > max_size_bytes:
                logging.warning(f"File {file_path} is too large ({file_size} bytes), skipping content read")
                return f"[File too large: {file_size} bytes]"
            
            if file_path.endswith('.gz'):
                with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            else:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
            return content
            
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")
            return None
    
    def process_log_file(self, file_path: str) -> bool:
        """Process a single log file"""
        try:
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            # Calculate file hash to avoid duplicates
            file_hash = self.calculate_file_hash(file_path)
            if not file_hash:
                return False
            
            # Check if already processed
            if self.db_manager.is_file_processed(file_hash):
                logging.info(f"File {filename} already processed, skipping")
                return True
            
            # Parse filename
            parsed = LogParser.parse_filename(filename)
            if not parsed:
                self.db_manager.mark_file_processed(file_path, file_hash, file_size, 
                                                  'error', 'Failed to parse filename')
                return False
            
            app_name, log_type, timestamp = parsed
            
            # Read file content
            log_content = self.read_log_content(file_path)
            if log_content is None:
                self.db_manager.mark_file_processed(file_path, file_hash, file_size,
                                                  'error', 'Failed to read file content')
                return False
            
            # Insert into database
            log_id = self.db_manager.insert_log_entry(
                app_name=app_name,
                log_type=log_type,
                timestamp=timestamp,
                file_name=filename,
                file_hash=file_hash,
                log_content=log_content,
                file_size=file_size
            )
            
            if log_id:
                self.db_manager.mark_file_processed(file_path, file_hash, file_size)
                logging.info(f"Successfully processed {filename} -> Log ID: {log_id}")
                return True
            else:
                self.db_manager.mark_file_processed(file_path, file_hash, file_size,
                                                  'error', 'Failed to insert into database')
                return False
                
        except Exception as e:
            logging.error(f"Error processing file {file_path}: {e}")
            return False

# ============================================================================
# FILE SYSTEM MONITORING
# ============================================================================

class LogFileHandler(FileSystemEventHandler):
    """Handles file system events for log file monitoring"""
    
    def __init__(self, processor: LogFileProcessor, file_queue: queue.Queue):
        self.processor = processor
        self.file_queue = file_queue
        
    def on_created(self, event):
        if event.is_directory:
            return
            
        file_path = event.src_path
        if self._is_log_file(file_path):
            logging.info(f"New log file detected: {file_path}")
            self.file_queue.put(file_path)
    
    def on_moved(self, event):
        if event.is_directory:
            return
            
        file_path = event.dest_path
        if self._is_log_file(file_path):
            logging.info(f"Log file moved to: {file_path}")
            self.file_queue.put(file_path)
    
    def _is_log_file(self, file_path: str) -> bool:
        """Check if file is a log file we should process"""
        filename = os.path.basename(file_path)
        return (filename.endswith('.log') or filename.endswith('.log.gz')) and '__' in filename

# ============================================================================
# LOG MONITOR CLASS
# ============================================================================

class LogMonitor:
    """Main log monitoring application"""
    
    def __init__(self, config_path: str = 'config.json'):
        self.config = self._load_config(config_path)
        self.db_manager = DatabaseManager(self.config['database'])
        self.processor = LogFileProcessor(self.db_manager)
        self.file_queue = queue.Queue()
        self.observer = None
        self.worker_thread = None
        self.running = False
        
        # Setup logging
        self._setup_logging()
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from JSON file and environment variables"""
        # Load environment variables from .env file
        load_dotenv()
        
        default_config = {
            "database": {
                "host": os.getenv("DB_HOST", "localhost"),
                "database": os.getenv("DB_NAME", "log_monitor"),
                "user": os.getenv("DB_USER", "log_user"),
                "password": os.getenv("DB_PASSWORD", "log_password"),
                "port": int(os.getenv("DB_PORT", "3306"))
            },
            "monitoring": {
                "watch_directory": os.getenv("WATCH_DIRECTORY", "./logs"),
                "max_file_size_mb": int(os.getenv("MAX_FILE_SIZE_MB", "10")),
                "cleanup_days": int(os.getenv("CLEANUP_DAYS", "90")),
                "cleanup_interval_hours": int(os.getenv("CLEANUP_INTERVAL_HOURS", "24"))
            },
            "logging": {
                "level": os.getenv("LOG_LEVEL", "INFO"),
                "file": os.getenv("LOG_FILE", "log_monitor.log"),
                "max_bytes": int(os.getenv("LOG_MAX_BYTES", "10485760")),
                "backup_count": int(os.getenv("LOG_BACKUP_COUNT", "5"))
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    
                # Merge configs (JSON config overrides environment variables)
                for key, value in user_config.items():
                    if isinstance(value, dict) and key in default_config:
                        default_config[key].update(value)
                    else:
                        default_config[key] = value
        except Exception as e:
            logging.error(f"Error loading config: {e}, using defaults")
        
        return default_config
    
    def _setup_logging(self):
        """Setup logging configuration"""
        from logging.handlers import RotatingFileHandler
        
        log_config = self.config['logging']
        
        # Create logs directory if it doesn't exist
        log_dir = os.path.dirname(log_config['file'])
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            level=getattr(logging, log_config['level']),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                RotatingFileHandler(
                    log_config['file'],
                    maxBytes=log_config['max_bytes'],
                    backupCount=log_config['backup_count']
                ),
                logging.StreamHandler()
            ]
        )
    
    def _process_files_worker(self):
        """Worker thread to process files from the queue"""
        while self.running:
            try:
                file_path = self.file_queue.get(timeout=1)
                self.processor.process_log_file(file_path)
                self.file_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Error in worker thread: {e}")
    
    def scan_existing_files(self, directory: str):
        """Scan directory for existing log files and process them"""
        logging.info(f"Scanning existing files in {directory}")
        
        if not os.path.exists(directory):
            logging.warning(f"Directory {directory} does not exist")
            return
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if self._is_log_file(file_path):
                    self.file_queue.put(file_path)
        
        logging.info(f"Queued {self.file_queue.qsize()} files for processing")
    
    def _is_log_file(self, file_path: str) -> bool:
        """Check if file is a log file we should process"""
        filename = os.path.basename(file_path)
        return (filename.endswith('.log') or filename.endswith('.log.gz')) and '__' in filename
    
    def start_monitoring(self):
        """Start the log monitoring service"""
        logging.info("Starting Log Monitor Application")
        
        # Connect to database
        if not self.db_manager.connect():
            logging.error("Failed to connect to database, exiting")
            return False
        
        # Create watch directory if it doesn't exist
        watch_dir = self.config['monitoring']['watch_directory']
        os.makedirs(watch_dir, exist_ok=True)
        
        # Process existing files
        self.scan_existing_files(watch_dir)
        
        # Start worker thread
        self.running = True
        self.worker_thread = threading.Thread(target=self._process_files_worker)
        self.worker_thread.daemon = True
        self.worker_thread.start()
        
        # Setup file system monitoring
        event_handler = LogFileHandler(self.processor, self.file_queue)
        self.observer = Observer()
        self.observer.schedule(event_handler, watch_dir, recursive=True)
        self.observer.start()
        
        logging.info(f"Monitoring started on directory: {watch_dir}")
        
        # Start cleanup scheduler
        self._schedule_cleanup()
        
        return True
    
    def _schedule_cleanup(self):
        """Schedule periodic database cleanup"""
        def cleanup_worker():
            while self.running:
                try:
                    cleanup_interval = self.config['monitoring']['cleanup_interval_hours'] * 3600
                    time.sleep(cleanup_interval)
                    
                    if self.running:
                        days_to_keep = self.config['monitoring']['cleanup_days']
                        self.db_manager.cleanup_old_logs(days_to_keep)
                except Exception as e:
                    logging.error(f"Error in cleanup worker: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_worker)
        cleanup_thread.daemon = True
        cleanup_thread.start()
    
    def stop_monitoring(self):
        """Stop the monitoring service"""
        logging.info("Stopping Log Monitor Application")
        
        self.running = False
        
        if self.observer:
            self.observer.stop()
            self.observer.join()
        
        # Wait for queue to empty
        self.file_queue.join()
        
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
        
        if self.db_manager.connection:
            self.db_manager.connection.close()
        
        logging.info("Log Monitor Application stopped")

# ============================================================================
# FLASK WEB APPLICATION
# ============================================================================

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Custom unauthorized handler to use full_url_for
@login_manager.unauthorized_handler
def unauthorized():
    """Handle unauthorized access with proper URL generation"""
    from flask_login import current_user
    if not current_user.is_authenticated:
        return redirect(full_url_for('login'))
    return redirect(full_url_for('index'))

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
    if not db_manager or not db_manager.connect():
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

# Custom template function for full URLs
def full_url_for(endpoint, **values):
    """Generate full URL with SITE_URL prefix"""
    if SITE_URL:
        # Ensure SITE_URL doesn't have trailing slash and url_for result starts with /
        site_url = SITE_URL.rstrip('/')
        url_path = url_for(endpoint, **values)
        return f"{site_url}{url_path}"
    return url_for(endpoint, **values)

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

# Global variables for the monitor
log_monitor = None
db_manager = None

def load_config():
    """Load configuration from config.json and environment variables"""
    # Load environment variables from .env file
    load_dotenv()
    
    default_config = {
        "database": {
            "host": os.getenv("DB_HOST", "localhost"),
            "database": os.getenv("DB_NAME", "log_monitor"),
            "user": os.getenv("DB_USER", "root"),
            "password": os.getenv("DB_PASSWORD", "root"),
            "port": int(os.getenv("DB_PORT", "3306"))
        },
        "web": {
            "host": os.getenv("WEB_HOST", "0.0.0.0"),
            "port": int(os.getenv("WEB_PORT", "5000")),
            "debug": os.getenv("WEB_DEBUG", "True").lower() == "true",
            "auto_reload": os.getenv("WEB_AUTO_RELOAD", "True").lower() == "true"
        }
    }
    
    if os.path.exists('config.json'):
        try:
            with open('config.json', 'r') as f:
                user_config = json.load(f)
                if 'database' in user_config:
                    default_config['database'].update(user_config['database'])
                if 'web' in user_config:
                    default_config['web'].update(user_config['web'])
        except Exception as e:
            logging.error(f"Error loading config: {e}")
    
    return default_config

# Initialize database manager
config = load_config()
db_manager = DatabaseManager(config['database'])

# ============================================================================
# FLASK ROUTES
# ============================================================================

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    from flask_login import current_user
    
    if current_user.is_authenticated:
        return redirect(full_url_for('index'))
    
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
            if next_page:
                # Handle next page with SITE_URL if it's a relative URL
                if next_page.startswith('/'):
                    next_page = f"{SITE_URL.rstrip('/')}{next_page}" if SITE_URL else next_page
                return redirect(next_page)
            return redirect(full_url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(full_url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    from flask_login import current_user
    
    if current_user.is_authenticated:
        return redirect(full_url_for('index'))
    
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
            return redirect(full_url_for('login'))
        else:
            flash('Registration failed. Username may already exist.', 'error')
    
    return render_template('register.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile/settings page"""
    from flask_login import current_user
    
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

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def create_sample_config():
    """Create sample configuration files"""
    # Create .env file
    env_content = """# Database Configuration
DB_HOST=localhost
DB_NAME=log_monitor
DB_USER=root
DB_PASSWORD=root
DB_PORT=3306

# Monitoring Configuration
WATCH_DIRECTORY=./logs
MAX_FILE_SIZE_MB=10
CLEANUP_DAYS=90
CLEANUP_INTERVAL_HOURS=24

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=./logs/log_monitor.log
LOG_MAX_BYTES=10485760
LOG_BACKUP_COUNT=5

# Web Server Configuration
WEB_HOST=0.0.0.0
WEB_PORT=5000
WEB_DEBUG=True
WEB_AUTO_RELOAD=True
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    # Create config.json file
    config = {
        "database": {
            "host": "localhost",
            "database": "log_monitor",
            "user": "root",
            "password": "root",
            "port": 3306
        },
        "monitoring": {
            "watch_directory": "./logs",
            "max_file_size_mb": 10,
            "cleanup_days": 90,
            "cleanup_interval_hours": 24
        },
        "logging": {
            "level": "INFO",
            "file": "./logs/log_monitor.log",
            "max_bytes": 10485760,
            "backup_count": 5
        },
        "web": {
            "host": "0.0.0.0",
            "port": 5000,
            "debug": True,
            "auto_reload": True
        }
    }
    
    with open('config.json', 'w') as f:
        json.dump(config, f, indent=4)
    
    print("Sample .env and config.json created.")
    print("Please update .env with your database credentials.")
    print("The .env file takes priority over config.json for database settings.")

# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(description='Complete Log Monitor Application with Web UI')
    parser.add_argument('--config', default='config.json', help='Configuration file path')
    parser.add_argument('--create-config', action='store_true', help='Create sample configuration file')
    parser.add_argument('--scan-only', action='store_true', help='Scan existing files only, then exit')
    parser.add_argument('--web-only', action='store_true', help='Run web interface only (no file monitoring)')
    parser.add_argument('--monitor-only', action='store_true', help='Run file monitoring only (no web interface)')
    
    args = parser.parse_args()
    
    if args.create_config:
        create_sample_config()
        return
    
    # Load configuration
    config = load_config()
    
    # Initialize log monitor
    log_monitor = LogMonitor(args.config)
    
    if args.scan_only:
        if log_monitor.db_manager.connect():
            watch_dir = log_monitor.config['monitoring']['watch_directory']
            log_monitor.scan_existing_files(watch_dir)
            
            # Process all queued files
            log_monitor.running = True
            while not log_monitor.file_queue.empty():
                try:
                    file_path = log_monitor.file_queue.get_nowait()
                    log_monitor.processor.process_log_file(file_path)
                    log_monitor.file_queue.task_done()
                except queue.Empty:
                    break
        return
    
    if args.monitor_only:
        # Run only the file monitoring
        if not log_monitor.start_monitoring():
            return
        
        try:
            # Keep the application running
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logging.info("Received interrupt signal")
        finally:
            log_monitor.stop_monitoring()
        return
    
    if args.web_only:
        # Run only the web interface
        print("=" * 60)
        print("Log Monitor Web UI")
        print("=" * 60)
        print(f"Database: {config['database']['host']}:{config['database']['port']}")
        print(f"Database Name: {config['database']['database']}")
        print(f"Web Server: {config['web']['host']}:{config['web']['port']}")
        print("=" * 60)
        print("\nStarting web server...")
        print(f"Access the web UI at: http://{config['web']['host']}:{config['web']['port']}")
        print("Press Ctrl+C to stop the server")
        print("=" * 60)
        
        try:
            app.run(
                host=config['web']['host'],
                port=config['web']['port'],
                debug=config['web']['debug'],
                use_reloader=config['web']['auto_reload']
            )
        except KeyboardInterrupt:
            print("\nShutting down web server...")
        return
    
    # Run both monitoring and web interface
    print("=" * 60)
    print("Complete Log Monitor Application")
    print("=" * 60)
    print(f"Database: {config['database']['host']}:{config['database']['port']}")
    print(f"Database Name: {config['database']['database']}")
    print(f"Web Server: {config['web']['host']}:{config['web']['port']}")
    print(f"Watch Directory: {log_monitor.config['monitoring']['watch_directory']}")
    print("=" * 60)
    
    # Start file monitoring
    if not log_monitor.start_monitoring():
        print("Failed to start file monitoring")
        return
    
    print("\nStarting web server...")
    print(f"Access the web UI at: http://{config['web']['host']}:{config['web']['port']}")
    print("Press Ctrl+C to stop both services")
    print("=" * 60)
    
    # Start web server in a separate thread
    def run_web_server():
        app.run(
            host=config['web']['host'],
            port=config['web']['port'],
            debug=False,  # Disable debug mode for production
            use_reloader=False,  # Disable auto-reload
            threaded=True
        )
    
    web_thread = threading.Thread(target=run_web_server)
    web_thread.daemon = True
    web_thread.start()
    
    try:
        # Keep the application running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logging.info("Received interrupt signal")
    finally:
        log_monitor.stop_monitoring()
        print("\nShutting down application...")

if __name__ == "__main__":
    main()
