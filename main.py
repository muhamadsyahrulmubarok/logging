#!/usr/bin/env python3
"""
Log Monitor Application
Monitors log files from multiple applications and stores them in MySQL database
Handles compressed .gz files and parses app names and timestamps
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
        }
    }
    
    with open('config.json', 'w') as f:
        json.dump(config, f, indent=4)
    
    print("Sample .env and config.json created.")
    print("Please update .env with your database credentials.")
    print("The .env file takes priority over config.json for database settings.")

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(description='Log Monitor Application')
    parser.add_argument('--config', default='config.json', help='Configuration file path')
    parser.add_argument('--create-config', action='store_true', help='Create sample configuration file')
    parser.add_argument('--scan-only', action='store_true', help='Scan existing files only, then exit')
    
    args = parser.parse_args()
    
    if args.create_config:
        create_sample_config()
        return
    
    monitor = LogMonitor(args.config)
    
    if args.scan_only:
        if monitor.db_manager.connect():
            watch_dir = monitor.config['monitoring']['watch_directory']
            monitor.scan_existing_files(watch_dir)
            
            # Process all queued files
            monitor.running = True
            while not monitor.file_queue.empty():
                try:
                    file_path = monitor.file_queue.get_nowait()
                    monitor.processor.process_log_file(file_path)
                    monitor.file_queue.task_done()
                except queue.Empty:
                    break
        return
    
    if not monitor.start_monitoring():
        return
    
    try:
        # Keep the application running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logging.info("Received interrupt signal")
    finally:
        monitor.stop_monitoring()

if __name__ == "__main__":
    main()