#!/usr/bin/env python3
"""
Setup script for Log Monitor Application
Creates configuration files and helps with initial setup
"""

import os
import sys

def main():
    """Setup the log monitor application"""
    print("=" * 60)
    print("Log Monitor Application Setup")
    print("=" * 60)
    
    # Check if .env already exists
    if os.path.exists('.env'):
        print("✓ .env file already exists")
        response = input("Do you want to recreate it? (y/N): ").lower()
        if response != 'y':
            print("Setup cancelled.")
            return
    
    # Create .env file
    print("\nCreating .env file...")
    env_content = """# Database Configuration
DB_HOST=localhost
DB_NAME=log_monitor
DB_USER=root
DB_PASSWORD=your_password_here
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
    
    print("✓ .env file created")
    
    # Create logs directory
    if not os.path.exists('logs'):
        os.makedirs('logs')
        print("✓ logs directory created")
    
    # Create templates and static directories if they don't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    
    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)
    print("Next steps:")
    print("1. Edit .env file with your database credentials")
    print("2. Install dependencies: pip install -r requirements.txt")
    print("3. Run the application: python main.py")
    print("\nEnvironment variables in .env will override config.json settings.")
    print("=" * 60)

if __name__ == "__main__":
    main()
