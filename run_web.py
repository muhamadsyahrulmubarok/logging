#!/usr/bin/env python3
"""
Web UI Startup Script for Log Monitor
Starts the Flask web application with proper configuration
"""

import os
import sys
import json
import logging
from app import app, load_config

def setup_logging():
    """Setup logging for the web application"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('web_app.log')
        ]
    )

def main():
    """Main startup function"""
    print("=" * 60)
    print("Log Monitor Web UI")
    print("=" * 60)
    
    # Setup logging
    setup_logging()
    
    # Load configuration
    config = load_config()
    web_config = config.get('web', {})
    
    # Display configuration
    print(f"Database: {config['database']['host']}:{config['database']['port']}")
    print(f"Database Name: {config['database']['database']}")
    print(f"Web Server: {web_config.get('host', '0.0.0.0')}:{web_config.get('port', 5000)}")
    print(f"Debug Mode: {web_config.get('debug', True)}")
    print("=" * 60)
    
    # Check if database is accessible
    try:
        from app import db_manager
        if db_manager.connect():
            print("✓ Database connection successful")
        else:
            print("✗ Database connection failed")
            print("Please check your database configuration in config.json")
            return
    except Exception as e:
        print(f"✗ Database error: {e}")
        print("Please check your database configuration in config.json")
        return
    
    # Start the web application
    print("\nStarting web server...")
    print(f"Access the web UI at: http://{web_config.get('host', '0.0.0.0')}:{web_config.get('port', 5000)}")
    print("Press Ctrl+C to stop the server")
    print("=" * 60)
    
    try:
        app.run(
            host=web_config.get('host', '0.0.0.0'),
            port=web_config.get('port', 5000),
            debug=web_config.get('debug', True),
            use_reloader=web_config.get('auto_reload', True)
        )
    except KeyboardInterrupt:
        print("\nShutting down web server...")
    except Exception as e:
        print(f"Error starting web server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
