# Complete Log Monitor Application

A comprehensive log monitoring solution that combines file monitoring with a modern web interface. This single-file application provides everything you need to monitor, process, and visualize application logs.

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Create Configuration

```bash
python log_monitor_complete.py --create-config
```

### 3. Edit Configuration

Update `config.json` with your database settings:

```json
{
	"database": {
		"host": "localhost",
		"database": "log_monitor",
		"user": "your_username",
		"password": "your_password",
		"port": 3306
	}
}
```

### 4. Run the Application

```bash
python start.py
```

## 📋 Features

### File Monitoring

- **Real-time Monitoring**: Watches directories for new log files
- **Automatic Processing**: Processes compressed (.gz) and regular log files
- **Duplicate Prevention**: Uses file hashing to avoid reprocessing
- **Database Storage**: Stores logs in MySQL with full metadata
- **Automatic Cleanup**: Removes old logs based on configurable retention

### Web Interface

- **Dashboard**: Real-time statistics and charts
- **Log Viewer**: Browse, search, and filter logs
- **Application Management**: Monitor application status
- **Log Details**: View complete log content with syntax highlighting
- **REST API**: Programmatic access to data

### Advanced Features

- **Responsive Design**: Works on desktop, tablet, and mobile
- **Real-time Updates**: Auto-refreshing dashboard
- **Search & Filter**: Advanced log searching capabilities
- **Export Functionality**: Copy log content to clipboard
- **Statistics**: Comprehensive analytics and reporting

## 🎯 Usage Options

### Complete Application (Recommended)

Runs both file monitoring and web interface:

```bash
python log_monitor_complete.py
```

### Web Interface Only

For when you only need the dashboard:

```bash
python log_monitor_complete.py --web-only
```

### File Monitoring Only

For headless server environments:

```bash
python log_monitor_complete.py --monitor-only
```

### Scan Existing Files

Process existing logs without monitoring:

```bash
python log_monitor_complete.py --scan-only
```

## 🌐 Web Interface

### Dashboard (`/`)

- **Statistics Cards**: Total logs, monitored apps, error counts
- **Interactive Charts**: Log distribution by type and application
- **Application Status**: Overview of all monitored applications
- **Recent Logs**: Latest entries with quick access

### Logs (`/logs`)

- **Advanced Filtering**: By application, type, date, and content
- **Search Functionality**: Full-text search across log content
- **Pagination**: Efficient handling of large log volumes
- **Quick Actions**: Direct access to log details

### Applications (`/apps`)

- **Status Monitoring**: Active/inactive application tracking
- **Statistics**: Per-application log counts and trends
- **Quick Access**: Direct links to application-specific logs

### Log Detail (`/log/<id>`)

- **Complete Information**: All log metadata and file details
- **Content Viewer**: Full log content with syntax highlighting
- **Navigation**: Easy access to related logs
- **Copy Functionality**: Copy content to clipboard

## ⚙️ Configuration

### Database Settings

```json
{
	"database": {
		"host": "localhost",
		"database": "log_monitor",
		"user": "root",
		"password": "root",
		"port": 3306
	}
}
```

### Monitoring Settings

```json
{
	"monitoring": {
		"watch_directory": "./logs",
		"max_file_size_mb": 10,
		"cleanup_days": 90,
		"cleanup_interval_hours": 24
	}
}
```

### Web Server Settings

```json
{
	"web": {
		"host": "0.0.0.0",
		"port": 5000,
		"debug": true,
		"auto_reload": true
	}
}
```

### Logging Settings

```json
{
	"logging": {
		"level": "INFO",
		"file": "./logs/log_monitor.log",
		"max_bytes": 10485760,
		"backup_count": 5
	}
}
```

## 📁 File Structure

```
monitoring_apps/
├── log_monitor_complete.py    # Main application file
├── start.py                   # Simple startup script
├── config.json               # Configuration file
├── requirements.txt          # Python dependencies
├── templates/               # HTML templates
│   ├── base.html
│   ├── dashboard.html
│   ├── logs.html
│   ├── log_detail.html
│   ├── apps.html
│   └── error.html
├── static/                  # Static assets
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── main.js
└── logs/                   # Log files directory
```

## 🔧 API Endpoints

### Statistics API

```
GET /api/stats?days=7
```

Returns log statistics for the specified period.

### Logs API

```
GET /api/logs?app_name=myapp&log_type=error&limit=50
```

Returns filtered log entries with optional parameters.

## 📊 Database Schema

### log_entries

- `id`: Primary key
- `app_name`: Application name
- `log_type`: Log type (error, info, warn, debug, out)
- `timestamp`: Log timestamp
- `file_name`: Original filename
- `file_hash`: SHA-256 hash for deduplication
- `log_content`: Full log content
- `file_size`: File size in bytes
- `processed_at`: Processing timestamp

### monitored_apps

- `id`: Primary key
- `app_name`: Application name (unique)
- `last_log_timestamp`: Last log entry time
- `total_logs`: Total log count
- `status`: Application status
- `created_at`: Creation timestamp
- `updated_at`: Last update timestamp

### processed_files

- `id`: Primary key
- `file_path`: Full file path
- `file_hash`: SHA-256 hash
- `file_size`: File size in bytes
- `processed_at`: Processing timestamp
- `status`: Processing status
- `error_message`: Error details if failed

## 🚀 Production Deployment

### Using Gunicorn

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 log_monitor_complete:app
```

### Using Docker

```dockerfile
FROM python:3.9
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["python", "log_monitor_complete.py"]
```

### System Service

Create a systemd service file for automatic startup:

```ini
[Unit]
Description=Log Monitor Application
After=network.target

[Service]
Type=simple
User=logmonitor
WorkingDirectory=/opt/logmonitor
ExecStart=/usr/bin/python3 log_monitor_complete.py
Restart=always

[Install]
WantedBy=multi-user.target
```

## 🔍 Troubleshooting

### Database Connection Issues

1. Verify database credentials in `config.json`
2. Ensure MySQL server is running
3. Check database and table creation
4. Verify user permissions

### Web Server Issues

1. Check if port 5000 is available
2. Verify all dependencies are installed
3. Check firewall settings
4. Review application logs

### File Monitoring Issues

1. Verify watch directory exists and is accessible
2. Check file permissions
3. Review log file format requirements
4. Monitor application logs for errors

### Performance Issues

1. Adjust log retention settings
2. Optimize database queries
3. Enable database indexing
4. Monitor server resources

## 📈 Performance Optimization

### Database Optimization

- Add indexes on frequently queried columns
- Regular database maintenance
- Monitor query performance
- Consider database partitioning for large datasets

### File Processing

- Adjust `max_file_size_mb` based on your needs
- Monitor disk space usage
- Implement log rotation
- Consider file compression strategies

### Web Interface

- Enable browser caching for static assets
- Use CDN for external libraries
- Implement pagination for large datasets
- Consider data caching strategies

## 🔒 Security Considerations

- Secure database credentials
- Use HTTPS in production
- Implement authentication if needed
- Regular security updates
- Monitor access logs
- Implement rate limiting

## 📞 Support

For issues and questions:

1. Check the application logs
2. Verify database connectivity
3. Review configuration settings
4. Check system requirements
5. Review the troubleshooting section

## 📄 License

This application is provided as-is for monitoring and managing application logs. Please ensure compliance with your organization's policies and applicable laws.
