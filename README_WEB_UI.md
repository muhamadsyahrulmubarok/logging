# Log Monitor Web UI

A modern web interface for the Log Monitor application that provides real-time monitoring, log viewing, and application management capabilities.

## Features

- **Dashboard**: Overview of monitored applications, log statistics, and recent entries
- **Log Viewer**: Browse, search, and filter log entries with detailed content viewing
- **Application Management**: Monitor application status and statistics
- **Real-time Updates**: Auto-refreshing dashboard with live data
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Modern UI**: Built with Bootstrap 5 and custom styling

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Database

Update `config.json` with your database credentials:

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

### 3. Start the Web Server

```bash
python run_web.py
```

### 4. Access the Web UI

Open your browser and navigate to:

```
http://localhost:5000
```

## Web Interface Pages

### Dashboard (`/`)

- **Statistics Cards**: Total logs, monitored apps, error logs, recent entries
- **Charts**: Log distribution by type and top applications
- **Application Status**: Overview of all monitored applications
- **Recent Logs**: Latest log entries with quick access

### Logs (`/logs`)

- **Filter Options**: By application, log type, and search terms
- **Log Table**: Comprehensive list of all log entries
- **Quick Actions**: View detailed log content
- **Search**: Full-text search across log content and filenames

### Log Detail (`/log/<id>`)

- **Complete Information**: All log metadata and file details
- **Log Content**: Full log content with syntax highlighting
- **Navigation**: Easy access to related logs
- **Copy Functionality**: Copy log content to clipboard

### Applications (`/apps`)

- **Application List**: All monitored applications with status
- **Statistics**: Per-application log counts and trends
- **Status Monitoring**: Active/inactive application tracking
- **Quick Access**: Direct links to application-specific logs

## API Endpoints

The web UI also provides REST API endpoints for programmatic access:

### Statistics API

```
GET /api/stats?days=7
```

Returns log statistics for the specified number of days.

### Logs API

```
GET /api/logs?app_name=myapp&log_type=error&limit=50
```

Returns filtered log entries with optional parameters.

## Configuration

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

## Features in Detail

### Real-time Dashboard

- Auto-refreshing statistics every 30 seconds
- Interactive charts showing log distribution
- Application status monitoring
- Recent log entries with quick access

### Advanced Log Search

- Full-text search across log content
- Filter by application name
- Filter by log type (error, info, warn, debug, out)
- Date range filtering
- Results pagination

### Log Content Viewer

- Syntax highlighting for log content
- Copy to clipboard functionality
- File metadata display
- Related log navigation

### Application Monitoring

- Real-time application status
- Log count statistics per application
- Last log entry timestamps
- Application-specific log filtering

## Customization

### Styling

- Custom CSS in `static/css/style.css`
- Bootstrap 5 integration
- Responsive design for all screen sizes
- Dark/light theme support

### JavaScript

- Interactive features in `static/js/main.js`
- Chart.js integration for data visualization
- Real-time updates and notifications
- Copy functionality and user interactions

## Troubleshooting

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

### Performance Issues

1. Adjust log retention settings
2. Optimize database queries
3. Enable database indexing
4. Monitor server resources

## Development

### Adding New Features

1. Update Flask routes in `app.py`
2. Create new templates in `templates/`
3. Add custom CSS in `static/css/`
4. Extend JavaScript in `static/js/`

### Database Schema

The web UI works with the existing database schema:

- `log_entries`: Main log storage
- `monitored_apps`: Application tracking
- `processed_files`: File processing status

## Security Considerations

- Database credentials should be secured
- Web server should be behind a firewall
- Consider HTTPS for production use
- Implement authentication if needed

## Production Deployment

### Using Gunicorn

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Using Docker

```dockerfile
FROM python:3.9
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["python", "run_web.py"]
```

## Support

For issues and questions:

1. Check the application logs
2. Verify database connectivity
3. Review configuration settings
4. Check system requirements

## License

This web UI is part of the Log Monitor application and follows the same licensing terms.
