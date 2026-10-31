import logging
import threading
import time
from datetime import datetime
from flask import request, g, has_request_context
import os
import sys

class ApplicationLogger:
    """Collects real application logs from the Flask application"""

    def __init__(self):
        self.logger = logging.getLogger('ApplicationLogger')
        self.app_logs = []
        self.max_logs = 100
        self.is_running = False

        # Set up Flask request logging
        self.setup_flask_logging()

    def setup_flask_logging(self):
        """Set up logging for Flask requests and application events"""
        # Create a custom handler to capture Flask logs
        class LogHandler(logging.Handler):
            def __init__(self, app_logger):
                super().__init__()
                self.app_logger = app_logger

            def emit(self, record):
                try:
                    # Werkzeug's access lines repeat what log_request already recorded in more
                    # detail, and include the dashboard polling itself. Keep only its other messages.
                    if record.name == 'werkzeug' and ' HTTP/' in record.getMessage():
                        return

                    # Initialize default values
                    method = ''
                    endpoint = ''
                    status_code = None
                    payload_size = 0
                    user_agent = ''
                    src_ip = '127.0.0.1'
                    user = 'anonymous'

                    # Capture deep Flask request data ONLY if in request context
                    if has_request_context():
                        method = getattr(request, 'method', '')
                        endpoint = getattr(request, 'path', '')
                        payload_size = getattr(request, 'content_length', 0)
                        user_agent = str(getattr(request, 'user_agent', ''))
                        src_ip = getattr(request, 'remote_addr', '127.0.0.1')
                        user = getattr(g, 'user', 'anonymous')

                    # Try to extract status code from record if it's a werkzeug log
                    msg = record.getMessage()
                    if record.name == 'werkzeug' and ' "' in msg:
                        try:
                            # Werkzeug logs look like: "GET /api/logs HTTP/1.1" 200 -
                            status_code = int(msg.split('" ')[1].split(' ')[0])
                        except: pass

                    log_entry = {
                        'event_type': self.app_logger._get_event_type(record),
                        'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                        'user': user,
                        'src_ip': src_ip,
                        'dst_ip': '127.0.0.1',
                        'method': method,
                        'endpoint': endpoint,
                        'status_code': status_code,
                        'payload_size': payload_size,
                        'user_agent': user_agent,
                        'geo_location': self.app_logger._get_geo_location(src_ip),
                        'message': msg,
                        'level': record.levelname,
                        'details': f"HTTP {method} {endpoint} | Status: {status_code} | UA: {user_agent}" if method else msg
                    }
                    self.app_logger.app_logs.append(log_entry)

                    # Keep only recent logs
                    if len(self.app_logger.app_logs) > self.app_logger.max_logs:
                        self.app_logger.app_logs = self.app_logger.app_logs[-self.app_logger.max_logs:]

                except Exception as e:
                    print(f"Error in log handler: {e}")

        # Add the custom handler to Flask's logger
        flask_logger = logging.getLogger('werkzeug')
        flask_logger.addHandler(LogHandler(self))
        flask_logger.setLevel(logging.INFO)

        # Also set up for the app logger
        app_logger = logging.getLogger('app')
        app_logger.addHandler(LogHandler(self))
        app_logger.setLevel(logging.INFO)

    def _get_event_type(self, record):
        """Determine event type from log record"""
        message = record.getMessage().lower()

        if 'get' in message or 'post' in message or 'put' in message or 'delete' in message:
            return 'api_access'
        elif 'login' in message:
            return 'login'
        elif 'logout' in message:
            return 'logout'
        elif 'error' in message or 'exception' in message:
            return 'error'
        elif 'warning' in message:
            return 'warning'
        elif '200' in message or '201' in message:
            return 'success'
        elif '404' in message:
            return 'not_found'
        elif '500' in message:
            return 'server_error'
        else:
            return 'info'

    def collect_events(self):
        """Collect recent application logs"""
        # Swap rather than copy-and-clear, so an event arriving in between is not lost
        events, self.app_logs = self.app_logs, []

        # Also generate some system events
        system_events = self._generate_system_events()
        events.extend(system_events)

        return events

    def _generate_system_events(self):
        """Generate system-level application events"""
        events = []

        # Monitor system resources
        try:
            import psutil

            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 80:
                events.append({
                    'event_type': 'high_cpu',
                    'timestamp': datetime.now().isoformat(),
                    'user': 'SYSTEM',
                    'src_ip': '127.0.0.1',
                    'dst_ip': '',
                    'message': f'High CPU usage detected: {cpu_percent}%'
                })

            # Memory usage
            memory = psutil.virtual_memory()
            if memory.percent > 85:
                events.append({
                    'event_type': 'high_memory',
                    'timestamp': datetime.now().isoformat(),
                    'user': 'SYSTEM',
                    'src_ip': '127.0.0.1',
                    'dst_ip': '',
                    'message': f'High memory usage detected: {memory.percent}%'
                })

            # Disk usage
            disk = psutil.disk_usage('/')
            if disk.percent > 90:
                events.append({
                    'event_type': 'high_disk',
                    'timestamp': datetime.now().isoformat(),
                    'user': 'SYSTEM',
                    'src_ip': '127.0.0.1',
                    'dst_ip': '',
                    'message': f'High disk usage detected: {disk.percent}%'
                })

        except ImportError:
            # psutil not available, skip system monitoring
            pass
        except Exception as e:
            self.logger.error(f"Error monitoring system: {e}")

        # If no threats were detected, occasionally log a "Heartbeat" to show activity
        if not events:
            # Only log a heartbeat every 5 polls to avoid spamming
            if not hasattr(self, '_poll_counter'): self._poll_counter = 0
            self._poll_counter += 1
            if self._poll_counter >= 5:
                self._poll_counter = 0
                events.append({
                    'event_type': 'system_heartbeat',
                    'timestamp': datetime.now().isoformat(),
                    'user': 'SYSTEM',
                    'src_ip': '127.0.0.1',
                    'dst_ip': '127.0.0.1',
                    'method': 'SYSTEM',
                    'endpoint': 'CORE_HEARTBEAT',
                    'status_code': 200,
                    'payload_size': 0,
                    'user_agent': 'ALLSAFE Internal Monitor',
                    'geo_location': 'Local Node',
                    'message': 'Application Monitoring Engine: System Healthy'
                })

        return events

    def _get_geo_location(self, ip):
        """Mock Geo-location lookup based on IP"""
        if ip == '127.0.0.1':
            return "Localhost (Internal)"
        # Simple mock mapping for demo
        mocks = {
            '192.168': 'Local Network',
            '10.': 'Private Cloud'
        }
        for prefix, loc in mocks.items():
            if ip.startswith(prefix): return loc
        return "Unknown (External)"

    def log_login(self, username, ip_address):
        """Log a successful login event"""
        event = {
            'event_type': 'login',
            'timestamp': datetime.now().isoformat(),
            'user': username,
            'src_ip': ip_address,
            'dst_ip': '127.0.0.1',
            'method': 'POST',
            'endpoint': '/login',
            'status_code': 200,
            'geo_location': self._get_geo_location(ip_address),
            'message': f"User {username} logged in successfully from {ip_address}",
            'details': f"Successful authentication for {username}"
        }
        self.app_logs.append(event)
        return event

    def log_failed_login(self, username, ip_address):
        """Log a failed login attempt"""
        event = {
            'event_type': 'failed_login',
            'timestamp': datetime.now().isoformat(),
            'user': username,
            'src_ip': ip_address,
            'dst_ip': '',
            'message': f"Failed login attempt for user {username} from {ip_address}"
        }
        self.app_logs.append(event)
        return event

    def log_api_access(self, username, ip_address, endpoint):
        """Log API access"""
        event = {
            'event_type': 'api_access',
            'timestamp': datetime.now().isoformat(),
            'user': username,
            'src_ip': ip_address,
            'dst_ip': '',
            'message': f"User {username} accessed {endpoint} from {ip_address}"
        }
        self.app_logs.append(event)
        return event

    def log_error(self, username, error_message):
        """Log an application error"""
        event = {
            'event_type': 'error',
            'timestamp': datetime.now().isoformat(),
            'user': username,
            'src_ip': '127.0.0.1',
            'dst_ip': '',
            'message': f"Error for user {username}: {error_message}"
        }
        self.app_logs.append(event)
        return event
    def log_request(self, req, res):
        """High-fidelity logging of a real HTTP request"""
        try:
            # Calculate payload size (sum of incoming and outgoing for realism)
            in_bytes = req.content_length or 0
            out_bytes = res.content_length or 0

            event = {
                'event_type': 'api_access',
                'timestamp': datetime.now().isoformat(),
                'user': getattr(g, 'user', 'anonymous'),
                'src_ip': req.remote_addr,
                'dst_ip': '127.0.0.1',
                'bytes_in': in_bytes,
                'bytes_out': out_bytes,
                'method': req.method,
                'endpoint': req.path,
                'status_code': res.status_code,
                'payload_size': in_bytes + out_bytes,
                'user_agent': str(req.user_agent),
                'geo_location': self._get_geo_location(req.remote_addr),
                'message': f"Inbound {req.method} request to {req.path}",
                'details': f"Status: {res.status_code} | Agent: {req.user_agent}"
            }
            self.app_logs.append(event)
        except Exception as e:
            self.logger.error(f"Failed high-fidelity log: {e}")
