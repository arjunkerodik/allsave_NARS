import threading
import time
import os
import subprocess
import platform
from datetime import datetime
import logging
import psutil

from utils.redaction import redact_secrets

RESOURCE_SCAN_SECONDS = 60

class EndpointCollector:
    """Collects real endpoint/host-level activity logs"""

    def __init__(self):
        self.logger = logging.getLogger('EndpointCollector')
        self.endpoint_logs = []
        self.max_logs = 100
        self.is_running = False
        self.monitor_thread = None
        self.system = platform.system().lower()
        self.hostname = platform.node()
        self._last_resource_scan = 0

    def start_monitoring(self):
        """Start real-time endpoint monitoring"""
        if self.is_running:
            return

        self.is_running = True
        self.monitor_thread = threading.Thread(target=self._monitor_system, daemon=True)
        self.monitor_thread.start()
        self.logger.info("Endpoint monitoring started")

    def stop_monitoring(self):
        """Stop endpoint monitoring"""
        self.is_running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info("Endpoint monitoring stopped")

    def _monitor_system(self):
        """Monitor system activity in background thread"""
        while self.is_running:
            try:
                # Monitor different aspects of system activity
                events = []

                # Monitor running processes
                events.extend(self._monitor_processes())

                # Monitor system performance
                events.extend(self._monitor_performance())

                # Monitor file system changes (basic)
                events.extend(self._monitor_file_system())

                # Monitor network connections
                events.extend(self._monitor_connections())

                # Add events to log list
                for event in events:
                    self.endpoint_logs.append(event)

                # Keep only recent logs
                if len(self.endpoint_logs) > self.max_logs:
                    self.endpoint_logs = self.endpoint_logs[-self.max_logs:]

                time.sleep(2)  # Monitor every 2 seconds for real-time response

            except Exception as e:
                self.logger.error(f"Error in endpoint monitoring: {e}")
                time.sleep(5)  # Wait slightly on error

    def _monitor_processes(self):
        """Monitor running processes and detect changes"""
        events = []
        try:
            # Initialize set of pids if not exists
            if not hasattr(self, '_previous_pids'):
                self._previous_pids = set()
                self._process_names = {}
                for p in psutil.process_iter(['pid', 'name']):
                    self._previous_pids.add(p.info['pid'])
                    self._process_names[p.info['pid']] = p.info.get('name')
                return []

            # Listing ids is one cheap call. Reading every process's details on each pass froze the
            # whole server for over a second at a time, so details are read only for new processes.
            current_pids = set(psutil.pids())

            # Detect new processes
            for pid in current_pids - self._previous_pids:
                name = 'unknown'
                user = 'SYSTEM'
                ppid = None
                parent_name = 'unknown'
                command_line = None
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    user = proc.username()
                    ppid = proc.ppid()
                    parent_name = proc.parent().name() if proc.parent() else 'system'
                    command_line = redact_secrets(' '.join(proc.cmdline())) or None
                except (psutil.Error, OSError):
                    # Short-lived or protected process: record what is visible
                    pass
                self._process_names[pid] = name

                events.append({
                    'action': 'process_start',
                    'timestamp': datetime.now().isoformat(),
                    'hostname': self.hostname,
                    'user': user,
                    'process_name': name,
                    'pid': pid,
                    'ppid': ppid,
                    'parent_process_name': parent_name,
                    'command_line': command_line,
                    'file_path': '',
                    'details': f"New process started: {name} (PID: {pid}, Parent: {parent_name})"
                })

            # Detect terminated processes
            for pid in self._previous_pids - current_pids:
                name = self._process_names.pop(pid, None)
                events.append({
                    'action': 'process_stop',
                    'timestamp': datetime.now().isoformat(),
                    'hostname': self.hostname,
                    'process_name': name or 'unknown',
                    'pid': pid,
                    'details': f"Process ended: {name or 'unknown'} (PID: {pid})"
                })

            self._previous_pids = current_pids

            if time.time() - self._last_resource_scan >= RESOURCE_SCAN_SECONDS:
                self._last_resource_scan = time.time()
                events.extend(self._monitor_resource_usage())

        except Exception as e:
            self.logger.error(f"Error monitoring processes: {e}")

        return events

    def _monitor_resource_usage(self):
        """Detect high resource usage. This reads every process, so it runs only now and then."""
        events = []
        # psutil reports None for protected processes, and the idle pseudo-process
        # always "uses" whatever CPU is free.
        for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
            if p.info['pid'] == 0 or p.info.get('name') == 'System Idle Process':
                continue
            if (p.info.get('cpu_percent') or 0) > 50:  # High CPU usage
                events.append({
                    'action': 'high_cpu_process',
                    'timestamp': datetime.now().isoformat(),
                    'user': p.info.get('username', 'SYSTEM'),
                    'process_name': p.info.get('name', 'unknown'),
                    'ppid': None, # Optional for resource alerts
                    'parent_process_name': '',
                    'file_path': '',
                    'details': f"Process {p.info.get('name')} using {p.info.get('cpu_percent'):.1f}% CPU"
                })

            if (p.info.get('memory_percent') or 0) > 20:  # High memory usage
                events.append({
                    'action': 'high_memory_process',
                    'timestamp': datetime.now().isoformat(),
                    'user': p.info.get('username', 'SYSTEM'),
                    'process_name': p.info.get('name', 'unknown'),
                    'file_path': '',
                    'details': f"Process {p.info.get('name')} using {p.info.get('memory_percent'):.1f}% memory"
                })
        return events

    def _monitor_performance(self):
        """Monitor system performance"""
        events = []
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 80:
                events.append({
                    'action': 'high_cpu_system',
                    'timestamp': datetime.now().isoformat(),
                    'user': 'SYSTEM',
                    'process_name': 'system',
                    'file_path': '',
                    'details': f'High system CPU usage: {cpu_percent}%'
                })

            # Memory usage
            memory = psutil.virtual_memory()
            if memory.percent > 85:
                events.append({
                    'action': 'high_memory_system',
                    'timestamp': datetime.now().isoformat(),
                    'user': 'SYSTEM',
                    'process_name': 'system',
                    'file_path': '',
                    'details': f'High system memory usage: {memory.percent}%'
                })

            # Disk usage
            disk = psutil.disk_usage('/')
            if disk.percent > 90:
                events.append({
                    'action': 'high_disk_system',
                    'timestamp': datetime.now().isoformat(),
                    'user': 'SYSTEM',
                    'process_name': 'system',
                    'file_path': '',
                    'details': f'High disk usage: {disk.percent}%'
                })

        except Exception as e:
            self.logger.error(f"Error monitoring performance: {e}")

        return events

    def _monitor_file_system(self):
        """Monitor file system changes in key directories"""
        events = []
        try:
            # Monitor multiple directories for a more "real" experience
            dirs_to_monitor = [
                os.path.join(os.path.expanduser('~'), 'Downloads'),
                os.path.join(os.path.expanduser('~'), 'Desktop'),
                os.path.join(os.getcwd(), 'temp')
            ]

            if not hasattr(self, '_previous_files'):
                self._previous_files = {} # dir -> set of files

            for monitor_dir in dirs_to_monitor:
                if not os.path.exists(monitor_dir):
                    if 'temp' in monitor_dir: os.makedirs(monitor_dir, exist_ok=True)
                    else: continue

                current_files = set(os.listdir(monitor_dir))

                if monitor_dir in self._previous_files:
                    new_files = current_files - self._previous_files[monitor_dir]
                    for file in new_files:
                        events.append({
                            'action': 'file_create',
                            'timestamp': datetime.now().isoformat(),
                            'hostname': self.hostname,
                            'user': self._current_user(),
                            'file_path': os.path.join(monitor_dir, file),
                            'details': f"New file created in {os.path.basename(monitor_dir)}: {file}"
                        })

                self._previous_files[monitor_dir] = current_files

        except Exception as e:
            self.logger.error(f"Error monitoring file system: {e}")

        return events

    def _monitor_connections(self):
        """Monitor network connections"""
        events = []
        try:
            connections = psutil.net_connections()

            # Look for suspicious connections
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port

                    # Check for connections to suspicious ports
                    if remote_port in [22, 23, 3389, 5900]:  # SSH, Telnet, RDP, VNC
                        events.append({
                            'action': 'remote_connection',
                            'timestamp': datetime.now().isoformat(),
                            'hostname': self.hostname,
                            'src_ip': conn.laddr.ip if conn.laddr else None,
                            'dst_ip': remote_ip,
                            'dst_port': remote_port,
                            'process_name': self._process_name(conn.pid),
                            'pid': conn.pid,
                            'file_path': '',
                            'details': f"Remote connection to {remote_ip}:{remote_port}"
                        })

        except Exception as e:
            self.logger.error(f"Error monitoring connections: {e}")

        return events

    def _process_name(self, pid):
        """Name of a process that may already have exited"""
        if not pid:
            return 'unknown'
        try:
            return psutil.Process(pid).name()
        except (psutil.Error, OSError):
            return 'unknown'

    def _current_user(self):
        """os.getlogin() raises when the process has no controlling terminal"""
        try:
            return os.getlogin()
        except OSError:
            return os.environ.get('USERNAME') or os.environ.get('USER')

    def collect_events(self):
        """Collect recent endpoint events"""
        if not self.is_running:
            self.start_monitoring()

        # Swap rather than copy-and-clear, so an event arriving in between is not lost
        events, self.endpoint_logs = self.endpoint_logs, []

        return events

    def log_process_start(self, process_name, user, command_line=""):
        """Log a process start event"""
        event = {
            'action': 'process_start',
            'timestamp': datetime.now().isoformat(),
            'user': user,
            'process_name': process_name,
            'file_path': '',
            'details': f"Process {process_name} started by user {user}"
        }
        if command_line:
            event['details'] += f" with command line: {command_line}"
        return event

    def log_file_access(self, process_name, user, file_path, access_type):
        """Log a file access event"""
        event = {
            'action': access_type,
            'timestamp': datetime.now().isoformat(),
            'user': user,
            'process_name': process_name,
            'file_path': file_path,
            'details': f"Process {process_name} {access_type.replace('_', ' ')} {file_path}"
        }
        return event

    def log_registry_access(self, process_name, user, registry_key, access_type="read"):
        """Log a registry access event"""
        event = {
            'action': 'registry_access',
            'timestamp': datetime.now().isoformat(),
            'user': user,
            'process_name': process_name,
            'registry_key': registry_key,
            'details': f"Process {process_name} {access_type} registry key: {registry_key}"
        }
        return event

    def log_network_connection(self, process_name, user, remote_ip, remote_port):
        """Log a network connection event"""
        event = {
            'action': 'network_connection',
            'timestamp': datetime.now().isoformat(),
            'user': user,
            'process_name': process_name,
            'file_path': '',
            'details': f"Process {process_name} connected to {remote_ip}:{remote_port}"
        }
        return event

    def log_logon_event(self, username, logon_type, success=True):
        """Log a logon event"""
        action = 'logon' if success else 'failed_logon'
        event = {
            'action': action,
            'timestamp': datetime.now().isoformat(),
            'user': username,
            'process_name': 'winlogon.exe' if self.system == 'windows' else 'login',
            'file_path': '',
            'details': f"User {username} {logon_type} logon {'successful' if success else 'failed'}"
        }
        return event
