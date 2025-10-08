#!/usr/bin/env python3
"""
Advanced File Integrity Monitor
Real-time file monitoring with logging and alerting capabilities
Author: Cybersecurity Project
"""

import hashlib
import os
import json
import time
import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil

class FileIntegrityEventHandler(FileSystemEventHandler):
    """
    Event handler for real-time file system monitoring
    """

    def __init__(self, integrity_monitor):
        """
        Initialize event handler

        Args:
            integrity_monitor: Reference to the main monitor class
        """
        self.monitor = integrity_monitor
        super().__init__()

    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory and not event.src_path.endswith('.json'):
            self.monitor.handle_file_change('modified', event.src_path)

    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory and not event.src_path.endswith('.json'):
            self.monitor.handle_file_change('created', event.src_path)

    def on_deleted(self, event):
        """Handle file deletion events"""
        if not event.is_directory and not event.src_path.endswith('.json'):
            self.monitor.handle_file_change('deleted', event.src_path)

    def on_moved(self, event):
        """Handle file move events"""
        if not event.is_directory:
            self.monitor.handle_file_change('moved', event.src_path, event.dest_path)


class AdvancedFileIntegrityMonitor:
    """
    Advanced file integrity monitor with real-time capabilities
    """

    def __init__(self, target_directory: str = ".", 
                 hash_algorithm: str = "sha256",
                 enable_logging: bool = True,
                 log_level: str = "INFO"):
        """
        Initialize the advanced monitor

        Args:
            target_directory: Directory to monitor
            hash_algorithm: Hash algorithm to use
            enable_logging: Enable logging to file
            log_level: Logging level
        """
        self.target_directory = os.path.abspath(target_directory)
        self.hash_algorithm = hash_algorithm.lower()
        self.baseline_file = os.path.join(self.target_directory, ".integrity_baseline.json")
        self.config_file = os.path.join(self.target_directory, ".integrity_config.json")
        self.log_file = os.path.join(self.target_directory, "integrity_monitor.log")

        # Real-time monitoring
        self.observer = None
        self.event_handler = None
        self.monitoring = False
        self.excluded_patterns = {'.git', '__pycache__', '.pyc', '.log', '.tmp'}
        self.critical_files = set()

        # Performance monitoring
        self.memory_threshold_mb = 500
        self.max_file_size_mb = 100

        # Initialize logging
        if enable_logging:
            self.setup_logging(log_level)

        # Load configuration
        self.load_config()

    def setup_logging(self, log_level: str):
        """
        Setup logging configuration

        Args:
            log_level: Logging level
        """
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.excluded_patterns.update(config.get('excluded_patterns', []))
                    self.critical_files.update(config.get('critical_files', []))
                    self.memory_threshold_mb = config.get('memory_threshold_mb', 500)
        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.warning(f"Could not load config: {e}")

    def save_config(self):
        """Save current configuration to file"""
        config = {
            'excluded_patterns': list(self.excluded_patterns),
            'critical_files': list(self.critical_files),
            'memory_threshold_mb': self.memory_threshold_mb,
            'hash_algorithm': self.hash_algorithm
        }

        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.error(f"Could not save config: {e}")

    def should_monitor_file(self, file_path: str) -> bool:
        """
        Check if file should be monitored

        Args:
            file_path: Path to the file

        Returns:
            True if file should be monitored
        """
        file_name = os.path.basename(file_path)

        # Check exclusions
        for pattern in self.excluded_patterns:
            if pattern in file_path or file_name.endswith(pattern):
                return False

        # Check file size
        try:
            if os.path.getsize(file_path) > self.max_file_size_mb * 1024 * 1024:
                return False
        except (OSError, IOError):
            return False

        return True

    def calculate_file_hash(self, file_path: str) -> str:
        """
        Calculate file hash with error handling

        Args:
            file_path: Path to the file

        Returns:
            Hash string or empty string on error
        """
        if not self.should_monitor_file(file_path):
            return ""

        hash_obj = hashlib.new(self.hash_algorithm)

        try:
            with open(file_path, 'rb') as file:
                while chunk := file.read(8192):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.error(f"Error hashing file {file_path}: {e}")
            return ""

    def check_system_resources(self):
        """Check system resource usage"""
        try:
            memory_usage = psutil.virtual_memory().used / (1024 * 1024)  # MB
            if memory_usage > self.memory_threshold_mb:
                if hasattr(self, 'logger'):
                    self.logger.warning(f"High memory usage: {memory_usage:.1f} MB")
            return True
        except Exception:
            return True

    def handle_file_change(self, event_type: str, src_path: str, dest_path: str = None):
        """
        Handle file system changes

        Args:
            event_type: Type of change (created, modified, deleted, moved)
            src_path: Source path
            dest_path: Destination path (for move operations)
        """
        if not self.should_monitor_file(src_path):
            return

        relative_path = os.path.relpath(src_path, self.target_directory)
        timestamp = datetime.now().isoformat()

        # Check if it's a critical file
        is_critical = any(pattern in src_path for pattern in self.critical_files)
        priority = "HIGH" if is_critical else "MEDIUM"

        alert_msg = f"[{priority}] File {event_type}: {relative_path}"

        if dest_path:
            dest_relative = os.path.relpath(dest_path, self.target_directory)
            alert_msg += f" -> {dest_relative}"

        if hasattr(self, 'logger'):
            if is_critical:
                self.logger.warning(alert_msg)
            else:
                self.logger.info(alert_msg)

        # Log to security events
        self.log_security_event({
            'timestamp': timestamp,
            'event_type': event_type,
            'file_path': relative_path,
            'dest_path': os.path.relpath(dest_path, self.target_directory) if dest_path else None,
            'priority': priority,
            'file_hash': self.calculate_file_hash(src_path) if event_type != 'deleted' else None
        })

    def log_security_event(self, event: Dict):
        """
        Log security events to a separate file

        Args:
            event: Event dictionary
        """
        security_log_file = os.path.join(self.target_directory, "security_events.json")

        try:
            # Load existing events
            events = []
            if os.path.exists(security_log_file):
                with open(security_log_file, 'r') as f:
                    events = json.load(f)

            # Add new event
            events.append(event)

            # Keep only last 1000 events
            if len(events) > 1000:
                events = events[-1000:]

            # Save events
            with open(security_log_file, 'w') as f:
                json.dump(events, f, indent=2)

        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.error(f"Could not log security event: {e}")

    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.monitoring:
            if hasattr(self, 'logger'):
                self.logger.info("Monitoring already active")
            return

        if hasattr(self, 'logger'):
            self.logger.info(f"Starting real-time monitoring of: {self.target_directory}")

        self.event_handler = FileIntegrityEventHandler(self)
        self.observer = Observer()
        self.observer.schedule(self.event_handler, self.target_directory, recursive=True)
        self.observer.start()
        self.monitoring = True

        # Start resource monitoring thread
        threading.Thread(target=self._monitor_resources, daemon=True).start()

    def stop_monitoring(self):
        """Stop real-time monitoring"""
        if self.observer and self.monitoring:
            self.observer.stop()
            self.observer.join()
            self.monitoring = False
            if hasattr(self, 'logger'):
                self.logger.info("Monitoring stopped")

    def _monitor_resources(self):
        """Monitor system resources periodically"""
        while self.monitoring:
            self.check_system_resources()
            time.sleep(30)  # Check every 30 seconds

    def create_baseline(self) -> bool:
        """Create enhanced baseline with metadata"""
        if hasattr(self, 'logger'):
            self.logger.info(f"Creating baseline for: {self.target_directory}")

        file_inventory = {}
        file_count = 0

        for root, dirs, files in os.walk(self.target_directory):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]

            for file in files:
                file_path = os.path.join(root, file)

                if not self.should_monitor_file(file_path):
                    continue

                relative_path = os.path.relpath(file_path, self.target_directory)

                try:
                    stat_info = os.stat(file_path)
                    file_hash = self.calculate_file_hash(file_path)

                    if file_hash:  # Only include if hash was calculated successfully
                        file_inventory[relative_path] = {
                            'hash': file_hash,
                            'size': stat_info.st_size,
                            'modified_time': stat_info.st_mtime,
                            'permissions': oct(stat_info.st_mode)[-3:],
                            'algorithm': self.hash_algorithm,
                            'is_critical': any(pattern in file_path for pattern in self.critical_files)
                        }
                        file_count += 1

                except Exception as e:
                    if hasattr(self, 'logger'):
                        self.logger.error(f"Error processing {file_path}: {e}")

        baseline_data = {
            'timestamp': datetime.now().isoformat(),
            'directory': self.target_directory,
            'algorithm': self.hash_algorithm,
            'file_count': file_count,
            'critical_files': list(self.critical_files),
            'excluded_patterns': list(self.excluded_patterns),
            'files': file_inventory
        }

        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(baseline_data, f, indent=2)

            if hasattr(self, 'logger'):
                self.logger.info(f"Baseline created with {file_count} files")
            return True

        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.error(f"Error creating baseline: {e}")
            return False

    def add_critical_file(self, file_pattern: str):
        """Add file pattern to critical files list"""
        self.critical_files.add(file_pattern)
        self.save_config()
        if hasattr(self, 'logger'):
            self.logger.info(f"Added critical file pattern: {file_pattern}")

    def generate_security_report(self) -> Dict:
        """Generate comprehensive security report"""
        security_log_file = os.path.join(self.target_directory, "security_events.json")

        report = {
            'timestamp': datetime.now().isoformat(),
            'directory': self.target_directory,
            'monitoring_status': 'Active' if self.monitoring else 'Inactive',
            'total_events': 0,
            'high_priority_events': 0,
            'event_summary': {},
            'recent_events': []
        }

        try:
            if os.path.exists(security_log_file):
                with open(security_log_file, 'r') as f:
                    events = json.load(f)

                report['total_events'] = len(events)

                # Count event types and priorities
                for event in events:
                    event_type = event.get('event_type', 'unknown')
                    priority = event.get('priority', 'MEDIUM')

                    if event_type not in report['event_summary']:
                        report['event_summary'][event_type] = 0
                    report['event_summary'][event_type] += 1

                    if priority == 'HIGH':
                        report['high_priority_events'] += 1

                # Get recent events (last 10)
                report['recent_events'] = events[-10:] if events else []

        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.error(f"Error generating security report: {e}")

        return report

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop_monitoring()


def main():
    """Main function for advanced file integrity monitor"""
    import argparse
    import signal
    import sys

    def signal_handler(signum, frame):
        """Handle Ctrl+C gracefully"""
        print("\nStopping monitor...")
        if 'monitor' in locals():
            monitor.stop_monitoring()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="Advanced File Integrity Monitor")
    parser.add_argument("-d", "--directory", default=".",
                       help="Directory to monitor")
    parser.add_argument("-a", "--algorithm", default="sha256",
                       choices=['md5', 'sha1', 'sha256', 'sha512'],
                       help="Hash algorithm")
    parser.add_argument("-c", "--create-baseline", action="store_true",
                       help="Create baseline")
    parser.add_argument("-m", "--monitor", action="store_true",
                       help="Start real-time monitoring")
    parser.add_argument("--add-critical", help="Add critical file pattern")
    parser.add_argument("-r", "--report", action="store_true",
                       help="Generate security report")

    args = parser.parse_args()

    monitor = AdvancedFileIntegrityMonitor(
        target_directory=args.directory,
        hash_algorithm=args.algorithm
    )

    try:
        if args.create_baseline:
            monitor.create_baseline()
        elif args.add_critical:
            monitor.add_critical_file(args.add_critical)
        elif args.report:
            report = monitor.generate_security_report()
            print(json.dumps(report, indent=2))
        elif args.monitor:
            monitor.start_monitoring()
            print("Monitoring active. Press Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                monitor.stop_monitoring()
        else:
            print("Use -h for help")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()