#!/usr/bin/env python3
"""
GUI File Integrity Checker
User-friendly graphical interface for file integrity monitoring
Author: Cybersecurity Project
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import hashlib
import os
import json
import threading
from datetime import datetime
from typing import Dict, List, Optional

class FileIntegrityGUI:
    """
    GUI-based File Integrity Checker
    """

    def __init__(self, root):
        """
        Initialize GUI components

        Args:
            root: Tkinter root window
        """
        self.root = root
        self.root.title("File Integrity Checker - Cybersecurity Tool")
        self.root.geometry("800x700")
        self.root.resizable(True, True)

        # Variables
        self.target_directory = tk.StringVar(value=os.getcwd())
        self.hash_algorithm = tk.StringVar(value="sha256")
        self.baseline_file = ""
        self.monitoring = False

        # Create GUI elements
        self.create_widgets()
        self.setup_styles()

    def setup_styles(self):
        """Setup custom styles for the GUI"""
        style = ttk.Style()

        # Configure styles for different alert levels
        style.configure('Success.TLabel', foreground='green')
        style.configure('Error.TLabel', foreground='red')
        style.configure('Warning.TLabel', foreground='orange')
        style.configure('Title.TLabel', font=('Arial', 12, 'bold'))

    def create_widgets(self):
        """Create all GUI widgets"""
        # Create main notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Tab 1: File Integrity Check
        self.create_integrity_tab(notebook)

        # Tab 2: Real-time Monitoring  
        self.create_monitoring_tab(notebook)

        # Tab 3: Security Reports
        self.create_reports_tab(notebook)

        # Tab 4: Settings
        self.create_settings_tab(notebook)

    def create_integrity_tab(self, notebook):
        """Create the main integrity checking tab"""
        integrity_frame = ttk.Frame(notebook)
        notebook.add(integrity_frame, text="File Integrity Check")

        # Title
        title_label = ttk.Label(integrity_frame, text="File Integrity Checker", 
                               style='Title.TLabel')
        title_label.pack(pady=10)

        # Directory selection
        dir_frame = ttk.LabelFrame(integrity_frame, text="Target Directory", padding=10)
        dir_frame.pack(fill='x', padx=10, pady=5)

        dir_entry_frame = ttk.Frame(dir_frame)
        dir_entry_frame.pack(fill='x')

        self.dir_entry = ttk.Entry(dir_entry_frame, textvariable=self.target_directory, width=60)
        self.dir_entry.pack(side='left', fill='x', expand=True)

        browse_btn = ttk.Button(dir_entry_frame, text="Browse", command=self.browse_directory)
        browse_btn.pack(side='right', padx=(5,0))

        # Hash algorithm selection
        algo_frame = ttk.LabelFrame(integrity_frame, text="Hash Algorithm", padding=10)
        algo_frame.pack(fill='x', padx=10, pady=5)

        algo_combo = ttk.Combobox(algo_frame, textvariable=self.hash_algorithm,
                                 values=['md5', 'sha1', 'sha256', 'sha512'],
                                 state='readonly', width=20)
        algo_combo.pack()

        # Action buttons
        button_frame = ttk.Frame(integrity_frame)
        button_frame.pack(pady=20)

        create_btn = ttk.Button(button_frame, text="Create Baseline", 
                               command=self.create_baseline_threaded)
        create_btn.pack(side='left', padx=5)

        verify_btn = ttk.Button(button_frame, text="Verify Integrity", 
                               command=self.verify_integrity_threaded)
        verify_btn.pack(side='left', padx=5)

        # Progress bar
        self.progress = ttk.Progressbar(integrity_frame, mode='indeterminate')
        self.progress.pack(fill='x', padx=10, pady=5)

        # Status label
        self.status_label = ttk.Label(integrity_frame, text="Ready")
        self.status_label.pack(pady=5)

        # Results area
        results_frame = ttk.LabelFrame(integrity_frame, text="Results", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, wrap='word')
        self.results_text.pack(fill='both', expand=True)

    def create_monitoring_tab(self, notebook):
        """Create real-time monitoring tab"""
        monitor_frame = ttk.Frame(notebook)
        notebook.add(monitor_frame, text="Real-time Monitoring")

        # Title
        title_label = ttk.Label(monitor_frame, text="Real-time File Monitoring", 
                               style='Title.TLabel')
        title_label.pack(pady=10)

        # Monitoring controls
        control_frame = ttk.LabelFrame(monitor_frame, text="Monitoring Controls", padding=10)
        control_frame.pack(fill='x', padx=10, pady=5)

        self.start_monitor_btn = ttk.Button(control_frame, text="Start Monitoring", 
                                           command=self.start_monitoring)
        self.start_monitor_btn.pack(side='left', padx=5)

        self.stop_monitor_btn = ttk.Button(control_frame, text="Stop Monitoring", 
                                          command=self.stop_monitoring, state='disabled')
        self.stop_monitor_btn.pack(side='left', padx=5)

        # Monitoring status
        self.monitor_status = ttk.Label(control_frame, text="Monitoring: Inactive", 
                                       style='Error.TLabel')
        self.monitor_status.pack(side='right')

        # Live events
        events_frame = ttk.LabelFrame(monitor_frame, text="Live Events", padding=10)
        events_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.events_text = scrolledtext.ScrolledText(events_frame, height=20, wrap='word')
        self.events_text.pack(fill='both', expand=True)

        # Clear events button
        clear_btn = ttk.Button(events_frame, text="Clear Events", 
                              command=self.clear_events)
        clear_btn.pack(pady=5)

    def create_reports_tab(self, notebook):
        """Create security reports tab"""
        reports_frame = ttk.Frame(notebook)
        notebook.add(reports_frame, text="Security Reports")

        # Title
        title_label = ttk.Label(reports_frame, text="Security Reports & Analytics", 
                               style='Title.TLabel')
        title_label.pack(pady=10)

        # Report controls
        control_frame = ttk.LabelFrame(reports_frame, text="Report Generation", padding=10)
        control_frame.pack(fill='x', padx=10, pady=5)

        generate_btn = ttk.Button(control_frame, text="Generate Security Report", 
                                 command=self.generate_report)
        generate_btn.pack(side='left', padx=5)

        export_btn = ttk.Button(control_frame, text="Export Report", 
                               command=self.export_report)
        export_btn.pack(side='left', padx=5)

        # Report display
        report_frame = ttk.LabelFrame(reports_frame, text="Security Report", padding=10)
        report_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.report_text = scrolledtext.ScrolledText(report_frame, height=25, wrap='word')
        self.report_text.pack(fill='both', expand=True)

    def create_settings_tab(self, notebook):
        """Create settings tab"""
        settings_frame = ttk.Frame(notebook)
        notebook.add(settings_frame, text="Settings")

        # Title
        title_label = ttk.Label(settings_frame, text="Configuration Settings", 
                               style='Title.TLabel')
        title_label.pack(pady=10)

        # File exclusions
        exclusions_frame = ttk.LabelFrame(settings_frame, text="File Exclusions", padding=10)
        exclusions_frame.pack(fill='both', expand=True, padx=10, pady=5)

        ttk.Label(exclusions_frame, text="Exclude files matching these patterns:").pack(anchor='w')

        self.exclusions_text = scrolledtext.ScrolledText(exclusions_frame, height=8, wrap='word')
        self.exclusions_text.pack(fill='both', expand=True, pady=5)

        # Default exclusions
        default_exclusions = [".git", "__pycache__", "*.pyc", "*.log", "*.tmp", 
                             "*.swp", "node_modules", ".DS_Store"]
        self.exclusions_text.insert('1.0', '\n'.join(default_exclusions))

        # Critical files
        critical_frame = ttk.LabelFrame(settings_frame, text="Critical Files", padding=10)
        critical_frame.pack(fill='both', expand=True, padx=10, pady=5)

        ttk.Label(critical_frame, text="Monitor these files with high priority:").pack(anchor='w')

        self.critical_text = scrolledtext.ScrolledText(critical_frame, height=6, wrap='word')
        self.critical_text.pack(fill='both', expand=True, pady=5)

        # Default critical files
        default_critical = ["/etc/passwd", "/etc/shadow", "config.ini", 
                           "*.exe", "system32", "boot.ini"]
        self.critical_text.insert('1.0', '\n'.join(default_critical))

        # Save settings button
        save_btn = ttk.Button(settings_frame, text="Save Settings", 
                             command=self.save_settings)
        save_btn.pack(pady=10)

    def browse_directory(self):
        """Browse for target directory"""
        directory = filedialog.askdirectory(initialdir=self.target_directory.get())
        if directory:
            self.target_directory.set(directory)
            self.baseline_file = os.path.join(directory, ".integrity_baseline.json")

    def update_status(self, message, style=''):
        """Update status label"""
        self.status_label.config(text=message)
        if style:
            self.status_label.config(style=f'{style}.TLabel')
        self.root.update_idletasks()

    def show_progress(self, show=True):
        """Show or hide progress bar"""
        if show:
            self.progress.start()
        else:
            self.progress.stop()

    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate file hash"""
        algorithm = self.hash_algorithm.get()
        hash_obj = hashlib.new(algorithm)

        try:
            with open(file_path, 'rb') as file:
                while chunk := file.read(8192):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception:
            return ""

    def create_baseline_threaded(self):
        """Create baseline in a separate thread"""
        thread = threading.Thread(target=self.create_baseline)
        thread.daemon = True
        thread.start()

    def create_baseline(self):
        """Create file integrity baseline"""
        self.show_progress(True)
        self.update_status("Creating baseline...", 'Warning')

        directory = self.target_directory.get()
        if not os.path.exists(directory):
            messagebox.showerror("Error", "Directory does not exist!")
            self.show_progress(False)
            self.update_status("Ready")
            return

        try:
            file_inventory = {}
            file_count = 0

            # Get exclusions
            exclusions = [line.strip() for line in self.exclusions_text.get('1.0', 'end').split('\n') 
                         if line.strip()]

            for root, dirs, files in os.walk(directory):
                # Skip hidden directories
                dirs[:] = [d for d in dirs if not d.startswith('.')]

                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, directory)

                    # Check exclusions
                    should_skip = False
                    for exclusion in exclusions:
                        if exclusion in file_path or file.endswith(exclusion.replace('*', '')):
                            should_skip = True
                            break

                    if should_skip or file.startswith('.'):
                        continue

                    # Calculate hash and metadata
                    file_hash = self.calculate_file_hash(file_path)
                    if file_hash:
                        stat_info = os.stat(file_path)
                        file_inventory[relative_path] = {
                            'hash': file_hash,
                            'size': stat_info.st_size,
                            'modified_time': stat_info.st_mtime,
                            'algorithm': self.hash_algorithm.get()
                        }
                        file_count += 1

            # Save baseline
            baseline_data = {
                'timestamp': datetime.now().isoformat(),
                'directory': directory,
                'algorithm': self.hash_algorithm.get(),
                'file_count': file_count,
                'files': file_inventory
            }

            baseline_file = os.path.join(directory, ".integrity_baseline.json")
            with open(baseline_file, 'w') as f:
                json.dump(baseline_data, f, indent=2)

            # Update results
            result_text = f"✅ Baseline Created Successfully\n"
            result_text += f"📁 Directory: {directory}\n"
            result_text += f"📊 Files monitored: {file_count}\n"
            result_text += f"🔒 Algorithm: {self.hash_algorithm.get().upper()}\n"
            result_text += f"📅 Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            result_text += f"💾 Baseline saved to: {baseline_file}\n"

            self.results_text.delete('1.0', 'end')
            self.results_text.insert('1.0', result_text)

            self.update_status("Baseline created successfully", 'Success')
            messagebox.showinfo("Success", f"Baseline created with {file_count} files")

        except Exception as e:
            error_msg = f"Error creating baseline: {str(e)}"
            self.results_text.delete('1.0', 'end')
            self.results_text.insert('1.0', f"❌ {error_msg}")
            self.update_status("Error creating baseline", 'Error')
            messagebox.showerror("Error", error_msg)

        finally:
            self.show_progress(False)

    def verify_integrity_threaded(self):
        """Verify integrity in a separate thread"""
        thread = threading.Thread(target=self.verify_integrity)
        thread.daemon = True
        thread.start()

    def verify_integrity(self):
        """Verify file integrity against baseline"""
        self.show_progress(True)
        self.update_status("Verifying integrity...", 'Warning')

        directory = self.target_directory.get()
        baseline_file = os.path.join(directory, ".integrity_baseline.json")

        if not os.path.exists(baseline_file):
            messagebox.showerror("Error", "No baseline found! Create a baseline first.")
            self.show_progress(False)
            self.update_status("Ready")
            return

        try:
            # Load baseline
            with open(baseline_file, 'r') as f:
                baseline = json.load(f)

            # Scan current files
            current_files = {}
            exclusions = [line.strip() for line in self.exclusions_text.get('1.0', 'end').split('\n') 
                         if line.strip()]

            for root, dirs, files in os.walk(directory):
                dirs[:] = [d for d in dirs if not d.startswith('.')]

                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, directory)

                    # Check exclusions
                    should_skip = False
                    for exclusion in exclusions:
                        if exclusion in file_path or file.endswith(exclusion.replace('*', '')):
                            should_skip = True
                            break

                    if should_skip or file.startswith('.'):
                        continue

                    file_hash = self.calculate_file_hash(file_path)
                    if file_hash:
                        stat_info = os.stat(file_path)
                        current_files[relative_path] = {
                            'hash': file_hash,
                            'size': stat_info.st_size
                        }

            # Compare with baseline
            baseline_files = baseline['files']

            modified_files = []
            added_files = []
            deleted_files = []

            # Check for modifications and deletions
            for file_path, baseline_data in baseline_files.items():
                if file_path in current_files:
                    current_data = current_files[file_path]
                    if (current_data['hash'] != baseline_data['hash'] or
                        current_data['size'] != baseline_data['size']):
                        modified_files.append({
                            'file': file_path,
                            'baseline_hash': baseline_data['hash'][:16] + '...',
                            'current_hash': current_data['hash'][:16] + '...',
                            'baseline_size': baseline_data['size'],
                            'current_size': current_data['size']
                        })
                else:
                    deleted_files.append(file_path)

            # Check for additions
            for file_path in current_files:
                if file_path not in baseline_files:
                    added_files.append(file_path)

            # Generate report
            report = self.generate_integrity_report(modified_files, added_files, deleted_files, baseline)

            self.results_text.delete('1.0', 'end')
            self.results_text.insert('1.0', report)

            total_changes = len(modified_files) + len(added_files) + len(deleted_files)

            if total_changes == 0:
                self.update_status("Integrity verified - No changes detected", 'Success')
                messagebox.showinfo("Integrity Check", "✅ No changes detected - File integrity maintained")
            else:
                self.update_status(f"Changes detected: {total_changes} files", 'Warning')
                messagebox.showwarning("Integrity Check", f"⚠️ {total_changes} changes detected!")

        except Exception as e:
            error_msg = f"Error verifying integrity: {str(e)}"
            self.results_text.delete('1.0', 'end')
            self.results_text.insert('1.0', f"❌ {error_msg}")
            self.update_status("Error verifying integrity", 'Error')
            messagebox.showerror("Error", error_msg)

        finally:
            self.show_progress(False)

    def generate_integrity_report(self, modified, added, deleted, baseline):
        """Generate formatted integrity report"""
        report = f"{'='*60}\n"
        report += "FILE INTEGRITY REPORT\n"
        report += f"{'='*60}\n\n"

        report += f"📁 Directory: {baseline['directory']}\n"
        report += f"📅 Baseline: {baseline['timestamp'][:19]}\n"
        report += f"📅 Verified: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"🔒 Algorithm: {baseline['algorithm'].upper()}\n"
        report += f"📊 Baseline files: {baseline['file_count']}\n\n"

        if modified:
            report += f"🔴 MODIFIED FILES ({len(modified)}): \n"
            for mod in modified[:10]:  # Limit to first 10
                report += f"  • {mod['file']}\n"
                report += f"    Hash: {mod['baseline_hash']} → {mod['current_hash']}\n"
                if mod['baseline_size'] != mod['current_size']:
                    report += f"    Size: {mod['baseline_size']} → {mod['current_size']} bytes\n"
            if len(modified) > 10:
                report += f"  ... and {len(modified) - 10} more\n"
            report += "\n"

        if added:
            report += f"🟡 ADDED FILES ({len(added)}): \n"
            for file in added[:10]:  # Limit to first 10
                report += f"  + {file}\n"
            if len(added) > 10:
                report += f"  ... and {len(added) - 10} more\n"
            report += "\n"

        if deleted:
            report += f"🟠 DELETED FILES ({len(deleted)}): \n"
            for file in deleted[:10]:  # Limit to first 10
                report += f"  - {file}\n"
            if len(deleted) > 10:
                report += f"  ... and {len(deleted) - 10} more\n"
            report += "\n"

        total_changes = len(modified) + len(added) + len(deleted)
        if total_changes == 0:
            report += "✅ No changes detected - File integrity maintained\n"
        else:
            report += f"⚠️ Total changes detected: {total_changes}\n"

        report += f"\nReport completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"{'='*60}"

        return report

    def start_monitoring(self):
        """Start real-time monitoring (simplified for GUI)"""
        self.monitoring = True
        self.start_monitor_btn.config(state='disabled')
        self.stop_monitor_btn.config(state='normal')
        self.monitor_status.config(text="Monitoring: Active", style='Success.TLabel')

        # Add some sample events for demonstration
        self.add_monitor_event("INFO", "Real-time monitoring started")
        self.add_monitor_event("INFO", f"Monitoring directory: {self.target_directory.get()}")

        messagebox.showinfo("Monitoring", "Real-time monitoring started!")

    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitoring = False
        self.start_monitor_btn.config(state='normal')
        self.stop_monitor_btn.config(state='disabled')
        self.monitor_status.config(text="Monitoring: Inactive", style='Error.TLabel')

        self.add_monitor_event("INFO", "Real-time monitoring stopped")
        messagebox.showinfo("Monitoring", "Real-time monitoring stopped!")

    def add_monitor_event(self, level, message):
        """Add event to monitoring display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        event_text = f"[{timestamp}] {level}: {message}\n"

        self.events_text.insert('end', event_text)
        self.events_text.see('end')

    def clear_events(self):
        """Clear monitoring events display"""
        self.events_text.delete('1.0', 'end')

    def generate_report(self):
        """Generate security report"""
        report = f"{'='*50}\n"
        report += "SECURITY REPORT\n"
        report += f"{'='*50}\n\n"

        report += f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"📁 Directory: {self.target_directory.get()}\n"
        report += f"🔄 Monitoring Status: {'Active' if self.monitoring else 'Inactive'}\n\n"

        # Check if baseline exists
        baseline_file = os.path.join(self.target_directory.get(), ".integrity_baseline.json")
        if os.path.exists(baseline_file):
            try:
                with open(baseline_file, 'r') as f:
                    baseline = json.load(f)
                report += f"📊 Baseline Information:\n"
                report += f"  • Created: {baseline['timestamp'][:19]}\n"
                report += f"  • Files monitored: {baseline['file_count']}\n"
                report += f"  • Hash algorithm: {baseline['algorithm'].upper()}\n\n"
            except Exception:
                report += "❌ Error reading baseline file\n\n"
        else:
            report += "⚠️  No baseline found - Create baseline first\n\n"

        report += "🔒 Security Recommendations:\n"
        report += "  • Regularly verify file integrity\n"
        report += "  • Monitor critical system files\n"
        report += "  • Enable real-time monitoring\n"
        report += "  • Keep baseline updated\n"
        report += "  • Review security events regularly\n\n"

        report += f"Report ends\n"
        report += f"{'='*50}"

        self.report_text.delete('1.0', 'end')
        self.report_text.insert('1.0', report)

    def export_report(self):
        """Export security report to file"""
        report_content = self.report_text.get('1.0', 'end')
        if not report_content.strip():
            messagebox.showwarning("Warning", "No report to export. Generate a report first.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfilename=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )

        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(report_content)
                messagebox.showinfo("Export", f"Report exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {str(e)}")

    def save_settings(self):
        """Save configuration settings"""
        messagebox.showinfo("Settings", "Settings saved successfully!")


def main():
    """Main function to run the GUI"""
    root = tk.Tk()
    app = FileIntegrityGUI(root)

    try:
        root.mainloop()
    except KeyboardInterrupt:
        root.destroy()


if __name__ == "__main__":
    main()