#!/usr/bin/env python3
"""
Basic File Integrity Checker
A cybersecurity tool for detecting unauthorized file modifications
Author: Cybersecurity Project
"""

import hashlib
import os
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class BasicFileIntegrityChecker:
    """
    Basic file integrity checker using hash-based verification
    """

    def __init__(self, target_directory: str = ".", hash_algorithm: str = "sha256"):
        """
        Initialize the file integrity checker

        Args:
            target_directory: Directory to monitor
            hash_algorithm: Hash algorithm to use (md5, sha1, sha256, sha512)
        """
        self.target_directory = os.path.abspath(target_directory)
        self.hash_algorithm = hash_algorithm.lower()
        self.baseline_file = os.path.join(self.target_directory, ".file_integrity_baseline.json")
        self.supported_algorithms = ['md5', 'sha1', 'sha256', 'sha512']

        if self.hash_algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")

    def calculate_file_hash(self, file_path: str) -> str:
        """
        Calculate hash of a file

        Args:
            file_path: Path to the file

        Returns:
            Hexadecimal hash string
        """
        hash_obj = hashlib.new(self.hash_algorithm)

        try:
            with open(file_path, 'rb') as file:
                # Read file in chunks for memory efficiency
                while chunk := file.read(8192):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except (IOError, OSError) as e:
            print(f"Error reading file {file_path}: {e}")
            return ""

    def get_file_metadata(self, file_path: str) -> Dict:
        """
        Get file metadata including hash, size, and modification time

        Args:
            file_path: Path to the file

        Returns:
            Dictionary containing file metadata
        """
        try:
            stat_info = os.stat(file_path)
            return {
                'hash': self.calculate_file_hash(file_path),
                'size': stat_info.st_size,
                'modified_time': stat_info.st_mtime,
                'permissions': oct(stat_info.st_mode)[-3:],
                'algorithm': self.hash_algorithm
            }
        except (IOError, OSError) as e:
            print(f"Error getting metadata for {file_path}: {e}")
            return {}

    def scan_directory(self, directory: str = None) -> Dict[str, Dict]:
        """
        Scan directory and create file inventory

        Args:
            directory: Directory to scan (defaults to target_directory)

        Returns:
            Dictionary with file paths as keys and metadata as values
        """
        if directory is None:
            directory = self.target_directory

        file_inventory = {}

        print(f"Scanning directory: {directory}")

        for root, dirs, files in os.walk(directory):
            # Skip hidden directories and the baseline file
            dirs[:] = [d for d in dirs if not d.startswith('.')]

            for file in files:
                if file.startswith('.') or file.endswith('.json'):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, directory)

                metadata = self.get_file_metadata(file_path)
                if metadata:
                    file_inventory[relative_path] = metadata

        return file_inventory

    def create_baseline(self) -> bool:
        """
        Create initial baseline of all files in target directory

        Returns:
            True if baseline created successfully
        """
        print(f"Creating baseline for directory: {self.target_directory}")

        baseline_data = {
            'timestamp': datetime.now().isoformat(),
            'directory': self.target_directory,
            'algorithm': self.hash_algorithm,
            'files': self.scan_directory()
        }

        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(baseline_data, f, indent=2)

            print(f"Baseline created with {len(baseline_data['files'])} files")
            print(f"Baseline saved to: {self.baseline_file}")
            return True

        except (IOError, OSError) as e:
            print(f"Error creating baseline: {e}")
            return False

    def load_baseline(self) -> Optional[Dict]:
        """
        Load existing baseline

        Returns:
            Baseline data or None if not found
        """
        try:
            with open(self.baseline_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"No baseline found at {self.baseline_file}")
            return None
        except json.JSONDecodeError as e:
            print(f"Error parsing baseline file: {e}")
            return None

    def verify_integrity(self) -> Dict[str, List]:
        """
        Verify file integrity against baseline

        Returns:
            Dictionary containing lists of modified, added, and deleted files
        """
        baseline = self.load_baseline()
        if not baseline:
            return {'error': ['No baseline found. Create baseline first.']}

        print("\nVerifying file integrity...")
        print(f"Baseline created: {baseline['timestamp']}")

        current_files = self.scan_directory()
        baseline_files = baseline['files']

        # Find changes
        modified_files = []
        added_files = []
        deleted_files = []

        # Check for modifications and deletions
        for file_path, baseline_metadata in baseline_files.items():
            if file_path in current_files:
                current_metadata = current_files[file_path]
                if (current_metadata['hash'] != baseline_metadata['hash'] or
                    current_metadata['size'] != baseline_metadata['size']):
                    modified_files.append({
                        'file': file_path,
                        'baseline_hash': baseline_metadata['hash'],
                        'current_hash': current_metadata['hash'],
                        'baseline_size': baseline_metadata['size'],
                        'current_size': current_metadata['size']
                    })
            else:
                deleted_files.append(file_path)

        # Check for additions
        for file_path in current_files:
            if file_path not in baseline_files:
                added_files.append(file_path)

        return {
            'modified': modified_files,
            'added': added_files,
            'deleted': deleted_files
        }

    def print_integrity_report(self, changes: Dict[str, List]):
        """
        Print formatted integrity report

        Args:
            changes: Dictionary containing file changes
        """
        if 'error' in changes:
            print(f"Error: {changes['error'][0]}")
            return

        print("\n" + "="*60)
        print("FILE INTEGRITY REPORT")
        print("="*60)

        # Modified files
        if changes['modified']:
            print(f"\n🔴 MODIFIED FILES ({len(changes['modified'])}):")
            for mod in changes['modified']:
                print(f"  - {mod['file']}")
                print(f"    Baseline Hash: {mod['baseline_hash'][:16]}...")
                print(f"    Current Hash:  {mod['current_hash'][:16]}...")
                if mod['baseline_size'] != mod['current_size']:
                    print(f"    Size changed: {mod['baseline_size']} → {mod['current_size']} bytes")

        # Added files
        if changes['added']:
            print(f"\n🟡 ADDED FILES ({len(changes['added'])}):")
            for file in changes['added']:
                print(f"  + {file}")

        # Deleted files
        if changes['deleted']:
            print(f"\n🟠 DELETED FILES ({len(changes['deleted'])}):")
            for file in changes['deleted']:
                print(f"  - {file}")

        # Summary
        total_changes = len(changes['modified']) + len(changes['added']) + len(changes['deleted'])
        if total_changes == 0:
            print("\n✅ No changes detected - File integrity maintained")
        else:
            print(f"\n⚠️  Total changes detected: {total_changes}")

        print("\nReport generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print("="*60)


def main():
    """Main function to demonstrate the file integrity checker"""
    import argparse

    parser = argparse.ArgumentParser(description="File Integrity Checker")
    parser.add_argument("-d", "--directory", default=".", 
                       help="Directory to monitor (default: current directory)")
    parser.add_argument("-a", "--algorithm", default="sha256", 
                       choices=['md5', 'sha1', 'sha256', 'sha512'],
                       help="Hash algorithm to use (default: sha256)")
    parser.add_argument("-c", "--create-baseline", action="store_true",
                       help="Create new baseline")
    parser.add_argument("-v", "--verify", action="store_true",
                       help="Verify integrity against baseline")

    args = parser.parse_args()

    # Create checker instance
    checker = BasicFileIntegrityChecker(args.directory, args.algorithm)

    if args.create_baseline:
        checker.create_baseline()
    elif args.verify:
        changes = checker.verify_integrity()
        checker.print_integrity_report(changes)
    else:
        print("Please specify --create-baseline or --verify")
        print("Use -h for help")


if __name__ == "__main__":
    main()
