#!/usr/bin/env python3
"""
File Integrity Checker - Demo Script
Demonstrates the functionality of all three file integrity tools
Author: Cybersecurity Project
"""

import os
import sys
import time
import tempfile
import shutil
from datetime import datetime

def create_demo_directory():
    """Create a temporary demo directory with test files"""
    demo_dir = os.path.join(tempfile.gettempdir(), f"fim_demo_{int(time.time())}")
    os.makedirs(demo_dir, exist_ok=True)

    # Create test files
    test_files = {
        'config.txt': 'server=localhost\nport=8080\nssl=true',
        'data.csv': 'name,age,city\nJohn,25,NYC\nJane,30,LA',
        'script.py': '#!/usr/bin/env python3\nprint("Hello World")',
        'readme.md': '# Test Project\nThis is a demo file.'
    }

    for filename, content in test_files.items():
        file_path = os.path.join(demo_dir, filename)
        with open(file_path, 'w') as f:
            f.write(content)

    # Create subdirectory with files
    subdir = os.path.join(demo_dir, 'subdir')
    os.makedirs(subdir, exist_ok=True)

    with open(os.path.join(subdir, 'nested.txt'), 'w') as f:
        f.write('This is a nested file')

    return demo_dir

def demo_basic_checker(demo_dir):
    """Demonstrate basic file integrity checker"""
    print(f"\n{'='*60}")
    print("DEMO: Basic File Integrity Checker")
    print(f"{'='*60}")

    # Import the basic checker
    sys.path.append('.')
    try:
        from basic_file_integrity_checker import BasicFileIntegrityChecker

        print(f"📁 Demo directory: {demo_dir}")
        print(f"📊 Files in directory: {len(os.listdir(demo_dir)) - 1}")  # -1 for subdir

        # Create checker instance
        checker = BasicFileIntegrityChecker(demo_dir, "sha256")

        # Create baseline
        print("\n1️⃣ Creating baseline...")
        success = checker.create_baseline()
        if success:
            print("✅ Baseline created successfully")
        else:
            print("❌ Failed to create baseline")
            return

        # Verify integrity (should be clean)
        print("\n2️⃣ Verifying integrity (should be clean)...")
        changes = checker.verify_integrity()
        checker.print_integrity_report(changes)

        # Modify a file
        print("\n3️⃣ Modifying a file...")
        config_file = os.path.join(demo_dir, 'config.txt')
        with open(config_file, 'a') as f:
            f.write('\n# Modified by demo')
        print(f"📝 Modified: {config_file}")

        # Add a new file
        print("\n4️⃣ Adding a new file...")
        new_file = os.path.join(demo_dir, 'new_file.txt')
        with open(new_file, 'w') as f:
            f.write('This is a new file added during demo')
        print(f"➕ Added: {new_file}")

        # Delete a file
        print("\n5️⃣ Deleting a file...")
        readme_file = os.path.join(demo_dir, 'readme.md')
        os.remove(readme_file)
        print(f"🗑️ Deleted: {readme_file}")

        # Verify integrity again (should show changes)
        print("\n6️⃣ Verifying integrity (should show changes)...")
        changes = checker.verify_integrity()
        checker.print_integrity_report(changes)

    except ImportError as e:
        print(f"❌ Could not import basic checker: {e}")
    except Exception as e:
        print(f"❌ Demo error: {e}")

def demo_gui_info():
    """Provide information about GUI demo"""
    print(f"\n{'='*60}")
    print("DEMO: GUI File Integrity Checker")
    print(f"{'='*60}")

    print("🖥️  To demo the GUI version:")
    print("   python3 gui_file_integrity_checker.py")
    print("")
    print("📋 GUI Demo Steps:")
    print("   1. Launch the GUI application")
    print("   2. Browse to select your demo directory")
    print("   3. Create a baseline using the GUI")
    print("   4. Make some file changes outside the GUI")
    print("   5. Verify integrity using the GUI")
    print("   6. Explore the monitoring and reports tabs")

def demo_advanced_info():
    """Provide information about advanced monitor demo"""
    print(f"\n{'='*60}")
    print("DEMO: Advanced File Integrity Monitor")
    print(f"{'='*60}")

    print("⚡ To demo the advanced monitor:")
    print("   python3 advanced_file_integrity_monitor.py -d /path/to/demo --monitor")
    print("")
    print("📋 Advanced Demo Steps:")
    print("   1. Create baseline: python3 advanced_file_integrity_monitor.py -c -d /demo/dir")
    print("   2. Start monitoring: python3 advanced_file_integrity_monitor.py -m -d /demo/dir")
    print("   3. Make changes to files in another terminal")
    print("   4. Watch real-time alerts in the monitor")
    print("   5. Generate reports: python3 advanced_file_integrity_monitor.py -r -d /demo/dir")

def run_hash_comparison_demo():
    """Demonstrate different hash algorithms"""
    print(f"\n{'='*60}")
    print("DEMO: Hash Algorithm Comparison")
    print(f"{'='*60}")

    # Create a test file
    test_content = "This is a test file for hash algorithm comparison.\n" * 10
    test_file = os.path.join(tempfile.gettempdir(), 'hash_test.txt')

    with open(test_file, 'w') as f:
        f.write(test_content)

    print(f"📄 Test file: {test_file}")
    print(f"📊 File size: {len(test_content)} characters")

    # Import hash library
    import hashlib

    algorithms = ['md5', 'sha1', 'sha256', 'sha512']

    print("\n🔐 Hash Results:")
    for algorithm in algorithms:
        hash_obj = hashlib.new(algorithm)

        with open(test_file, 'rb') as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)

        hash_value = hash_obj.hexdigest()
        print(f"  {algorithm.upper():>6}: {hash_value}")

    # Demonstrate hash sensitivity
    print("\n🔍 Hash Sensitivity Test:")

    # Modify file by one character
    modified_content = test_content[:-1] + 'X'  # Change last character
    modified_file = os.path.join(tempfile.gettempdir(), 'hash_test_modified.txt')

    with open(modified_file, 'w') as f:
        f.write(modified_content)

    print("📝 Modified file (changed 1 character):")

    for algorithm in algorithms:
        hash_obj = hashlib.new(algorithm)

        with open(modified_file, 'rb') as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)

        hash_value = hash_obj.hexdigest()
        print(f"  {algorithm.upper():>6}: {hash_value}")

    # Cleanup
    os.remove(test_file)
    os.remove(modified_file)

def main():
    """Main demo function"""
    print("🔒 FILE INTEGRITY CHECKER - CYBERSECURITY PROJECT DEMO")
    print("=" * 65)
    print(f"📅 Demo started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        # Create demo directory
        demo_dir = create_demo_directory()
        print(f"\n📁 Created demo directory: {demo_dir}")

        # Run hash comparison demo
        run_hash_comparison_demo()

        # Run basic checker demo
        demo_basic_checker(demo_dir)

        # Provide GUI demo info
        demo_gui_info()

        # Provide advanced monitor info  
        demo_advanced_info()

        print(f"\n{'='*60}")
        print("DEMO SUMMARY")
        print(f"{'='*60}")
        print("✅ Basic file integrity checker demonstrated")
        print("ℹ️  GUI and advanced monitor information provided")
        print("🔐 Hash algorithm comparison completed")
        print("📁 Demo files remain in:", demo_dir)
        print("\n🧹 To cleanup demo files:")
        print(f"   rm -rf {demo_dir}")

        print(f"\n📅 Demo completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    except Exception as e:
        print(f"❌ Demo failed: {str(e)}")

    print("\n🔒 Thank you for trying the File Integrity Checker project!")

if __name__ == "__main__":
    main()
