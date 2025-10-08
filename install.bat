@echo off
echo Installing File Integrity Checker Project...

python --version nul 2&1
if errorlevel 1 (
    echo Python is not installed or not in PATH
    echo Please install Python 3.7+ from python.org
    pause
    exit b 1
)

echo Installing required packages...
pip install -r requirements.txt

echo.
echo Installation completed!
echo.
echo Usage examples
echo 1. Basic checker python basic_file_integrity_checker.py -c -d Cpathtodirectory
echo 2. Advanced monitor python advanced_file_integrity_monitor.py -m -d Cpathtodirectory
echo 3. GUI version python gui_file_integrity_checker.py
echo.
echo For help python [script_name].py -h
pause
