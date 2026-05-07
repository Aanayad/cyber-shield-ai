@echo off
echo Installing packages...
pip install flask numpy pandas scikit-learn
echo.
echo Starting AI CyberShield...
echo Open browser at: http://localhost:5000
echo.
python app.py
pause
