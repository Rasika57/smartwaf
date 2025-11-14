SmartWAF - Lightweight Web Application Firewall (Regex only)
-----------------------------------------------------------

How to run (local):
1. unzip SmartWAF.zip
2. create a virtual env (optional)
   python -m venv venv
   source venv/bin/activate   (Linux/Mac) OR venv\Scripts\activate (Windows)
3. install dependencies:
   pip install flask
4. run:
   python app.py
5. open http://127.0.0.1:5000 in your browser

Admin dashboard:
- Login at /login
- Username: admin
- Password: admin123
- Dashboard URL: /smartadmin

Notes:
- This is a demo/proof-of-concept WAF. Do NOT use as production WAF.
- The detection uses simple regex rules. You can extend waf.py to add more patterns.