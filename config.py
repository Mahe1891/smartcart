# config.py
# ------------------------------------
# This file holds all configurations
# like Secret Key, Database connection
# details, Email settings, Razorpay keys etc.
# ------------------------------------

SECRET_KEY = "abc@123"   # used for sessions

# MySQL Database Configuration
DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWORD = "Mahe0120@"  # keep empty if no password
DB_NAME = "smartcart"


# Email SMTP Settings
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'kmahendra1891@gmail.com'
MAIL_PASSWORD = 'rfudduqjshzycpej'   # Gmail App Password

RAZORPAY_KEY_ID = "rzp_test_Sgt3SitBBeknng"
RAZORPAY_KEY_SECRET = "BM1I01MW07F6R1aNzUmFUayZ"
