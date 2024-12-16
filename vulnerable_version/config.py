import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # DB Configuration
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'database', 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'yoursecretkey'
    # Mail Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = 'saharmichelleleetcode@gmail.com'
    MAIL_PASSWORD = 'jhav gwxi yiop yjou' 
    MAIL_DEFAULT_SENDER = 'saharmichelleleetcode@gmail.com' 
    # Password Configuration
    PASSWORD_MIN_LENGTH = 10  # Minimum length
    PASSWORD_COMPLEXITY = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{10,}$"  # One uppercase, one lowercase, one number, one special character
    PASSWORD_HISTORY_LIMIT = 3  # Number of previous passwords to remember
    PASSWORD_DICTIONARY = ['password', '123456', 'qwerty', 'admin'] 
    LOGIN_ATTEMPTS_LIMIT = 3  # Max number of failed login attempts