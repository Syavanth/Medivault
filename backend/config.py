import os
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Base directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Database configuration
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'mydb.sqlite')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'medivault_secret_key_2024_secure')
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
    
    # Logging configuration
    LOG_LEVEL = logging.INFO
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Logging setup
logging.basicConfig(
    level=Config.LOG_LEVEL,
    format=Config.LOG_FORMAT
)
