from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from config import Config
from models import db
import logging

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Enable CORS for frontend (React on port 3000)
db.init_app(app)
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])

jwt = JWTManager(app)

# Configure logging
logging.basicConfig(
    level=app.config['LOG_LEVEL'],
    format=app.config['LOG_FORMAT']
)
logger = logging.getLogger(__name__)

# Import and register blueprints
from routes.auth import auth_bp
from routes.patient import patient_bp
from routes.doctor import doctor_bp

app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(patient_bp, url_prefix='/api/patient')
app.register_blueprint(doctor_bp, url_prefix='/api/doctor')

# Create tables if they don't exist
with app.app_context():
    db.create_all()
    logger.info("Database tables created")

if __name__ == '__main__':
    logger.info("Starting Medivault server...")
    app.run(debug=True)
