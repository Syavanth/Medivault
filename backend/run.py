from app import app, db
import logging
import sys
from flask_cors import CORS

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)

CORS(app)

logger = logging.getLogger(__name__)

if __name__ == '__main__':
    try:
        with app.app_context():
            # Test database connection
            logger.info("Attempting to connect to PostgreSQL database...")
            connection = db.engine.connect()
            logger.info("Successfully connected to PostgreSQL database")
            
            # Create tables if they don't exist
            logger.info("Creating database tables...")
            db.create_all()
            logger.info("Database tables created successfully")
            
            # Closing the connection explicitly (optional, but good practice)
            connection.close()
            
            # Start the Flask development server
            logger.info("Starting Flask development server...")
            app.run(host='0.0.0.0', port=5000, debug=True)
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        sys.exit(1)
