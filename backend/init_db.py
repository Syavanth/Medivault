from app import app, db
from models import User, MedicalHistory, Prescription, Appointment, LabReport, AccessRequest, MedicationReminder

def init_db():
    with app.app_context():
        # Create all tables
        db.create_all()
        print("Database tables created successfully!")

if __name__ == '__main__':
    init_db() 