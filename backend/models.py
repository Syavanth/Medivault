from datetime import datetime, date
from extensions import db  # import the shared db instance

# ------------------- USERS -------------------
class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'Patient' or 'Doctor'
    phone_number = db.Column(db.String(20))  # New field for phone number

# ------------------- DOCTORS -------------------
class Doctor(db.Model):
    __tablename__ = 'doctors'
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), primary_key=True)
    specialization = db.Column(db.String(100), nullable=False)
    availability_slots = db.Column(db.Text)

# ------------------- PATIENT ACCESS CONTROL -------------------
class PatientAccess(db.Model):
    __tablename__ = 'patient_access'
    patient_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.doctor_id'), primary_key=True)
    access_granted = db.Column(db.Boolean, default=False)
    granted_on = db.Column(db.DateTime, default=datetime.utcnow)

# ------------------- MEDICAL HISTORY -------------------
class MedicalHistory(db.Model):
    __tablename__ = 'medical_history'
    record_id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    disease = db.Column(db.String(200))
    allergies = db.Column(db.String(200))
    surgery_history = db.Column(db.Text)

# ------------------- PRESCRIPTIONS -------------------
class Prescription(db.Model):
    __tablename__ = 'prescriptions'
    prescription_id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.doctor_id'), nullable=False)
    diagnosis = db.Column(db.String(255))
    date_issued = db.Column(db.Date, default=datetime.utcnow)

    # Relationships
    medicine_entries = db.relationship('MedicineEntry', backref='prescription', lazy=True)

# ------------------- MEDICINE ENTRIES -------------------
class MedicineEntry(db.Model):
    __tablename__ = 'medicine_entries'
    id = db.Column(db.Integer, primary_key=True)
    prescription_id = db.Column(db.Integer, db.ForeignKey('prescriptions.prescription_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    dosage = db.Column(db.String(100))
    frequency = db.Column(db.String(100))
    timing = db.Column(db.String(100))

    # Relationships
    reminders = db.relationship('MedicationReminder', backref='medicine', lazy=True)

# ------------------- MEDICATION REMINDERS -------------------
class MedicationReminder(db.Model):
    __tablename__ = 'medication_reminders'
    reminder_id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    medicine_entry_id = db.Column(db.Integer, db.ForeignKey('medicine_entries.id'), nullable=False)
    remind_at = db.Column(db.Time, nullable=False)
    start_date = db.Column(db.Date, default=date.today)
    end_date = db.Column(db.Date)
    is_active = db.Column(db.Boolean, default=True)

# ------------------- APPOINTMENTS -------------------
class Appointment(db.Model):
    __tablename__ = 'appointments'
    appointment_id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.doctor_id'), nullable=False)
    date_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default="Pending")  # Pending/Approved/Cancelled

# ------------------- LAB REPORTS -------------------
class LabReport(db.Model):
    __tablename__ = 'lab_reports'
    report_id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    report_type = db.Column(db.String(100))
    file_url = db.Column(db.String(300))
    uploaded_on = db.Column(db.DateTime, default=datetime.utcnow)

# ------------------- DOCTOR ACCESS REQUESTS -------------------
class DoctorRequest(db.Model):
    __tablename__ = 'doctor_requests'
    request_id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.doctor_id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    status = db.Column(db.String(20), default='Pending')  # Pending/Approved/Denied
