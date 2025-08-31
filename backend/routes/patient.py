from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity,  get_jwt
from models import Doctor, db, User, Prescription, MedicationReminder, Appointment, PatientAccess, MedicalHistory, LabReport, DoctorRequest, MedicineEntry
import logging
from datetime import datetime, timedelta, timezone
import json

logger = logging.getLogger(__name__)

patient_bp = Blueprint('patient', __name__)

def get_doctor_name(doctor_id):
    doctor = db.session.get(User, doctor_id)
    return doctor.name if doctor else "Unknown Doctor"

def extract_user_identity():
    # get_jwt_identity() returns the user_id string; role is in claims
    user_id = get_jwt_identity()
    claims = get_jwt()
    return int(user_id), claims.get('role')

@patient_bp.route('/dashboard', methods=['GET'])
@jwt_required()
def patient_dashboard():
    try:
        # ✅ Now identity is just the user_id string
        current_user_id = get_jwt_identity()
        claims = get_jwt()  # contains role from additional_claims
        logger.info(f"JWT Identity (user_id): {current_user_id}, Role: {claims.get('role')}")

        # ✅ Role check from claims
        if claims.get('role') != 'Patient':
            logger.warning(f"Unauthorized access attempt by user {current_user_id} with role {claims.get('role')}")
            return jsonify({"error": "Unauthorized"}), 403

        # user_id is a string, convert to int if needed for DB queries
        user_id = int(current_user_id)

        # Fetch all necessary data
        medical_history = MedicalHistory.query.filter_by(patient_id=user_id).first()
        prescriptions = Prescription.query.filter_by(patient_id=user_id).all()
        appointments = Appointment.query.filter_by(patient_id=user_id).all()
        lab_reports = LabReport.query.filter_by(patient_id=user_id).all()
        access_requests = DoctorRequest.query.filter_by(patient_id=user_id, status='Pending').all()
        current_access = PatientAccess.query.filter_by(patient_id=user_id, access_granted=True).all()
        reminders = MedicationReminder.query.filter_by(patient_id=user_id).all()

        # Medical History
        medical_history_data = {
            'disease': medical_history.disease if medical_history else '',
            'allergies': medical_history.allergies if medical_history else '',
            'surgery_history': medical_history.surgery_history if medical_history else ''
        }

        # Prescriptions
        prescriptions_data = [{
            'prescription_id': p.prescription_id,
            'doctor_name': get_doctor_name(p.doctor_id),
            'diagnosis': p.diagnosis,
            'date_issued': p.date_issued.strftime('%Y-%m-%d'),
            'medicines': [{
                'name': m.name,
                'dosage': m.dosage,
                'frequency': m.frequency,
                'timing': m.timing
            } for m in p.medicine_entries]
        } for p in prescriptions]

        # Appointments
        appointments_data = [{
            'appointment_id': a.appointment_id,
            'doctor_name': get_doctor_name(a.doctor_id),
            'date': a.date_time.strftime('%Y-%m-%d'),
            'time': a.date_time.strftime('%H:%M'),
            'status': a.status
        } for a in appointments]

        # Lab Reports
        lab_reports_data = [{
            'report_id': r.report_id,
            'report_type': r.report_type,
            'file_url': r.file_url,
            'uploaded_on': r.uploaded_on.strftime('%Y-%m-%d')
        } for r in lab_reports]

        # Access Requests
        access_requests_data = [{
            'request_id': req.request_id,
            'doctor_name': get_doctor_name(req.doctor_id),
            'status': req.status,
            'purpose': req.purpose,
            'request_date': req.request_date.strftime('%Y-%m-%d') if req.request_date else None
        } for req in access_requests]

        # Current Access
        current_access_data = [{
            'access_id': access.access_id,
            'doctor_name': get_doctor_name(access.doctor_id),
            'granted_date': access.granted_on.strftime('%Y-%m-%d') if access.granted_on else None,
            'expiry_date': access.expiry_date.strftime('%Y-%m-%d') if access.expiry_date else None
        } for access in current_access]

        # Reminders
        reminders_data = []
        for r in reminders:
            med = db.session.get(MedicineEntry, r.medicine_entry_id) if r.medicine_entry_id else None
            reminders_data.append({
                'reminder_id': r.reminder_id,
                'medicine_name': med.name if med else 'Unknown Medicine',
                'dosage': med.dosage if med else 'Unknown Dosage',
                'time': r.remind_at.strftime('%H:%M'),
                'is_active': r.is_active
            })

        return jsonify({
            'medical_history': medical_history_data,
            'prescriptions': prescriptions_data,
            'appointments': appointments_data,
            'lab_reports': lab_reports_data,
            'access_requests': access_requests_data,
            'current_access': current_access_data,
            'reminders': reminders_data
        })

    except Exception as e:
        logger.error(f"Error in patient_dashboard: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@patient_bp.route('/prescriptions', methods=['GET'])
@jwt_required()
def get_prescriptions():
    try:
        user_id = int(get_jwt_identity())
        claims = get_jwt()
        role = claims.get('role')
        if role != 'Patient':
            return jsonify({"error": "Unauthorized"}), 403

        prescriptions = Prescription.query.filter_by(patient_id=user_id).all()
        prescriptions_data = [{
            'prescription_id': prescription.prescription_id,
            'doctor_name': get_doctor_name(prescription.doctor_id),
            'diagnosis': prescription.diagnosis,
            'date_issued': prescription.date_issued.strftime('%Y-%m-%d'),
            'medicines': [{
                'name': medicine.name,
                'dosage': medicine.dosage,
                'frequency': medicine.frequency,
                'timing': medicine.timing
            } for medicine in prescription.medicine_entries]
        } for prescription in prescriptions]

        return jsonify(prescriptions_data), 200

    except Exception as e:
        logger.error(f"Error in get_prescriptions: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@patient_bp.route('/reminders', methods=['GET'])
@jwt_required()
def get_reminders():
    try:
        user_id = int(get_jwt_identity())
        claims = get_jwt()
        role = claims.get('role')
        if role != 'Patient':
            return jsonify({"error": "Unauthorized"}), 403

        reminders = MedicationReminder.query.filter_by(patient_id=user_id).all()
        reminders_data = []
        for reminder in reminders:
            med = db.session.get(MedicineEntry, reminder.medicine_entry_id) if reminder.medicine_entry_id else None
            reminders_data.append({
                'reminder_id': reminder.reminder_id,
                'medicine_name': med.name if med else 'Unknown Medicine',
                'dosage': med.dosage if med else 'Unknown Dosage',
                'time': reminder.remind_at.strftime('%H:%M'),
                'is_active': reminder.is_active
            })

        return jsonify(reminders_data), 200

    except Exception as e:
        logger.error(f"Error in get_reminders: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@patient_bp.route('/appointments', methods=['GET'])
@jwt_required()
def get_appointments():
    try:
        user_id = int(get_jwt_identity())
        claims = get_jwt()
        if claims.get('role') != 'Patient':
            return jsonify({"error": "Unauthorized"}), 403

        appointments = Appointment.query.filter_by(patient_id=user_id).all()
        appointments_data = [{
            'appointment_id': appointment.appointment_id,
            'doctor_name': get_doctor_name(appointment.doctor_id),
            'date': appointment.date_time.strftime('%Y-%m-%d'),
            'time': appointment.date_time.strftime('%H:%M'),
            'status': appointment.status
        } for appointment in appointments]

        return jsonify(appointments_data), 200

    except Exception as e:
        logger.error(f"Error in get_appointments: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@patient_bp.route('/grant-access', methods=['POST'])
@jwt_required()
def grant_access():
    try:
        user_id = int(get_jwt_identity())
        claims = get_jwt()
        role = claims.get('role')
        if role != 'Patient':
            return jsonify({"error": "Unauthorized"}), 403

        doctor_id = request.json.get('doctor_id')
        if not doctor_id:
            return jsonify({"error": "Doctor ID is required"}), 400

        existing_access = PatientAccess.query.filter_by(patient_id=user_id, doctor_id=doctor_id).first()
        if existing_access:
            return jsonify({"message": "Access already granted"}), 200

        new_access = PatientAccess(patient_id=user_id, doctor_id=doctor_id, access_granted=True)
        db.session.add(new_access)
        db.session.commit()
        return jsonify({"message": "Access granted successfully"}), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in grant_access: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@patient_bp.route('/available-doctors', methods=['GET'])
@jwt_required()
def available_doctors():
    try:
        user_id = int(get_jwt_identity())
        claims = get_jwt()
        role = claims.get('role')
        logger.info(f"/available-doctors called for user_id={user_id}, role={role}")
        if role != 'Patient':
            logger.warning(f"Unauthorized attempt for /available-doctors by user_id={user_id}, role={role}")
            return jsonify({'error': 'Unauthorized'}), 403

        # Use Doctor table directly (make sure your DB is populated)
        doctors = Doctor.query.all()
        logger.info(f"Found {len(doctors)} doctors in Doctor table")
        doctors_data = [
            {
                'id': d.doctor_id,
                'name': getattr(d, 'name', None) or get_doctor_name(d.doctor_id),
                'specialization': getattr(d, 'specialization', None),
                'availability_slots': getattr(d, 'availability_slots', None),
            }
            for d in doctors
        ]
        print("Doctors data sent to frontend:", doctors_data)
        return jsonify(doctors_data)
    except Exception as e:
        logger.error(f"Error fetching available doctors: {e}", exc_info=True)
        return jsonify({'error': 'Failed to fetch doctors'}), 500


@patient_bp.route('/appointments', methods=['POST'])
@jwt_required()
def create_appointment():
    try:
        user_id = int(get_jwt_identity())
        claims = get_jwt()
        if claims.get('role') != 'Patient':
            return jsonify({'error': 'Unauthorized'}), 403

        data = request.get_json()
        doctor_id = data.get('doctor_id')
        date_time_str = data.get('date_time')
        purpose = data.get('purpose')

        if not doctor_id or not date_time_str or not purpose:
            return jsonify({'error': 'Missing required fields'}), 400

        doctor = db.session.get(Doctor, int(doctor_id))
        if not doctor:
            return jsonify({'error': 'Doctor not found'}), 404

        # Parse requested slot (expect ISO datetime string representing slot.start)
        try:
            requested_start = datetime.fromisoformat(date_time_str).astimezone(timezone.utc)
        except Exception:
            return jsonify({'error': 'Invalid date_time format. Use ISO format.'}), 400

        # Load doctor's availability as slot objects [{start,end}, ...]
        slots = []
        if doctor.availability_slots:
            try:
                slots = json.loads(doctor.availability_slots)
            except Exception:
                # fallback: treat as list of strings
                raw = [s.strip() for s in str(doctor.availability_slots).split(',') if s.strip()]
                for s in raw:
                    try:
                        st = datetime.fromisoformat(s).astimezone(timezone.utc)
                        slots.append({'start': st.isoformat(), 'end': (st + timedelta(hours=1)).isoformat()})
                    except Exception:
                        continue

        # Find matching slot object by exact start match (UTC)
        matched_slot = None
        for s in slots:
            try:
                s_start = datetime.fromisoformat(s['start']).astimezone(timezone.utc)
                if s_start == requested_start:
                    matched_slot = s
                    break
            except Exception:
                continue

        if slots and not matched_slot:
            return jsonify({'error': 'Requested slot not available for this doctor'}), 400

        # Prevent overlapping appointments (any overlap with matched slot)
        def overlaps(a_start, a_end, b_start, b_end):
            return max(a_start, b_start) < min(a_end, b_end)

        # Compute requested end from matched slot or default 1 hour
        if matched_slot:
            requested_end = datetime.fromisoformat(matched_slot['end']).astimezone(timezone.utc)
        else:
            requested_end = requested_start + timedelta(hours=1)

        conflict = None
        # check any appointment that overlaps requested_start..requested_end
        for ap in Appointment.query.filter(Appointment.doctor_id == int(doctor_id)).all():
            try:
                ap_start = ap.date_time.astimezone(timezone.utc) if ap.date_time.tzinfo else ap.date_time.replace(tzinfo=timezone.utc)
                ap_end = ap_start + timedelta(hours=1)
                if overlaps(ap_start, ap_end, requested_start, requested_end):
                    conflict = ap
                    break
            except Exception:
                continue

        if conflict:
            return jsonify({'error': 'Selected slot conflicts with existing appointment'}), 409

        # All checks passed; create appointment and remove slot atomically
        try:
            new_appt = Appointment(
                patient_id=user_id,
                doctor_id=int(doctor_id),
                date_time=requested_start,
                status='Pending',
                purpose=purpose
            )
            db.session.add(new_appt)

            # remove matched_slot from doctor's availability
            if matched_slot:
                remaining = [s for s in slots if not (s.get('start') == matched_slot.get('start') and s.get('end') == matched_slot.get('end'))]
                doctor.availability_slots = json.dumps(remaining)

            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error saving appointment: {e}", exc_info=True)
            return jsonify({'error': 'Failed to create appointment'}), 500

        appointment_data = {
            'appointment_id': new_appt.appointment_id,
            'patient_id': new_appt.patient_id,
            'doctor_id': new_appt.doctor_id,
            'doctor_name': get_doctor_name(new_appt.doctor_id),
            'date': new_appt.date_time.strftime('%Y-%m-%d'),
            'time': new_appt.date_time.strftime('%H:%M'),
            'purpose': new_appt.purpose,
            'status': new_appt.status
        }

        return jsonify({'message': 'Appointment created', 'appointment': appointment_data}), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating appointment: {e}", exc_info=True)
        return jsonify({'error': 'Failed to create appointment'}), 500


@patient_bp.route('/appointments/<int:appointment_id>', methods=['DELETE'])
@jwt_required()
def delete_appointment(appointment_id):
    try:
        user_id = int(get_jwt_identity())
        claims = get_jwt()
        if claims.get('role') != 'Patient':
            return jsonify({'error': 'Unauthorized'}), 403

        appt = db.session.get(Appointment, appointment_id)
        if not appt:
            return jsonify({'error': 'Appointment not found'}), 404

        if appt.patient_id != user_id:
            return jsonify({'error': 'Forbidden'}), 403

        # Capture slot to possibly restore to doctor's availability (ISO in UTC)
        slot_iso = None
        try:
            slot_iso = appt.date_time.astimezone(timezone.utc).isoformat()
        except Exception:
            try:
                slot_iso = appt.date_time.replace(tzinfo=timezone.utc).isoformat()
            except Exception:
                slot_iso = None

        # Do not allow deletion of completed or cancelled appointments
        if appt.status and appt.status.lower() in ('completed', 'cancelled'):
            return jsonify({'error': 'Cannot delete an appointment that is completed or cancelled'}), 400

        # Do not allow deletion if appointment has already started or passed
        try:
            now = datetime.utcnow().replace(tzinfo=timezone.utc)
            appt_dt = appt.date_time.astimezone(timezone.utc) if appt.date_time.tzinfo else appt.date_time.replace(tzinfo=timezone.utc)
            if appt_dt <= now:
                return jsonify({'error': 'Cannot delete an appointment that has already started or passed'}), 400
        except Exception:
            # if date parsing fails, be conservative and disallow deletion
            return jsonify({'error': 'Cannot delete appointment due to invalid appointment time'}), 400

        # Delete appointment
        db.session.delete(appt)
        db.session.commit()

        # Restore doctor's slot if possible
        try:
            if slot_iso:
                doctor = db.session.get(Doctor, appt.doctor_id)
                if doctor:
                    slots = []
                    if doctor.availability_slots:
                        try:
                            slots = json.loads(doctor.availability_slots)
                        except Exception:
                            slots = [s.strip() for s in str(doctor.availability_slots).split(',') if s.strip()]
                    # slots may be objects or strings; normalize to objects
                    normalized = []
                    for s in slots:
                        if isinstance(s, dict) and s.get('start'):
                            normalized.append(s)
                        elif isinstance(s, str):
                            try:
                                st = datetime.fromisoformat(s).astimezone(timezone.utc)
                                normalized.append({'start': st.isoformat(), 'end': (st + timedelta(hours=1)).isoformat()})
                            except Exception:
                                continue

                    # If slot_iso matches the start of an existing slot, don't duplicate
                    try:
                        iso_dt = datetime.fromisoformat(slot_iso).astimezone(timezone.utc)
                        exists = any(datetime.fromisoformat(s['start']).astimezone(timezone.utc) == iso_dt for s in normalized)
                    except Exception:
                        exists = False

                    if not exists:
                        normalized.append({'start': slot_iso, 'end': (datetime.fromisoformat(slot_iso).astimezone(timezone.utc) + timedelta(hours=1)).isoformat()})
                        doctor.availability_slots = json.dumps(normalized)
                        db.session.commit()
        except Exception:
            db.session.rollback()

        return jsonify({'message': 'Appointment deleted successfully'}), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting appointment: {e}", exc_info=True)
        return jsonify({'error': 'Failed to delete appointment'}), 500


