from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from models import db, User
import logging
from datetime import timedelta
import traceback

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/users', methods=['GET'])
def list_users():
    try:
        users = User.query.all()
        return jsonify([{
            'email': u.email,
            'name': u.name,
            'role': u.role
        } for u in users])
    except Exception as e:
        logger.error(f"Error listing users: {str(e)}")
        return jsonify({"error": "Failed to list users"}), 500

@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        required = ['email', 'password', 'name', 'role']
        if not all(field in data for field in required):
            return jsonify({'error': 'Missing required fields'}), 400

        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already registered'}), 400

        new_user = User(
            email=data['email'],
            password_hash=generate_password_hash(data['password']),
            name=data['name'],
            role=data['role'],
            phone_number=data.get('phone_number')
        )
        db.session.add(new_user)
        db.session.flush()  # Get new_user.user_id before commit

        # If registering a doctor, also add to Doctor table
        if data['role'].lower() == 'doctor':
            # You may want to collect specialization/availability from frontend
            specialization = data.get('specialization', 'General')
            availability_slots = data.get('availability_slots', '')
            # normalize availability_slots to JSON string
            import json
            if isinstance(availability_slots, list):
                availability_slots = json.dumps(availability_slots)
            elif isinstance(availability_slots, str) and availability_slots.strip() == '':
                availability_slots = json.dumps([])
            from models import Doctor
            new_doctor = Doctor(
                doctor_id=new_user.user_id,
                specialization=specialization,
                availability_slots=availability_slots
            )
            db.session.add(new_doctor)

        db.session.commit()

        logger.info(f"New user registered: {data['email']}")
        return jsonify({
            'message': 'Registration successful',
            'user': {
                'id': new_user.user_id,
                'name': new_user.name,
                'email': new_user.email,
                'role': new_user.role
            }
        }), 201
    except Exception as e:
        logger.error("Registration error: %s", str(e), exc_info=True)
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Registration failed'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'error': 'Email and password are required'}), 400

        user = User.query.filter_by(email=data['email']).first()
        if not user or not check_password_hash(user.password_hash, data['password']):
            return jsonify({'error': 'Invalid email or password'}), 401

        # Create a JWT token valid for 1 day
        access_token = create_access_token(
            identity=str(user.user_id),  # identity must be a string
            additional_claims={'role': user.role},
            expires_delta=timedelta(days=1)
        )


        logger.info(f"User logged in: {user.email}")

        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'user': {
                'id': user.user_id,
                'name': user.name,
                'email': user.email,
                'role': user.role
            }
        }), 200
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500
