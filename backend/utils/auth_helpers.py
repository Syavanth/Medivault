from werkzeug.security import generate_password_hash, check_password_hash
from models import User

def hash_password(password):
    return generate_password_hash(password)

def verify_password(password, stored_hash):
    return check_password_hash(stored_hash, password)

def find_user_by_email(email):
    return User.query.filter_by(email=email).first()
