from app import app, db

with app.app_context():
    # Drop all existing tables
    db.drop_all()
    # Create fresh tables
    db.create_all()
    print("Database tables created successfully. You can now add your own data through the application.")
