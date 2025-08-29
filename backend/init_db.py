from app import app, db
import models  # import models to ensure SQLAlchemy model registration


def init_db():
    with app.app_context():
        # Create all tables defined in models
        db.create_all()
        print("Database tables created successfully!")


if __name__ == '__main__':
    init_db()