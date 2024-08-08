from app import app, db, Dock, User
from sqlalchemy import inspect
from werkzeug.security import generate_password_hash

def initialize_docks_and_admin():
    with app.app_context():
        # Check if the 'dock' table exists
        inspector = inspect(db.engine)
        if not inspector.has_table('dock'):
            # Create all tables
            db.create_all()
        
        # Check if docks are already present
        if not Dock.query.first():
            # Add initial docks
            docks = [Dock(number=i) for i in range(1, 6)]
            db.session.add_all(docks)
            db.session.commit()
            print("Initialized docks in the database.")
        else:
            print("Docks already exist in the database.")
        
        # Check if the default admin user exists
        admin_user = User.query.filter_by(email='admin@admin.com').first()
        if not admin_user:
            # Create the default admin user
            hashed_password = generate_password_hash('Dikketieten123')
            admin_user = User(email='admin@admin.com', password=hashed_password, is_admin=True)
            db.session.add(admin_user)
            db.session.commit()
            print("Created default admin user.")
        else:
            print("Default admin user already exists.")

if __name__ == '__main__':
    initialize_docks_and_admin()
