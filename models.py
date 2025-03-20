from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)  # Increase to 255 or more
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
class CoalInventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coal_stock = db.Column(db.Float, nullable=False)  # Stock in MT
    coal_sufficiency = db.Column(db.Float, nullable=False)  # Days of sufficiency
    daily_consumption = db.Column(db.Float, nullable=False)  # MT per day
    electricity_generation = db.Column(db.Float, nullable=False)  # MW
    coal_wastage = db.Column(db.Float, nullable=False)  # MT
    updated_date = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)  # Add this line

    def __repr__(self):
        return f'<CoalInventory {self.id}>'
    