# models.py
from datetime import datetime
from app import db

class User(db.Model):
    __tablename__ = "users"   # public.users 사용
    __table_args__ = {"schema": "public"}  # 혹시 스키마 지정 필요하면 추가

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.Text, unique=True, nullable=False, index=True)
    username = db.Column(db.Text, nullable=True)
    password_hash = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    role = db.Column(db.String(20), default="user")

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at.isoformat()
        }

