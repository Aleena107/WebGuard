from datetime import datetime
from database import db


class Analysis(db.Model):
    __tablename__ = "analyses"

    id = db.Column(db.Integer, primary_key=True)

    url = db.Column(db.String(2048), nullable=False)

    risk_score = db.Column(db.Integer, nullable=False)

    risk_level = db.Column(db.String(20), nullable=False)

    page_title = db.Column(db.String(500))

    forms = db.Column(db.Integer, default=0)

    links = db.Column(db.Integer, default=0)

    images = db.Column(db.Integer, default=0)

    scripts = db.Column(db.Integer, default=0)

    password_fields = db.Column(db.Integer, default=0)

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )