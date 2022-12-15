from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    admin = db.Column(db.Boolean, default=False)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)


class Nasdaq(db.Model):
    id = db.Column(db.Integer, primary_key=True,  autoincrement=True)
    name = db.Column(db.String(10), nullable=False)
    date = db.Column(db.DateTime, nullable=True)
    low = db.Column(db.Float, nullable=True)
    open = db.Column(db.Float, nullable=True)
    volume = db.Column(db.BigInteger, nullable=True)
    high = db.Column(db.Float, nullable=True)
    close = db.Column(db.Float, nullable=True)
    adjustedClose = db.Column(db.Float, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
