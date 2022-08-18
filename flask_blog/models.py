from datetime import datetime
from email.policy import default
from enum import unique
from flask_blog import db
from flask_login import UserMixin


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.png')
    password = db.Column(db.Sring(60), nullable=False)
    posts = db.relationthip('Post', backref='author', lazy=True)

    def __repr__(self):
        return f'Пользователь("{self.username}", "{self.email}", "{self.image_file}")'

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.Foreignkey('user.id', nullable=False))

def __repr__(self):
    return f'Запись("{self.title}", "{self.date_posted}")'
