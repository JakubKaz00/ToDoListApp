from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')
    is_deleted = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.first_name} {self.last_name}>'

    def is_admin(self):
        return self.role == 'admin'


class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_url = db.Column(db.String(255), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)

    task = db.relationship('Task', back_populates='attachments')

    def __repr__(self):
        return f'<Attachment {self.filename}>'


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.String(255), nullable=True)
    completed = db.Column(db.Boolean, default=False)
    deadline = db.Column(db.DateTime, nullable=True)
    priority = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), nullable=False, default="TODO")
    is_deleted = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref=db.backref('tasks', lazy=True))

    attachments = db.relationship('Attachment', back_populates='task')

    def __repr__(self):
        return f'<Task {self.title}>'


class TaskHistory(db.Model):
    __tablename__ = 'task_history'

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    task = db.relationship('Task', backref='history', lazy=True)
    user = db.relationship('User', backref='history', lazy=True)

    def __repr__(self):
        return f'<TaskHistory {self.action} - Task {self.task_id}>'
