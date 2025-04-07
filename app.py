import os
from datetime import datetime

from flask import Flask, render_template, session
from flask import flash, redirect, url_for, request
from flask import jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from config import Config
from enums.taskStatus import TaskStatus
from models import db, Task, User, TaskHistory, Attachment

app = Flask(__name__)
app.config['SECRET_KEY'] = 'some_random_secret_key'
app.config.from_object(Config)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'attachments')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx', 'txt'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)


@app.route('/')
@login_required
def index():
    return redirect(url_for('tasks'))


@app.route('/tasks')
@login_required
def tasks():
    tasks = Task.query.filter_by(user_id=current_user.id, is_deleted=False).order_by(Task.priority.asc(),
                                                                                     Task.deadline.asc()).all()
    return render_template('tasks.html', tasks=tasks)


@app.route('/all-tasks')
@login_required
def all_tasks():
    if not current_user.is_admin:
        return redirect(url_for('tasks'))

    tasks = Task.query.order_by(Task.priority.asc(), Task.deadline.asc()).all()
    return render_template('all_tasks.html', tasks=tasks)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/add_task', methods=['GET', 'POST'])
@login_required
def add_task():
    if not current_user.is_admin():
        flash('Nie masz uprawnień do tej strony.', 'danger')
        return redirect(url_for('tasks'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        deadline = request.form.get('deadline')
        priority = int(request.form['priority'])
        user_id = request.form.get('user_id')

        if not user_id:
            flash("Musisz wybrać użytkownika!", "danger")
            return redirect(url_for('add_task'))

        assigned_user = db.session.get(User, user_id)
        if not assigned_user:
            flash("Wybrany użytkownik nie istnieje!", "danger")
            return redirect(url_for('add_task'))

        deadline = datetime.strptime(deadline, "%Y-%m-%d") if deadline else None
        new_task = Task(title=title, content=content, deadline=deadline, priority=priority, user_id=user_id)
        db.session.add(new_task)
        db.session.commit()

        task_history = TaskHistory(
            task_id=new_task.id,
            action="Utworzono zadanie",
            user_id=current_user.id
        )
        db.session.add(task_history)
        db.session.commit()

        if 'attachments' in request.files:
            files = request.files.getlist('attachments')
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                    file.save(filepath)

                    attachment = Attachment(
                        filename=filename,
                        file_url=url_for('static', filename=f'attachments/{filename}', _external=True),
                        task_id=new_task.id
                    )
                    db.session.add(attachment)

            db.session.commit()

        flash('Zadanie zostało dodane!', 'success')
        return redirect(url_for('all_tasks'))

    return render_template('add_task.html')


@app.route('/task/<int:task_id>')
@login_required
def task_details(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id and not current_user.is_admin:
        flash('Nie masz uprawnień do przeglądania tego zadania.', 'danger')
        return redirect(url_for('tasks'))
    attachments = Attachment.query.filter_by(task_id=task.id).all()
    task_history = TaskHistory.query.filter_by(task_id=task_id).order_by(TaskHistory.timestamp.desc()).all()

    return render_template('task_details.html', task=task, attachments=attachments, task_history=task_history)


@app.route('/complete/<int:task_id>')
@login_required
def complete_task(task_id):
    task = Task.query.get(task_id)
    if task and task.user_id == current_user.id:
        task.completed = not task.completed
        db.session.commit()

        action = 'Ukonczono' if task.completed else 'Anulowano'
        history = TaskHistory(task_id=task.id, action=action, user_id=current_user.id)
        db.session.add(history)
        db.session.commit()

    return redirect(url_for('tasks'))


@app.route('/delete/<int:task_id>')
@login_required
def delete_task(task_id):
    task = Task.query.get(task_id)

    if task and (task.user_id == current_user.id or current_user.role == 'admin'):
        history = TaskHistory(task_id=task.id, action='Usunięto', user_id=current_user.id)
        db.session.add(history)

        task.is_deleted = True
        db.session.commit()

        print("✅ Zadanie oznaczone jako usunięte.")
    else:
        print("⛔ Brak uprawnień.")
        flash("Brak uprawnień do usunięcia tego zadania.", "danger")

    return redirect(url_for('all_tasks'))



@app.route('/users/autocomplete', methods=['GET'])
@login_required
def autocomplete_users():
    if not current_user.is_admin():
        return jsonify([])

    search = request.args.get('q', '')
    users = User.query.filter(
        (User.first_name.ilike(f"%{search}%")) | (User.last_name.ilike(f"%{search}%")),
        User.is_deleted == False
    ).all()

    users_list = [{"id": user.id, "name": f"{user.first_name} {user.last_name}"} for user in users]

    return jsonify(users_list)


@app.route('/tasks/<int:task_id>/status', methods=['POST'])
@login_required
def update_status(task_id):
    task = Task.query.get_or_404(task_id)

    if task.user_id != current_user.id:
        flash("Nie masz dostępu do tego zadania!", "danger")
        return redirect(url_for('tasks'))

    new_status = request.form.get('status')

    try:
        new_status_enum = TaskStatus[new_status]

        if task.status != new_status_enum.value:
            old_status = task.status
            task.status = new_status_enum.value

            history_entry = TaskHistory(
                task_id=task.id,
                action=f'Zmieniono status:{old_status}->{new_status_enum.value}',
                user_id=current_user.id
            )
            db.session.add(history_entry)
            db.session.commit()
            flash("Status zaktualizowany i zapisany w historii!", "success")
        else:
            flash("Status nie został zmieniony.", "info")

    except KeyError:
        flash("Niepoprawny status!", "danger")

    return redirect(url_for('tasks'))


@app.route('/users')
@login_required
def users():
    if not current_user.is_admin():
        flash("Nie masz dostępu do tej strony!", "danger")
        return redirect(url_for('index'))

    users = User.query.filter_by(is_deleted=False).all()
    return render_template('users.html', users=users)


@app.route('/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin():
        flash("Nie masz dostępu do tej strony!", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'user')

        if not first_name or not last_name or not username or not password:
            flash("Wszystkie pola są wymagane!", "danger")
            return redirect(url_for('add_user'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Nazwa użytkownika jest już zajęta!", "danger")
            return redirect(url_for('add_user'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(first_name=first_name, last_name=last_name, username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash("Użytkownik został dodany!", "success")
        return redirect(url_for('users'))

    return render_template('add_user.html')

@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin():
        flash("Nie masz dostępu do tej strony!", "danger")
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.first_name = request.form.get('first_name')
        user.last_name = request.form.get('last_name')
        user.username = request.form.get('username')
        user.role = request.form.get('role')

        db.session.commit()
        flash("Dane użytkownika zostały zaktualizowane.", "success")
        return redirect(url_for('users'))

    return render_template('edit_user.html', user=user)

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin():
        flash("Nie masz dostępu!", "danger")
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)

    if user.is_deleted:
        flash("Użytkownik już został usunięty.", "warning")
        return redirect(url_for('users'))

    user.is_deleted = True
    db.session.commit()
    flash("Użytkownik został usunięty.", "success")
    return redirect(url_for('users'))


@app.route('/reset_password/<user_id>/<last_name>', methods=['GET'])
@login_required
def reset_password(user_id, last_name):
    if not current_user.is_admin():
        flash("Nie masz dostępu!", "danger")
        return redirect(url_for('index'))

    new_password = f"{last_name}123!"
    user = User.query.get(user_id)
    if user:
        user.password = generate_password_hash(new_password)
        db.session.commit()

        flash('Hasło zostało zresetowane pomyślnie!', 'success')
    else:
        flash('Użytkownik nie został znaleziony!', 'error')

    return redirect(url_for('users'))


@app.route('/user-details')
@login_required
def user_details():
    return render_template('user_details.html', user=current_user)


@app.route('/reset_password_self', methods=['POST'])
@login_required
def reset_password_self():
    user = current_user

    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not check_password_hash(user.password, old_password):
        flash("Błąd: Stare hasło jest niepoprawne!", "danger")
        return redirect(url_for('user_details'))

    if new_password != confirm_password:
        flash("Błąd: Nowe hasła nie są identyczne!", "danger")
        return redirect(url_for('user_details'))

    if len(new_password) < 8:
        flash("Błąd: Nowe hasło musi mieć co najmniej 8 znaków!", "danger")
        return redirect(url_for('user_details'))

    user.password = generate_password_hash(new_password)
    db.session.commit()

    flash("Sukces: Hasło zostało zmienione!", "success")
    return redirect(url_for('user_details'))



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, is_deleted=False).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('tasks'))
        else:
            flash('Niepoprawna nazwa użytkownika lub hasło.')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Zostałeś wylogowany.")
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                password=generate_password_hash('password123'),
                role='admin',
                first_name='John',
                last_name='Doe',
                is_deleted=False,
            )
            db.session.add(admin_user)

        db.session.commit()

    app.run(debug=True)
