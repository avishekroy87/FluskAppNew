from flask import Flask, request, redirect, url_for, flash,render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import render_template_string


app = Flask(__name__)
app.config['SECRET_KEY'] = 'abc123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view ='login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(64), nullable=False)

def load_user(id):
    return User.query.get(id)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@app.route('/index')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    else:
        return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('You are now registered!')
        return redirect(url_for('login'))

    return render_template_string('''
    <!DOCTYPE html>
        <html>
        <head><title>Register</title></head>
        <body>
            <h2>Register</h2>
            {% with messages = get_flashed_messages() %}
                {% if messages %}
                    <ul>
                    {% for message in messages %}
                        <li>{{ message }}</li>
                    {% endfor %}
                    </ul>
                {% endif %}
            {% endwith %}
            <form method="post">
                Username: <input type="text" name="username" required><br><br>
                Password: <input type="password" name="password" required><br><br>
                <input type="submit" value="Register">
            </form>
            <p><a href="{{ url_for('login') }}">Already have an account? Login</a></p>
        </body>
        </html>

    ''')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head><title>Login</title></head>
    <body>
    <h2>Login</h2>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <ul>
            {% for message in messages %}
            <li>{{ message }}</li>
            <ul>
            {% endfor %}
        {% endif %}
    {% endwith %}
    <form method="post">
    Username: <input type="text" name="username" required><br><br>
    Password: <input type="password" name="password" required><br><br>
    <input type="submit" value="Login">
    </form>
    <p>Don't have a account register <a href="{{ url_for('register') }}">Register</a></p>

    ''')


@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/home')
@login_required
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head><title>Home</title></head>
    <body>
        <h2>Welcome, {{ current_user.username }}!</h2>
        <p>This is your protected home page.</p>
        <a href="{{ url_for('logout') }}">Logout</a>
    </body>
    </html>
    ''', current_user=current_user)

if (__name__ == '__main__'):
    with app.app_context():
        db.create_all()
    app.run(debug=True)