from flask import Flask, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'


app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost/jayanth'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
    
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')


class ConversationHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_query = db.Column(db.String(255))
    bot_response = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def load_ipc_dataset_updated(file_path):
    ipc_data = pd.read_csv(file_path)
    return ipc_data

def standardize_ipc_section(query):
    if query.isdigit():
        return f"IPC_{query}"
    match = re.search(r'ipc\s*[-_]*\s*(\d+)', query, re.I)
    if match:
        return f"IPC_{match.group(1)}"
    return None

def find_ipc_section_info(standardized_section, ipc_data):
    if standardized_section:
        direct_match = ipc_data[ipc_data['Section'].str.contains(standardized_section, case=False, na=False)]
        if not direct_match.empty:
            return direct_match.iloc[0].to_dict()
    return None

def store_conversation(user_query, bot_response, user_id):
    new_conversation = ConversationHistory(user_query=user_query, bot_response=bot_response, user_id=user_id)
    db.session.add(new_conversation)
    db.session.commit()

file_path = 'cleaned.csv'  
ipc_data = load_ipc_dataset_updated(file_path)

@app.route('/', methods=['GET'])
@login_required
def index():
    history = ConversationHistory.query.filter_by(user_id=current_user.id).order_by(ConversationHistory.timestamp.asc()).all()
    return render_template('chat.html', messages=history)



@app.route('/query', methods=['POST'])
@login_required
def query_ipc():
    user_query = request.form['user_query']
    standardized_section = standardize_ipc_section(user_query)
    section_info = find_ipc_section_info(standardized_section, ipc_data)
    relevant_info = section_info.get('Full Description', 'Data not found') if section_info else 'Data not found'
    store_conversation(user_query, relevant_info, current_user.id)
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user is None:
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful, please login.')
            return redirect(url_for('login'))
        flash('Username already exists.')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        print("User found:", user is not None)
        if user and check_password_hash(user.password_hash, password):
            print("Password correct, logging in user:", user.username)
            login_user(user)
            return redirect(url_for('index'))
        
        print("Invalid login attempt")
        flash('Invalid username or password')
    return render_template('login.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
