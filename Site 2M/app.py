from flask import Flask, render_template, url_for, redirect, request, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user 
from database import db, User
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializa o banco de dados
db.init_app(app)

# Configuração do Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login_get'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Cria o banco de dados se não existir
with app.app_context():
    db.create_all()

# Rotas
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('index.html')

# Adicionando rota GET para login
@app.route('/login', methods=['GET'])
def login_get():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('login.html')  # Você precisará criar este template

@app.route('/login', methods=['POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    username = request.form.get('username')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(username=username).first()

    if not user or not user.verify_password(password):
        flash('Usuário ou senha incorretos!', 'danger')
        return redirect(url_for('login_get'))

    login_user(user, remember=remember)
    return redirect(url_for('home'))

@app.route('/cadastro', methods=['GET'])
def cadastro():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('cadastro.html')

@app.route('/cadastro', methods=['POST'])
def cadastro_post():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm-password')

    # Validações
    if password != confirm_password:
        flash('As senhas não coincidem!', 'danger')
        return redirect(url_for('cadastro'))

    if User.query.filter_by(username=username).first():
        flash('Nome de usuário já em uso!', 'danger')
        return redirect(url_for('cadastro'))

    if User.query.filter_by(email=email).first():
        flash('Email já cadastrado!', 'danger')
        return redirect(url_for('cadastro'))

    # Cria novo usuário
    new_user = User(username=username, email=email, password=password)
    db.session.add(new_user)
    db.session.commit()

    flash('Cadastro realizado com sucesso! Faça login.', 'success')
    return redirect(url_for('login_get'))

@app.route('/home')
@login_required
def home():
    return render_template('home.html', username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)