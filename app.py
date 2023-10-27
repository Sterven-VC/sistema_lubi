from flask import Flask, render_template, request, redirect, url_for, flash, make_response
from flask_mysqldb import MySQL
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from config import config
# Models:
from models.ModelUser import ModelUser
# Entities:
from models.entities.User import User

app = Flask(__name__)
csrf = CSRFProtect()
db = MySQL(app)
login_manager_app = LoginManager(app)

@login_manager_app.user_loader
def load_user(id):
    return ModelUser.get_by_id(db, id)

@app.route('/')
def index():
    return redirect(url_for('login'))

def status_401(error):
    return redirect(url_for('login'))

def status_404(error):
    return "<h1>Página no encontrada</h1>", 404

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.tipo_user == 0:
            return redirect(url_for('home'))
        elif current_user.tipo_user == 1:
            return redirect(url_for('admin'))
    
    if request.method == 'POST':
        user = User(0, request.form['username'], request.form['password'])
        logged_user = ModelUser.login(db, user)
        if logged_user is not None:
            # La función ModelUser.login ya debería haber verificado si la contraseña es correcta
            # Así que no necesitas comprobar de nuevo aquí

            login_user(logged_user)
            if logged_user.tipo_user == 0:
                return redirect(url_for('home'))
            elif logged_user.tipo_user == 1:
                return redirect(url_for('admin'))
        else:
            flash("Contraseña inválida")
            # En lugar de mostrar un mensaje de error, redirige a la página de inicio de sesión
            return redirect(url_for('login'))
    else:
        return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        fullname = request.form['fullname']
        # Verifica si el usuario ya existe en la base de datos
        existing_user = ModelUser.get_by_username(db, username)
        if existing_user is not None:
            flash("El nombre de usuario ya está en uso. Por favor, elige otro nombre de usuario.")
        elif not username or not password or not confirm_password or not fullname:
            flash("Por favor, complete todos los campos.")
        elif password != confirm_password:
            flash("Las contraseñas no coinciden.")
        else:
            # Crea un nuevo usuario y lo guarda en la base de datos
            new_user = User(0, username, password, fullname)
            result = ModelUser.register(db, new_user, confirm_password)
            if result:
                flash("Registro exitoso. ¡Ahora puedes iniciar sesión!")
                return redirect(url_for('login'))
    return render_template('auth/register.html')

@app.route('/logout')
@login_required
def logout():
    flash('Has cerrado sesión.')
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
def admin():
    response = make_response(render_template('admin.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


@app.route('/home')
@login_required
def home():
    response = make_response(render_template('home.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/perfil')
@login_required
def perfil():
    response = make_response(render_template('perfil.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/tema1')
@login_required
def tema1():
    response = make_response(render_template('Tema1/tema1.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/tema1-1')
@login_required
def intro1():
    response = make_response(render_template('Tema1/tema1-1.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/tema1-2')
@login_required
def intro2():
    response = make_response(render_template('Tema1/tema1-2.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/tema1-3')
@login_required
def intro3():
    response = make_response(render_template('Tema1/tema1-3.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/tema1-4')
@login_required
def intro4():
    response = make_response(render_template('Tema1/tema1-4.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/tema2')
@login_required
def tema2():
    response = make_response(render_template('Tema2/tema2.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/tema3')
@login_required
def tema3():
    response = make_response(render_template('Tema3/tema3.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/tema4')
@login_required
def tema4():
    response = make_response(render_template('Tema4/tema4.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/protected')
@login_required
def protected():
    return "<h1>Esta es una vista protegida, solo para usuarios autenticados.</h1>"

if __name__ == '__main__':
    app.config.from_object(config['development'])
    csrf.init_app(app)
    app.register_error_handler(401, status_401)
    app.register_error_handler(404, status_404)
    app.run()