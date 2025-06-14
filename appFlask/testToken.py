import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, g
import jwt
import datetime


app = Flask(__name__)
app.secret_key = 'tu_clave_secreta'

JWT_SECRET = 'clave_jwt_segura'  # cámbiala por algo fuerte
JWT_EXPIRATION_MINUTES = 60

# # Usuarios predefinidos (usuario: contraseña y su "certificado")
# users = {
#     'usuario1': {
#         'password': 'pass1',
#         'cert': 'C=US, ST=CA, O=Real Time Innovations, emailAddress=ecdsa01Peer01@rti.com, CN=RTI ECDSA01 (p256) PEER01'
#     },
#     'usuario2': {
#         'password': 'pass2',
#         'cert': 'C=ES, ST=Madrid, O=Mi Empresa, emailAddress=usuario2@miempresa.com, CN=Certificado Usuario2'
#     }
# }


def get_roles():
    conn = sqlite3.connect('roles.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM roles")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_users():
    conn = sqlite3.connect('roles.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, cert FROM users")
    rows = cursor.fetchall()
    conn.close()
    return rows


# @app.route('/dashboard')
# def dashboard():
#     if 'username' in session:
#         username = session['username']
#         cert = session.get('cert')
#         return render_template('dashboard.html', username=username, cert=cert)
#     return redirect(url_for('login'))


def get_user(username):
    conn = sqlite3.connect('roles.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, password, cert, is_superuser FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user  # Será una tupla (username, password, cert, is_superuser)


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')

#         user = get_user(username)
#         if user and password == user[1]:
#             session['username'] = user[0]
#             session['cert'] = user[2]
#             session['is_superuser'] = user[3] == 1  # 👈 Guardamos booleano
#             return redirect(url_for('index'))
#         else:
#             flash('Usuario o contraseña incorrectos', 'danger')

#     return render_template('login.html')


# @app.route('/logout')
# def logout():
#     session.pop('username', None)
#     session.pop('cert', None)
#     session.pop('is_superuser', None)
#     return redirect(url_for('index'))


def get_roles_by_username(username):
    conn = sqlite3.connect('roles.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.name, r.description
        FROM users u
        JOIN user_roles ur ON u.id = ur.user_id
        JOIN roles r ON ur.role_id = r.id
        WHERE u.username = ?
    ''', (username,))
    roles = cursor.fetchall()
    conn.close()
    return roles


def get_users2():
    conn = sqlite3.connect('roles.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Recuperamos todos los usuarios
    cursor.execute("""
        SELECT u.id, u.username, u.cert,
               GROUP_CONCAT(r.name) AS roles
        FROM users u
        LEFT JOIN user_roles ur ON u.id = ur.user_id
        LEFT JOIN roles r ON ur.role_id = r.id
        GROUP BY u.id
    """)
    rows = cursor.fetchall()
    conn.close()

    # Transformamos roles en lista
    usuarios = []
    for row in rows:
        usuarios.append({
            'id': row['id'],
            'username': row['username'],
            'cert': row['cert'],
            'roles': row['roles'].split(',') if row['roles'] else []
        })

    return usuarios


def get_all_users_and_roles():
    conn = sqlite3.connect('roles.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users")
    users = cursor.fetchall()

    cursor.execute("SELECT id, name FROM roles")
    roles = cursor.fetchall()

    conn.close()
    return users, roles


def assign_role_to_user(user_id, role_id):
    conn = sqlite3.connect('roles.db')
    cursor = conn.cursor()
    # Comprobamos si ya está asignado
    cursor.execute(
        "SELECT * FROM user_roles WHERE user_id = ? AND role_id = ?", (user_id, role_id))
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", (user_id, role_id))
        conn.commit()
    conn.close()


def generar_jwt(user):
    payload = {
        'username': user[0],
        'cert': user[2],
        'is_superuser': user[3] == 1,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=JWT_EXPIRATION_MINUTES)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token


def verificar_jwt():
    token = request.cookies.get('token')
    if not token:
        return None
    try:
        datos = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return datos
    except jwt.ExpiredSignatureError:
        flash("Sesión expirada. Por favor inicia sesión de nuevo.", "warning")
    except jwt.InvalidTokenError:
        flash("Token inválido.", "danger")
    return None

SECRET_KEY = "tu_clave_secreta"


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = get_user(username)
        if user and password == user[1]:
            token = generar_jwt(user)
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('token', token, httponly=True, samesite='Lax')
            return resp
        else:
            flash('Usuario o contraseña incorrectos', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('token', '', expires=0)
    return resp


# @app.route('/logout')
# def logout():
#     session.pop('username', None)
#     session.pop('cert', None)
#     session.pop('is_superuser', None)
#     return redirect(url_for('index'))


# @app.before_request
# def cargar_usuario_desde_token():
#     token = request.headers.get('Authorization', '').replace('Bearer ', '')
#     g.user = None
#     if token:
#         try:
#             data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
#             g.user = {
#                 'username': data['username'],
#                 'is_superuser': data.get('is_superuser', False),
#                 # puedes añadir más campos si necesitas
#             }
#         except jwt.ExpiredSignatureError:
#             g.user = None
#         except jwt.InvalidTokenError:
#             g.user = None


# @app.context_processor
# def inject_user_data():
#     user = getattr(g, 'current_user', None)
#     return {
#         'is_superadmin': getattr(user, 'is_superadmin', False) if user else False
#     }


def decodificar_jwt(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.context_processor
def inyectar_datos_token():
    token = request.cookies.get('token')
    datos_token = {}
    if token:
        datos = decodificar_jwt(token)
        if datos:
            datos_token = datos  # Contiene username, cert, is_superuser, etc.
    return {'token_data': datos_token}
















@app.route('/')
def home():
    return render_template('home.html')


@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/decode')
def decode():
    return render_template('decode.html')


@app.route('/informacion')
def informacion():
    return render_template('informacion.html')


@app.route("/roles")
def roles():
    roles = get_roles()
    return render_template("roles.html", roles=roles)


# @app.route("/usuarios")
# def usuarios():
#     if not session.get('is_superuser'):
#         return render_template("acceso_denegado.html"), 403
#     users = get_users()
#     return render_template("usuarios.html", usuarios=users)


@app.route('/usuarios')
def usuarios():
    user = verificar_jwt()
    if user:
        users = get_users()
        return render_template('usuarios.html', usuarios=users)
    return redirect(url_for('login'))


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.route('/mis_roles')
def mis_roles():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    roles = get_roles_by_username(username)
    return render_template('mis_roles.html', username=username, roles=roles)


@app.route("/usuarios2")
def usuarios2():
    if not session.get('is_superuser'):
        return render_template("acceso_denegado.html"), 403
    users = get_users2()
    # Usa la nueva plantilla
    return render_template("usuarios_roles.html", usuarios=users)


@app.route("/asignar_rol", methods=["GET", "POST"])
def asignar_rol():
    if not session.get("is_superuser"):
        return render_template("acceso_denegado.html"), 403

    if request.method == "POST":
        user_id = request.form.get("user_id")
        role_id = request.form.get("role_id")
        if user_id and role_id:
            assign_role_to_user(user_id, role_id)
            conn = sqlite3.connect('roles.db')
            cursor = conn.cursor()
            cursor.execute(
                "SELECT username FROM users WHERE id = ?", (user_id,))
            username = cursor.fetchone()[0]
            cursor.execute("SELECT name FROM roles WHERE id = ?", (role_id,))
            role_name = cursor.fetchone()[0]
            conn.close()
            flash(
                f"✅ Rol '{role_name}' asignado a '{username}' correctamente.", "success")
        return redirect(url_for("asignar_rol"))

    users, roles = get_all_users_and_roles()
    return render_template("asignar_rol.html", users=users, roles=roles)


@app.route('/dashboard')
def dashboard():
    user = verificar_jwt()
    if user:
        return render_template('dashboard.html', username=user['username'], cert=user['cert'])
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
