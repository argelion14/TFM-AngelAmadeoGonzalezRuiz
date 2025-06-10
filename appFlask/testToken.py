import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta'

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

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/decode')
def decode():
    return render_template('decode.html')

def get_roles():
    conn = sqlite3.connect('roles.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM roles")
    rows = cursor.fetchall()
    conn.close()
    return rows

@app.route("/roles")
def roles():
    roles = get_roles()
    return render_template("roles.html", roles=roles)

def get_users():
    conn = sqlite3.connect('roles.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, cert FROM users")
    rows = cursor.fetchall()
    conn.close()
    return rows

@app.route("/usuarios")
def usuarios():
    if not session.get('is_superuser'):
        return render_template("acceso_denegado.html"), 403
    users = get_users()
    return render_template("usuarios.html", usuarios=users)

def get_user(username):
    conn = sqlite3.connect('roles.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username, password, cert, is_superuser FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user  # Será una tupla (username, password, cert, is_superuser)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        cert = session.get('cert')
        return render_template('dashboard.html', username=username, cert=cert)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = get_user(username)
        if user and password == user[1]:
            session['username'] = user[0]
            session['cert'] = user[2]
            session['is_superuser'] = user[3] == 1  # 👈 Guardamos booleano
            return redirect(url_for('index'))
        else:
            flash('Usuario o contraseña incorrectos', 'danger')

    return render_template('login.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('cert', None)
    session.pop('is_superuser', None)
    return redirect(url_for('index'))














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

@app.route("/usuarios2")
def usuarios2():
    if not session.get('is_superuser'):
        return render_template("acceso_denegado.html"), 403
    users = get_users2()
    return render_template("usuarios_roles.html", usuarios=users)  # Usa la nueva plantilla


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
