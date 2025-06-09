import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta'

# Usuarios predefinidos (usuario: contraseña y su "certificado")
users = {
    'usuario1': {
        'password': 'pass1',
        'cert': 'C=US, ST=CA, O=Real Time Innovations, emailAddress=ecdsa01Peer01@rti.com, CN=RTI ECDSA01 (p256) PEER01'
    },
    'usuario2': {
        'password': 'pass2',
        'cert': 'C=ES, ST=Madrid, O=Mi Empresa, emailAddress=usuario2@miempresa.com, CN=Certificado Usuario2'
    }
}

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/index')
def index():
    return render_template('index.html')

# @app.route('/dashboard')
# def dashboard():
#     if 'username' in session:
#         username = session['username']
#         cert = users[username]['cert']
#         return render_template('dashboard.html', username=username, cert=cert)
#     return redirect(url_for('login'))

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

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')

#         if username in users and users[username]['password'] == password:
#             session['username'] = username
#             return redirect(url_for('index'))
#         else:
#             flash('Usuario o contraseña incorrectos', 'danger')

#     return render_template('login.html')

# @app.route('/logout')
# def logout():
#     session.pop('username', None)
#     return redirect(url_for('index'))














def get_user(username):
    conn = sqlite3.connect('roles.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username, password, cert FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user  # Será una tupla (username, password, cert) o None

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
        if user and password == user[1]:  # user[1] es la contraseña almacenada en bd
            session['username'] = user[0]
            session['cert'] = user[2]
            return redirect(url_for('index'))
        else:
            flash('Usuario o contraseña incorrectos', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('cert', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
