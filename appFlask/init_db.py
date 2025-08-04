import os
import sqlite3
import bcrypt
import subprocess
import platform
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from dotenv import load_dotenv

load_dotenv()

CA_CERT_PATH = os.getenv("CA_CERT_PATH")
CA_KEY_PATH = os.getenv("CA_KEY_PATH")
NEW_CERT_PATH = os.getenv("NEW_CERT_PATH")
DB_PATH = os.getenv("DB_PATH", "config/TFM.db")

# TODO: Borrar este DEBUG
print(f"🗄️ Usando base de datos en: {DB_PATH}")

# Detectar entorno (Windows o Unix)
if platform.system() == "Windows":
    OPENSSL_PATH = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
else:
    OPENSSL_PATH = "/usr/bin/openssl"


def generate_cert_and_key(username) -> tuple[str, str, str]:
    """
    Genera clave privada, CSR y certificado firmado por la CA.

    Devuelve:
    - cert_pem: contenido del certificado en texto
    - key_path: ruta absoluta al archivo de clave privada
    - cert_path: ruta al archivo PEM del certificado
    """
    base_dir = os.path.join(NEW_CERT_PATH, username)
    os.makedirs(base_dir, exist_ok=True)

    key_path = os.path.join(base_dir, "private.key")
    csr_path = os.path.join(base_dir, "request.csr")
    cert_path = os.path.join(base_dir, "certificate.pem")

    # 1. Clave privada
    subprocess.run([
        OPENSSL_PATH, "genpkey", "-algorithm", "EC",
        "-pkeyopt", "ec_paramgen_curve:P-256",
        "-out", key_path
    ], check=True)

    # 2. CSR
    subj = f"/C=ES/ST=Madrid/O=Mi Empresa/CN={username}/emailAddress={username}@miempresa.com"
    subprocess.run([
        OPENSSL_PATH, "req", "-new", "-key", key_path,
        "-out", csr_path, "-subj", subj
    ], check=True)

    # 3. Firmar con la CA
    subprocess.run([
        OPENSSL_PATH, "x509", "-req", "-in", csr_path,
        "-CA", CA_CERT_PATH, "-CAkey", CA_KEY_PATH,
        "-CAcreateserial", "-out", cert_path,
        "-days", "365"
    ], check=True)

    # 4. Leer contenido del certificado
    with open(cert_path, 'r') as f:
        cert_pem = f.read()

    return cert_pem, key_path, cert_path


def initialize_db():
    if os.path.exists(DB_PATH):
        # TODO: Borrar este debug
        print("✔️ La base de datos ya existe, no se necesita crearla.")
        return

    print("🛠️ Creando base de datos y tablas por primera vez...")
    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA foreign_keys = ON')
    cursor = conn.cursor()

    # --- TABLAS ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS grantTemplate (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            default_action TEXT CHECK(default_action IN ('ALLOW', 'DENY'))
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            cert TEXT,
            is_superuser INTEGER NOT NULL DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            public_cert TEXT NOT NULL,
            private_key_path TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            exp_time INTEGER NOT NULL DEFAULT 60,
            grant_id INTEGER,
            FOREIGN KEY (grant_id) REFERENCES grantTemplate(id) ON DELETE SET NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_roles (
            user_id INTEGER,
            role_id INTEGER,
            PRIMARY KEY (user_id, role_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS topics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            permiso TEXT CHECK(permiso IN ('allow_rule', 'deny_rule')) NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rule_domains (
            rule_id INTEGER,
            domain_id INTEGER,
            PRIMARY KEY (rule_id, domain_id),
            FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE,
            FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rule_topics (
            rule_id INTEGER NOT NULL,
            topic_id INTEGER NOT NULL,
            action TEXT CHECK(action IN ('publish', 'subscribe')) NOT NULL,
            PRIMARY KEY (rule_id, topic_id, action),
            FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE,
            FOREIGN KEY (topic_id) REFERENCES topics(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS grant_rules (
            grant_id INTEGER,
            rule_id INTEGER,
            PRIMARY KEY (grant_id, rule_id),
            FOREIGN KEY (grant_id) REFERENCES grantTemplate(id) ON DELETE CASCADE,
            FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
        )
    ''')

    # --- ROLES ---
    roles = [
        ('operator', 'Role operator: Domains 1-3, Topics: telemetry, Subscribe', 60),
        ('remote_driver', 'Remote driver: Truck publish', 30),
        ('trucks', 'Trucks (3): Topics: Telemetry, Remote Control', 45),
        ('drones', 'Drones (1): Topics: Telemetry, Video feed', 25),
        ('field', 'Field (2): Telemetry', 20)
    ]
    for role in roles:
        cursor.execute(
            'INSERT OR IGNORE INTO roles (name, description, exp_time) VALUES (?, ?, ?)', role)

    # --- USUARIOS ---
    # --- USUARIOS ---
    users = [
        ('usuario1', 'pass1', 1),
        ('usuario2', 'pass2', 0)
    ]

    for username, password_plain, is_superuser in users:
        hashed_password = bcrypt.hashpw(password_plain.encode(
            'utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Insertar en tabla users (sin certificado aún)
        cursor.execute(
            'INSERT INTO users (username, password, is_superuser) VALUES (?, ?, ?)',
            (username, hashed_password, is_superuser)
        )
        user_id = cursor.lastrowid

        # Generar clave privada y certificado autofirmado con OpenSSL
        cert_pem, key_path, cert_path = generate_cert_and_key(username)

        # Obtener el subject real del certificado usando openssl
        result = subprocess.run([
            OPENSSL_PATH, "x509", "-in", cert_path, "-noout", "-subject"
        ], capture_output=True, text=True, check=True)

        # Procesar el subject (e.g. "subject= C=ES, ST=Madrid, O=Mi Empresa, CN=usuario1, emailAddress=usuario1@miempresa.com")
        subject_line = result.stdout.strip()
        subject_clean = subject_line.replace("subject=", "").strip()

        # Actualizar campo cert con el subject limpio
        cursor.execute(
            'UPDATE users SET cert = ? WHERE id = ?',
            (subject_clean, user_id)
        )

        # Guardar claves en user_keys
        cursor.execute(
            'INSERT INTO user_keys (user_id, public_cert, private_key_path) VALUES (?, ?, ?)',
            (user_id, cert_pem, key_path)
        )

    # --- ASIGNACIÓN DE ROLES ---
    cursor.execute("SELECT id FROM users WHERE username = 'usuario1'")
    usuario1_id = cursor.fetchone()[0]
    cursor.execute("SELECT id FROM users WHERE username = 'usuario2'")
    usuario2_id = cursor.fetchone()[0]

    role_ids = {}
    for role_name in ['operator', 'remote_driver', 'trucks', 'drones', 'field']:
        cursor.execute("SELECT id FROM roles WHERE name = ?", (role_name,))
        role_ids[role_name] = cursor.fetchone()[0]

    for role in ['operator', 'trucks']:
        cursor.execute('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)',
                       (usuario1_id, role_ids[role]))
    for role in ['field', 'drones']:
        cursor.execute('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)',
                       (usuario2_id, role_ids[role]))

    conn.commit()
    conn.close()
    print("✅ Base de datos inicializada correctamente con usuarios, roles y certificados.")


if __name__ == "__main__":
    initialize_db()
