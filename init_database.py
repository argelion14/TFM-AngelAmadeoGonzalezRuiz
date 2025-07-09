import sqlite3
import bcrypt
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# TODO Mejorar donde se guardan las claves privadas y certificados
def generate_cert_and_key(common_name):
    # Generar clave privada EC
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Generar certificado autofirmado (simulación si no hay CA)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mi Empresa"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, f"{common_name}@miempresa.com"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    # Serializar certificado y clave
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    # Guardar clave en archivo opcionalmente
    key_path = f"private_keys/{common_name}.key"
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    with open(key_path, "w") as key_file:
        key_file.write(key_pem)

    return cert_pem, key_path


def create_tables():
    conn = sqlite3.connect('TFM.db')
    conn.execute('PRAGMA foreign_keys = ON')
    cursor = conn.cursor()

    # --- TABLAS PRINCIPALES ---

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
            user_id INTEGER NOT NULL,
            public_cert TEXT NOT NULL,  -- Certificado firmado por la CA (en PEM)
            private_key_path TEXT,      -- (Opcional) Ruta al archivo .key
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
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
        CREATE TABLE IF NOT EXISTS grantTemplate (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            default_action TEXT CHECK(default_action IN ('ALLOW', 'DENY'))
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

    # --- TABLA DE REGLAS (sin description) ---
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

    # --- DATOS DE EJEMPLO ---

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

    users = [
        ('usuario1', 'pass1', 'usuario1', 1),
        ('usuario2', 'pass2', 'usuario2', 0)
    ]

    for username, password_plain, cn, is_superuser in users:
        cert_pem, key_path = generate_cert_and_key(cn)
        hashed_password = bcrypt.hashpw(password_plain.encode('utf-8'), bcrypt.gensalt())
        cursor.execute(
            'INSERT OR IGNORE INTO users (username, password, cert, is_superuser) VALUES (?, ?, ?, ?)',
            (username, hashed_password.decode('utf-8'), cn, is_superuser)
        )
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_id = cursor.fetchone()[0]
        cursor.execute(
            'INSERT INTO user_keys (user_id, public_cert, private_key_path) VALUES (?, ?, ?)',
            (user_id, cert_pem, key_path)
        )

    # Asignación de roles
    cursor.execute("SELECT id FROM users WHERE username = 'usuario1'")
    usuario1_id = cursor.fetchone()[0]
    cursor.execute("SELECT id FROM users WHERE username = 'usuario2'")
    usuario2_id = cursor.fetchone()[0]

    role_ids = {}
    for role_name in ['operator', 'remote_driver', 'trucks', 'drones', 'field']:
        cursor.execute("SELECT id FROM roles WHERE name = ?", (role_name,))
        role_ids[role_name] = cursor.fetchone()[0]

    usuario1_roles = ['operator', 'trucks']
    usuario2_roles = ['field', 'drones']

    for role in usuario1_roles:
        cursor.execute(
            'INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)',
            (usuario1_id, role_ids[role])
        )
    for role in usuario2_roles:
        cursor.execute(
            'INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)',
            (usuario2_id, role_ids[role])
        )

    conn.commit()
    conn.close()
    print("Base de datos creada correctamente con usuarios y certificados")


if __name__ == "__main__":
    create_tables()