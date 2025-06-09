import sqlite3

def create_tables():
    conn = sqlite3.connect('roles.db')
    cursor = conn.cursor()

    # Crear tabla roles
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT
        )
    ''')

    # Crear tabla usuarios
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            cert TEXT
        )
    ''')

    # Tabla intermedia para la relación muchos a muchos usuarios-roles
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_roles (
            user_id INTEGER,
            role_id INTEGER,
            PRIMARY KEY (user_id, role_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (role_id) REFERENCES roles(id)
        )
    ''')

    # Insertar datos en roles
    roles = [
        ('operator', 'Role operator: Domains 1-3, Topics: telemetry, Subscribe'),
        ('remote_driver', 'Remote driver: Truck publish'),
        ('trucks', 'Trucks (3): Topics: Telemetry, Remote Control'),
        ('drones', 'Drones (1): Topics: Telemetry, Video feed'),
        ('field', 'Field (2): Telemetry')
    ]

    for role in roles:
        cursor.execute('INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)', role)

    # Insertar usuarios de ejemplo
    users = [
        ('usuario1', 'pass1', 'C=US, ST=CA, O=Real Time Innovations, emailAddress=ecdsa01Peer01@rti.com, CN=RTI ECDSA01 (p256) PEER01'),
        ('usuario2', 'pass2', 'C=ES, ST=Madrid, O=Mi EmpresaF, emailAddress=usuario2@miempresa.com, CN=Certificado Usuario2')
    ]

    for user in users:
        cursor.execute('INSERT OR IGNORE INTO users (username, password, cert) VALUES (?, ?, ?)', user)

    # Asociar roles a usuarios (ejemplo)
    # Primero obtén los IDs
    cursor.execute("SELECT id FROM users WHERE username = 'usuario1'")
    usuario1_id = cursor.fetchone()[0]
    cursor.execute("SELECT id FROM users WHERE username = 'usuario2'")
    usuario2_id = cursor.fetchone()[0]

    cursor.execute("SELECT id FROM roles WHERE name = 'operator'")
    operator_role_id = cursor.fetchone()[0]
    cursor.execute("SELECT id FROM roles WHERE name = 'remote_driver'")
    remote_driver_role_id = cursor.fetchone()[0]

    # usuario1 es operator
    cursor.execute('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)', (usuario1_id, operator_role_id))
    # usuario2 es remote_driver
    cursor.execute('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)', (usuario2_id, remote_driver_role_id))

    conn.commit()
    conn.close()

if __name__ == "__main__":
    create_tables()
    print("Tablas y datos creados correctamente.")
