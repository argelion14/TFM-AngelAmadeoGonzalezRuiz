import sqlite3

# Conexión a la base de datos (se creará si no existe)
conn = sqlite3.connect('permisos.db')
cursor = conn.cursor()

# Crear tablas
cursor.executescript('''
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS topics;
DROP TABLE IF EXISTS domains;
DROP TABLE IF EXISTS rules;
DROP TABLE IF EXISTS grants;
DROP TABLE IF EXISTS subjects;

CREATE TABLE subjects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_name TEXT UNIQUE NOT NULL,
    description TEXT
);

CREATE TABLE grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id INTEGER NOT NULL,
    grant_name TEXT NOT NULL,
    validity_start TEXT,
    validity_end TEXT,
    default_action TEXT CHECK (default_action IN ('ALLOW', 'DENY')) NOT NULL,
    FOREIGN KEY (subject_id) REFERENCES subjects(id)
);

CREATE TABLE rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_id INTEGER NOT NULL,
    rule_type TEXT CHECK (rule_type IN ('ALLOW', 'DENY')) NOT NULL,
    FOREIGN KEY (grant_id) REFERENCES grants(id)
);

CREATE TABLE domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    domain_id INTEGER,
    FOREIGN KEY (rule_id) REFERENCES rules(id)
);

CREATE TABLE topics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    topic_name TEXT,
    FOREIGN KEY (rule_id) REFERENCES rules(id)
);

CREATE TABLE permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    permission_type TEXT CHECK (permission_type IN ('publish', 'subscribe', 'relay', 'partition')) NOT NULL,
    allow INTEGER NOT NULL CHECK (allow IN (0,1)),
    FOREIGN KEY (rule_id) REFERENCES rules(id)
);
''')

# Insertar datos de ejemplo
cursor.executescript('''
INSERT INTO subjects (subject_name, description) VALUES 
('CN=operador1,O=empresa', 'Operador de drones'),
('CN=visualizador,O=empresa', 'Visualizador de datos'),
('CN=admin,O=empresa', 'Administrador');

INSERT INTO grants (subject_id, grant_name, validity_start, validity_end, default_action) VALUES
(1, 'operador_grant', '2024-01-01', '2026-01-01', 'DENY'),
(2, 'visualizador_grant', '2024-01-01', '2026-01-01', 'DENY'),
(3, 'admin_grant', NULL, NULL, 'ALLOW');

INSERT INTO rules (grant_id, rule_type) VALUES
(1, 'ALLOW'),
(2, 'ALLOW'),
(3, 'ALLOW');

INSERT INTO domains (rule_id, domain_id) VALUES
(1, 0),
(2, 0),
(3, NULL);

INSERT INTO topics (rule_id, topic_name) VALUES
(1, 'DronesData'),
(2, 'DronesData'),
(3, '*');

INSERT INTO permissions (rule_id, permission_type, allow) VALUES
(1, 'publish', 1),
(2, 'subscribe', 1),
(3, 'publish', 1),
(3, 'subscribe', 1),
(3, 'relay', 1);
''')

# Confirmar cambios y cerrar conexión
conn.commit()
conn.close()

print("✅ Base de datos 'permisos.db' creada con datos de ejemplo.")
