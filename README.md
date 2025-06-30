# TFM-AngelAmadeoGonzalezRuiz

Repository to store all the code related to my TFM

Para crear el entorno virtual

```bash
python3 -m venv venv
```

```bash
source venv/bin/activate
```

Salir del entorno virtual

```bash
deactivate
```

Eliminar el entorno virtual

```bash
rm -rf venv
```

Listar los paquetes que tengo en el entorno virtual:

```bash
pip list
```

## En docker

```bash
docker build -t jwt-flask-app .
```

```bash
docker run --name jwt-flask-app -p 5000:5000 -d jwt-flask-app
```

```bash
docker exec -it jwt-flask-app bash
```

## En docker-compose

```bash
docker-compose up
```

## Uso de la aplicación

```bash
curl -X POST http://127.0.0.1:5000/login -H "Content-Type: application/json" -d '{"username": "usuario", "password": "password"}'
```

```bash
curl -X GET http://127.0.0.1:5000/protected -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzdWFyaW8iLCJleHAiOjE3MzY1MTc1Njh9.BeKYJSQ_r0CoLB1ZVLr786K364nY5ucgWu4IOImJFfg"
```

---


### Permissions Document

Un Permissions Document describe, en uno o varios bloques <grant>, qué puede y qué no puede hacer un participante de dominio. Cada <grant> se asocia a la identidad del participante (mediante <subject_name> o <subject_name_expression>), define su periodo de validez y un conjunto de reglas de permitir (<allow_rule>) y denegar (<deny_rule>), así como el comportamiento por defecto (<default>). Dentro de cada regla se especifican dominios (<domains>), acciones (<publish>, <subscribe>, <relay>) y condiciones sobre topics y particiones.

INFO: https://community.rti.com/static/documentation/connext-dds/current/doc/manuals/connext_dds_secure/users_manual/p2_core/access_control.html

```bash
curl -X POST http://127.0.0.1:5000/auth \
    -H "Content-Type: application/json" \
    -d '{"subject_name": "CN=ArGeL,O=Cyber,OU=Admins", "domain_id": 0}'
```


```bash
curl -X POST http://127.0.0.1:5000/verify \
    -H "Content-Type: application/json" \
    -d '{"token": "TOKEN_AQUI"}'
```

# Sistema de Control de Acceso Basado en DDS

Este repositorio contiene el desarrollo del Trabajo Fin de Máster (TFM) basado en el middleware **RTI Connext DDS**, centrado en la implementación de un sistema de control de acceso distribuido utilizando políticas de permisos y temas (topics) definidos con el estándar **DDS Security**.

## 📌 Objetivos

- Aplicar el modelo DDS para el control de acceso basado en roles (RBAC).
- Configurar documentos `governance.xml` y `permissions.xml` siguiendo la especificación DDS Security 1.1.
- Demostrar un sistema de comunicación segura entre entidades (por ejemplo, drones, estaciones base, vehículos, etc.).

## ⚙️ Tecnologías

- **RTI Connext DDS Professional** (licencia académica)
- **Python / C++** (dependiendo de tu implementación)
- **OpenSSL** (para generación de certificados)
- **Docker** (opcional para despliegue de nodos)

## 📁 Estructura

├── permissions/
│ ├── governance.xml
│ ├── permissions.xml
│ └── certificados/
├── src/
│ ├── publicador.py
│ ├── suscriptor.py
├── doc/
│ └── memoria_tfm.pdf
├── LICENSE
└── README.md


## 🛡️ Licencia

Este proyecto se distribuye bajo la licencia MIT. Puedes usar, modificar y redistribuir este trabajo libremente con fines académicos y de investigación.
Consulta el archivo [LICENSE](LICENSE) para más detalles.

> ⚠️ **Nota importante:** Este trabajo utiliza **RTI Connext DDS Professional** bajo una licencia académica gratuita proporcionada por Real-Time Innovations, Inc.
> No se incluye ni redistribuye ningún binario, librería ni código fuente propietario de RTI.

## 🧪 Créditos

Autor: [Ángel Amadeo González Ruiz](https://github.com/argelion14)
Universidad: [UGR](https://www.ugr.es/)
Máster: [Master propio de ciberseguridad]
Curso: [2025]

---
