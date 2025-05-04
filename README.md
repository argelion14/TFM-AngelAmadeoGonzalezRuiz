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

### Resumen 28/04/2025

#### Qué has hecho hasta ahora. Ten preparado una demo si la tienes para ver qué has conseguido resumiendo entradas y salidas de los módulos implementados.




#### Siguientes pasos y fechas. Trae una propuesta y luego discutiremos sobre esto.












### Permissions Document

Un Permissions Document describe, en uno o varios bloques <grant>, qué puede y qué no puede hacer un participante de dominio. Cada <grant> se asocia a la identidad del participante (mediante <subject_name> o <subject_name_expression>), define su periodo de validez y un conjunto de reglas de permitir (<allow_rule>) y denegar (<deny_rule>), así como el comportamiento por defecto (<default>). Dentro de cada regla se especifican dominios (<domains>), acciones (<publish>, <subscribe>, <relay>) y condiciones sobre topics y particiones.

INFO: https://community.rti.com/static/documentation/connext-dds/current/doc/manuals/connext_dds_secure/users_manual/p2_core/access_control.html?utm_source=chatgpt.com

```xml
<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:noNamespaceSchemaLocation="http://community.rti.com/schema/7.3.0/dds_security_permissions.xsd">
  <permissions>
    <!-- Grants for a specific DomainParticipant will be grouped under this tag -->
    <grant name="ParticipantAlice">
      <!-- 1. The rules below will apply to the DomainParticipant
       whose Identity certificate contains this subject name -->
      <subject_name>Alice's X.509 subject (see below)</subject_name>
      <!-- 2. Validity dates for this grant -->
      <validity>
        <!-- Format is CCYY-MM-DDThh:mm:ss[Z|(+|-)hh:mm] in GMT -->
        <not_before>2019-10-31T13:00:00</not_before>
        <not_after>2029-10-31T13:00:00</not_after>
      </validity>

      <!-- 3. Allow this participant to publish the
       PatientMonitoring topic -->
      <allow_rule>
        <domains>
          <id>1</id>
        </domains>
        <publish>
          <topics>
            <topic>Example PatientMonitoring</topic>
          </topics>
        </publish>
      </allow_rule>

      <!-- 4. This participant will not be allowed to publish or
       subscribe to any other topic -->
      <default>DENY</default>
    </grant>
  </permissions>
</dds>
```

```markdown
## Tabla: grants
| Columna             | Tipo     | Descripción                                     |
|---------------------|----------|-------------------------------------------------|
| id                  | INTEGER  | Clave primaria autoincremental                 |
| name                | TEXT     | Nombre del grant (único)                       |
| subject_name        | TEXT     | Nombre del sujeto del certificado              |
| not_before          | TEXT     | Fecha desde la que es válido el grant          |
| not_after           | TEXT     | Fecha hasta la que es válido el grant          |
| default_permission  | TEXT     | Permiso por defecto (por ejemplo, DENY)        |

## Tabla: allow_rules
| Columna    | Tipo     | Descripción                                         |
|------------|----------|-----------------------------------------------------|
| id         | INTEGER  | Clave primaria autoincremental                     |
| grant_id   | INTEGER  | Clave foránea que apunta a `grants(id)`            |
| domain_id  | INTEGER  | ID del dominio donde se aplica la regla            |

## Tabla: topics
| Columna         | Tipo     | Descripción                                                  |
|------------------|----------|--------------------------------------------------------------|
| id               | INTEGER  | Clave primaria autoincremental                              |
| allow_rule_id    | INTEGER  | Clave foránea que apunta a `allow_rules(id)`                |
| topic            | TEXT     | Nombre del tópico permitido                                 |
| action           | TEXT     | Acción permitida (`publish`, `subscribe`, `relay`, etc.)     |
```
