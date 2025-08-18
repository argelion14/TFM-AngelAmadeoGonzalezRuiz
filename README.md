# Guía de Instalación y Ejecución del Proyecto 🚀

Este documento describe los pasos necesarios para instalar, configurar y ejecutar el proyecto en un entorno local, partiendo del código fuente disponible en GitHub.  

Incluye instrucciones para clonar el repositorio, generar una Autoridad Certificadora (CA) autofirmada, configurar las variables de entorno y levantar la aplicación mediante **Docker Compose**.  

El objetivo es que cualquier persona pueda reproducir el entorno de ejecución de forma **segura** y **controlada**, siguiendo las buenas prácticas recomendadas.  

---

## 1. Instalación desde el repositorio GitHub
El proyecto se encuentra disponible públicamente en:  
👉 [https://github.com/argelion14/TFM-AngelAmadeoGonzalezRuiz](https://github.com/argelion14/TFM-AngelAmadeoGonzalezRuiz)

### Pasos:
1. Clonar el repositorio:
    ```bash
    git clone https://github.com/argelion14/TFM-AngelAmadeoGonzalezRuiz.git
    cd TFM-AngelAmadeoGonzalezRuiz
    ```

2. Verificar que Docker y docker-compose estén instalados:
    ```bash
    docker --version
    docker compose version
    ```

## 2. Generación de la CA autofirmada

Antes de iniciar el sistema, es necesario generar la Autoridad Certificadora (CA) para firmar certificados ECDSA.

1. Generar la clave privada de la CA:
    ```bash
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$CA_KEY"
    ```
*Este comando crea una clave privada de curva elíptica P-256 que actuará como clave raíz de la CA.*

2. Generar el certificado autofirmado de la CA:
    ```bash
    openssl req -new -x509 -key "$CA_KEY" -out "$CA_CERT" -days 3650 -subj "/C=US/ST=CA/O=RTI Demo/CN=ecdsa01 Root CA"
    ```
*Este comando genera un certificado raíz autofirmado válido por 10 años.*

📌 El archivo $CA_CERT debe colocarse en la ruta definida por CA_CERT_PATH y la clave privada en CA_KEY_PATH, según lo indicado en docker-compose.yml.

## 3. Montaje de volúmenes

Es necesario configurar correctamente las rutas de volúmenes para que Docker tenga acceso a los certificados, la base de datos y la configuración.

### En Linux

    ```yaml
    volumes:
    - /ruta/a/certs:/app/appFlask/config/certs
    - /ruta/a/config:/app/appFlask/config
    ```

### En Windows (PowerShell o WSL)

    ```yaml
    volumes:
     - C:/ruta/a/certs:/app/appFlask/config/certs
     - C:/ruta/a/config:/app/appFlask/config
    ```
## 4. Variables de entorno

En el archivo `docker-compose.yml` se definen las siguientes variables de entorno:

|Variable|Descripción|
|---|---|
|`DEBIAN_FRONTEND`|Evita interacción durante instalaciones en modo no interactivo.|
|`PYTHONDONTWRITEBYTECODE`|Si está en `"1"`, evita la creación de `.pyc` y `__pycache__`.|
|`PYTHONUNBUFFERED`|Si está en `"1"`, muestra los logs en tiempo real.|
|`PATH`|Incluye el directorio de binarios locales del usuario.|
|`CA_CERT_PATH`|Ruta donde se almacena la clave pública de la CA.|
|`CA_KEY_PATH`|Ruta donde se almacena la clave privada de la CA.|
|`JWT_EXPIRATION_MINUTES`|Tiempo de expiración del token JWT (en minutos).|
|`DB_PATH`|Ruta de la base de datos SQLite.|
|`NEW_CERT_PATH`|Carpeta donde se guardan los certificados generados para usuarios.|

## 5. Levantar el proyecto con Docker Compose

El repositorio incluye un archivo `docker-compose.yml` listo para su uso.

- Iniciar el servicio:
    
    `docker compose up --build`
    
- Detener los contenedores:
    
    `docker compose down`
    

La aplicación Flask quedará disponible en:  
👉 [http://localhost:5000](http://localhost:5000)

---

## 6. Inicialización automática de la base de datos

Al iniciar por primera vez, la aplicación genera automáticamente un archivo de base de datos (`.db`) en la ruta definida en `DB_PATH`.

La base de datos contiene datos de prueba, incluyendo dos usuarios preconfigurados.

Usuario de interés:

- **Nombre:** `usuario1`
    
- **Contraseña:** `pass1`
    
- **Rol:** Administrador
    

Este usuario permite explorar la aplicación en su totalidad desde el primer inicio.

---

## 7. Seguridad del archivo docker-compose

El archivo `docker-compose.yml` ha sido configurado siguiendo **buenas prácticas de seguridad** recomendadas por:

- Docker Inc.
    
- OWASP
    
- Center for Internet Security (CIS)
    

### Medidas implementadas:

- **Uso de `read_only: false` y `tmpfs`** → Se restringe la escritura en el contenedor.
    
- **Restricción de privilegios** → `cap_drop: - ALL` y `security_opt: - no-new-privileges`.
    
- **Definición explícita de volúmenes** → Solo se mapean rutas necesarias.
    
- **Control de variables de entorno** → Entorno aislado y seguro.
    
- **Exposición mínima de puertos** → Solo el puerto `5000` está expuesto.
    

✅ Estas configuraciones reducen riesgos como ejecución con privilegios de `root`, apertura de puertos innecesarios o fugas de información sensible.



