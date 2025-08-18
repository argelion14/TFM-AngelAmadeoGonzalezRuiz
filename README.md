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





