# Guía de uso del contenedor `tfm-agent`

Este contenedor implementa un agente que se comunica con la API definida en el TFM y permite ejecutar pruebas sobre un entorno basado en **RTI Connext DDS**.
El despliegue se realiza con **Docker Compose** para simplificar la configuración.

---

## 📦 Requisitos previos

- Docker instalado en el sistema.

- Docker Compose disponible.

- Repositorio clonado con los siguientes ficheros:


`📦 proyecto/  ┣ 📜 Dockerfile  ┣ 📜 docker-compose.yml  ┣ 📜 requirements.txt  ┣ 📜 agent_loop.py  ┗ 📂 output/`

---

## ⚙️ Descripción de ficheros

- **`docker-compose.yml`** → Orquesta la ejecución del contenedor `tfm-agent`, define volúmenes, variables de entorno y la política de reinicio.

- **`Dockerfile`** → Define cómo se construye la imagen del agente (instalación de dependencias y configuración del entorno de ejecución).

- **`requirements.txt`** → Contiene la lista de dependencias Python necesarias para ejecutar el agente.

- **`agent_loop.py`** → Script principal del agente, encargado de ejecutar el ciclo de trabajo.

- **`output/`** → Carpeta local donde se almacenan los resultados generados por el agente.


---

## ▶️ Ejecución del agente

1. **Construir y arrancar** el servicio:

    `docker-compose up --build -d`

2. **Comprobar que está en ejecución**:

    `docker ps`

3. **Ver logs en tiempo real**:

    `docker logs -f tfm-agent`


---

## ⏹️ Detener el agente

Para detener y eliminar el contenedor:

`docker-compose down`

---

## 🛠️ Personalización

- Modifica la sección de **volúmenes** en `docker-compose.yml` si quieres cambiar la ruta local de salida.

- Ajusta las **variables de entorno** (`API_BASE`, `AUTH_HEADER`, `ROLE_ID`, `EXP_MINUTES`) en `docker-compose.yml` para cambiar el comportamiento del agente.

- En sistemas Linux/Mac, adapta las rutas de volúmenes (ejemplo: `/d/...` es propio de Windows con Docker Desktop).