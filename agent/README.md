# Guía de uso del contenedor `tfm-agent`

Este contenedor implementa un agente que se comunica con la API definida en el TFM y permite ejecutar pruebas sobre un entorno basado en **RTI Connext DDS**.
El despliegue se realiza con **Docker Compose** para simplificar la configuración.

---

## Requisitos previos

1. Tener **Docker** instalado en el sistema.

2. Tener **Docker Compose** disponible.

3. Clonar el repositorio con la siguiente estructura:


`proyecto/  ┣ Dockerfile  ┣ docker-compose.yml  ┣ requirements.txt  ┣ agent_loop.py  ┗ output/`

---

## Descripción de ficheros

- **docker-compose.yml**: orquesta la ejecución del contenedor `tfm-agent`, define volúmenes, variables de entorno y la política de reinicio.

- **Dockerfile**: define cómo se construye la imagen del agente (instalación de dependencias y configuración del entorno).

- **requirements.txt**: lista de dependencias Python necesarias para ejecutar el agente.

- **agent_loop.py**: script principal del agente, encargado de ejecutar el ciclo de trabajo.

- **output/**: carpeta local donde se almacenan los resultados generados por el agente.


---

## Variables de entorno importantes

Para que el agente funcione correctamente, es necesario configurar las siguientes variables de entorno en `docker-compose.yml`:

- **`API_BASE`**: URL base de la API con la que se va a comunicar el agente.

- **`AUTH_HEADER`**: token JWT del usuario que va a ejecutar el agente. Este token debe:

    1. Ser válido y no estar vencido.

    2. Tener permisos para el **rol** que se indica en `ROLE_ID`.


    > En este ejemplo se ha incluido un **token vencido** únicamente a modo de referencia.

- **`ROLE_ID`**: identificador del rol requerido para ejecutar el agente. En este ejemplo se usa `1`.

- **`EXP_MINUTES`**: duración en minutos del ciclo de ejecución antes de que el agente considere expirada la sesión.


---

## Ejecución del agente

1. Construir y arrancar el servicio:

    `docker-compose up --build -d`

2. Comprobar que el contenedor está en ejecución:

    `docker ps`

3. Ver logs en tiempo real:

    `docker logs -f tfm-agent`


> Si el token JWT no es válido o no tiene permisos para el rol indicado, el agente no podrá ejecutar correctamente las acciones sobre la API.

---

## Detener el agente

Para detener y eliminar el contenedor:

`docker-compose down`

---

## Personalización

1. Modificar la sección de **volúmenes** en `docker-compose.yml` si se quiere cambiar la ruta local de salida.

2. Ajustar las **variables de entorno** (`API_BASE`, `AUTH_HEADER`, `ROLE_ID`, `EXP_MINUTES`) en `docker-compose.yml` para cambiar el comportamiento del agente.

3. En sistemas Linux o Mac, adaptar las rutas de volúmenes (ejemplo: `/d/...` es propio de Windows con Docker Desktop).