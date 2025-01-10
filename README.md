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
docker run --name jwt-flask-app -d jwt-flask-app
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
