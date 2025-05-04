# Usa una imagen base de Python
FROM python:3.13-slim

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Copia los archivos necesarios
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copia el código de la aplicación
COPY appFlask ./

# Exponer el puerto en el que correrá la aplicación Flask
EXPOSE 5000

# Comando para iniciar la aplicación
CMD ["python", "testToken.py"]
