FROM python:3.11-slim
RUN pip install websockets && apt-get update && apt-get install -y openssl
COPY server.py /server.py
EXPOSE 8445
CMD ["python3", "/server.py"]
