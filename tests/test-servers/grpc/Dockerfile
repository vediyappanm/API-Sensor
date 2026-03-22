FROM python:3.11-slim
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*
RUN pip install grpcio grpcio-tools grpcio-reflection
COPY server.py /server.py
EXPOSE 50051
CMD ["python3", "/server.py"]
