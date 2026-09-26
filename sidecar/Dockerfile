FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask
COPY sidecar/ ./sidecar/
EXPOSE 8081
CMD ["python", "-m", "sidecar.app"]
