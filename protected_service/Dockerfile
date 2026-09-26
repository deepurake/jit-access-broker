FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask requests
COPY protected_service/ ./protected_service/
EXPOSE 8082
CMD ["python", "-m", "protected_service.app"]
