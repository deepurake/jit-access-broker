FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask requests
COPY broker/ ./broker/
COPY approval_service/ ./approval_service/
EXPOSE 8083
CMD ["python", "-m", "approval_service.app"]
