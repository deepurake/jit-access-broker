FROM python:3.12-slim
WORKDIR /app
# Installed from requirements.txt (not a hand-picked subset) because this
# image also runs `python -m broker.cli` for the compose `sweeper` service,
# and broker.cli imports pyyaml (acl_loader) and anthropic (triage).
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY broker/ ./broker/
COPY approval_service/ ./approval_service/
EXPOSE 8083
CMD ["python", "-m", "approval_service.app"]
