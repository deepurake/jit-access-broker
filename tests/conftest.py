import os
import threading
import time

import pytest
import requests
from werkzeug.serving import make_server

from protected_service.app import create_app as create_protected_app
from protected_service.introspector import HttpIntrospector
from sidecar.app import create_app as create_sidecar_app


def _run_in_thread(app):
    server = make_server("127.0.0.1", 0, app)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return port, server, thread


def _wait_until_ready(url: str, timeout: float = 10.0) -> None:
    """Polls until the service answers, or raises. Needed because under
    docker-compose the sibling container may still be starting; under the
    in-thread fixtures it's a no-op that succeeds on the first try."""
    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            requests.get(url, timeout=1)
            return
        except requests.exceptions.RequestException as exc:
            last_exc = exc
            time.sleep(0.2)
    raise RuntimeError(f"service at {url} did not become ready within {timeout}s") from last_exc


@pytest.fixture
def sidecar_url():
    """Points at a live sidecar. If SIDECAR_URL is set (docker-compose
    running this fixture inside the test-runner container), use that real
    service; otherwise spin up a real instance in a background thread so
    the same tests also run under plain pytest with no docker required."""
    env_url = os.environ.get("SIDECAR_URL")
    if env_url:
        _wait_until_ready(f"{env_url}/introspect/readiness-check")
        yield env_url
        return

    port, server, thread = _run_in_thread(create_sidecar_app())
    url = f"http://127.0.0.1:{port}"
    try:
        _wait_until_ready(f"{url}/introspect/readiness-check")
        yield url
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture
def protected_service_url(sidecar_url):
    """Same dual-mode pattern as sidecar_url."""
    env_url = os.environ.get("PROTECTED_SERVICE_URL")
    if env_url:
        _wait_until_ready(f"{env_url}/data")
        yield env_url
        return

    app = create_protected_app(HttpIntrospector(sidecar_url))
    port, server, thread = _run_in_thread(app)
    url = f"http://127.0.0.1:{port}"
    try:
        _wait_until_ready(f"{url}/data")
        yield url
    finally:
        server.shutdown()
        thread.join(timeout=5)
