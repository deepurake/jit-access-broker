import os
import threading
import time
from dataclasses import dataclass

import pytest
import requests
from werkzeug.serving import make_server

from approval_service.app import create_app as create_approval_app
from broker.broker import Broker
from broker.clock import FakeClock, SystemClock
from broker.db import Database
from broker.http_connector import HttpResourceConnector
from broker.models import PolicyDecision, PolicyDecisionType
from broker.policy import PolicyEngine
from protected_service.app import create_app as create_protected_app
from protected_service.introspector import HttpIntrospector
from sidecar.app import create_app as create_sidecar_app


class RouteToHumanPolicy(PolicyEngine):
    """Every request needs a reviewer. Lets the integration tests exercise
    the magic-link leg without depending on ACL/triage configuration."""

    def decide(self, requester, resource, access_level, duration_seconds, reason):
        return PolicyDecision(PolicyDecisionType.ROUTE_HUMAN, "needs a human")


@dataclass
class ApprovalHarness:
    """What a test needs to drive the human-review leg end to end: the URL
    of a live approval web app, and a Broker over the SAME Database that web
    app reads, so a pending approval created through `broker` is the one the
    reviewer's link resolves."""

    url: str
    broker: Broker


class _LazyApp:
    """WSGI shim that builds the real app on the first request, i.e. inside
    the serving thread. sqlite3 connections refuse cross-thread use and
    Database opens one at construction, so a web app over a Database must
    have that Database born in the (single) thread that serves requests."""

    def __init__(self, factory):
        self._factory = factory
        self._app = None

    def __call__(self, environ, start_response):
        if self._app is None:
            self._app = self._factory()
        return self._app(environ, start_response)


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


@pytest.fixture
def approval_service_url(tmp_path, sidecar_url):
    """Dual-mode like the others, but yields an ApprovalHarness rather than a
    bare URL because the test must create its pending approval in the very
    Database the web app reads.

    Env mode (APPROVAL_SERVICE_URL + BROKER_DB set, i.e. inside the compose
    test-runner): BROKER_DB is the SQLite file the approval-service container
    opens via the shared broker-data volume; opening it here gives us a
    second connection to the same state. The real clock is used because the
    remote service uses SystemClock -- a FakeClock-dated pending approval
    would be past its deadline the moment the service looked at it.

    In-thread mode: the same shape in miniature -- the test's Broker and the
    web app's Broker each open their own connection to one SQLite file under
    tmp_path (sqlite3 connections are thread-bound, so they can't share
    one), and share a single FakeClock so time stays under the test's control.

    Readiness is probed with a token that can't exist: the 404 is still an
    HTTP answer, which is all _wait_until_ready needs."""
    env_url = os.environ.get("APPROVAL_SERVICE_URL")
    if env_url:
        broker = Broker(
            db=Database(os.environ["BROKER_DB"]),
            policy=RouteToHumanPolicy(),
            connector=HttpResourceConnector(sidecar_url),
            clock=SystemClock(),
        )
        _wait_until_ready(f"{env_url}/approve/readiness-check")
        yield ApprovalHarness(url=env_url, broker=broker)
        return

    db_path = str(tmp_path / "approval.db")
    clock = FakeClock()

    def make_broker():
        return Broker(
            db=Database(db_path),
            policy=RouteToHumanPolicy(),
            connector=HttpResourceConnector(sidecar_url),
            clock=clock,
        )

    broker = make_broker()
    port, server, thread = _run_in_thread(_LazyApp(lambda: create_approval_app(make_broker())))
    url = f"http://127.0.0.1:{port}"
    try:
        _wait_until_ready(f"{url}/approve/readiness-check")
        yield ApprovalHarness(url=url, broker=broker)
    finally:
        server.shutdown()
        thread.join(timeout=5)
