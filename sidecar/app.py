"""Fake Okta sidecar: stands in for a real identity provider's token
issuance/introspection/revocation API. HttpResourceConnector (broker side)
and the protected test service (resource side) both talk to this over HTTP,
so the broker's ResourceConnector seam is proven against a real network
boundary instead of just an in-process mock.

State is in-memory and per-process by design: this is a test double, not a
production identity store. Each create_app() call gets its own isolated
token store (see broker/db.py's Database for the pattern this deliberately
does NOT need: this service is stateless across restarts on purpose)."""
import secrets

from flask import Flask, jsonify, request


def create_app() -> Flask:
    app = Flask(__name__)
    tokens = {}  # token -> {"resource": str, "access_level": str, "active": bool}

    @app.post("/grants")
    def issue_grant():
        body = request.get_json()
        token = secrets.token_hex(16)
        tokens[token] = {
            "resource": body["resource"],
            "access_level": body["access_level"],
            "active": True,
        }
        return jsonify({"token": token}), 201

    @app.get("/introspect/<token>")
    def introspect(token):
        record = tokens.get(token)
        if record is None or not record["active"]:
            return jsonify({"active": False}), 200
        return jsonify({
            "active": True,
            "resource": record["resource"],
            "access_level": record["access_level"],
        }), 200

    @app.post("/grants/<token>/revoke")
    def revoke_grant(token):
        record = tokens.get(token)
        if record is None or not record["active"]:
            return jsonify({"revoked": False}), 200
        record["active"] = False
        return jsonify({"revoked": True}), 200

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8081)
