"""The 'test service which requires authentication' -- stands in for a real
protected resource (e.g. prod-db's API). Every request is authorized by
asking a TokenIntrospector whether the bearer token is currently active,
which is what makes broker-side revocation take effect immediately here
rather than only in the broker's own database."""
import os

from flask import Flask, jsonify, request

from protected_service.introspector import HttpIntrospector, TokenIntrospector


def create_app(introspector: TokenIntrospector) -> Flask:
    app = Flask(__name__)

    @app.get("/data")
    def get_data():
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "missing or malformed bearer token"}), 401

        token = auth_header[len("Bearer "):]
        if not introspector.is_active(token):
            return jsonify({"error": "token is invalid, expired, or revoked"}), 401

        return jsonify({"data": "this is the protected payload"}), 200

    return app


if __name__ == "__main__":
    sidecar_url = os.environ["SIDECAR_URL"]
    create_app(HttpIntrospector(sidecar_url)).run(host="0.0.0.0", port=8082)
