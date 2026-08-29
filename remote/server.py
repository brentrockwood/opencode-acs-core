#!/usr/bin/env python3
"""Minimal ACS Guardian and capability-gated resource demonstration."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

ACS_VERSION = "0.1.0"
HKDF_INFO = b"opencode-acs-core/v0.1.0/HMAC-SHA256"
PROTECTED_TOOL = "acs_protected_append"
PROTECTED_ACTION = "append"
PROTECTED_RESOURCE = "remote:acs-demo-log"
METHODS = {
    "steps/sessionStart",
    "steps/sessionEnd",
    "steps/toolCallRequest",
    "steps/toolCallResult",
}

HOST = os.environ.get("ACS_DEMO_HOST", "127.0.0.1")
PORT = int(os.environ.get("ACS_DEMO_PORT", "8788"))
DATABASE = os.environ.get("ACS_DEMO_DATABASE", "/var/lib/opencode-acs-demo/state.sqlite3")
CLIENT_KEY = os.environ["ACS_DEMO_CLIENT_KEY"]
CLIENT_KEY_ID = os.environ["ACS_DEMO_CLIENT_KEY_ID"]
RESOURCE_KEY = base64.urlsafe_b64decode(os.environ["ACS_DEMO_RESOURCE_KEY"] + "===")


class RequestFailure(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def without_signature(envelope: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(json.dumps(envelope))
    if isinstance(value.get("params"), dict):
        value["params"].pop("signature", None)
    if isinstance(value.get("result"), dict):
        value["result"].pop("signature", None)
    return value


def hkdf_session_key(session_id: str) -> bytes:
    prk = hmac.new(session_id.encode(), CLIENT_KEY.encode(), hashlib.sha256).digest()
    return hmac.new(prk, HKDF_INFO + b"\x01", hashlib.sha256).digest()


def envelope_signature(envelope: dict[str, Any], key: bytes) -> str:
    return base64.b64encode(hmac.new(key, canonical(without_signature(envelope)), hashlib.sha256).digest()).decode()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE, timeout=5, isolation_level=None)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    os.makedirs(os.path.dirname(DATABASE), mode=0o700, exist_ok=True)
    with connect() as database:
        database.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS acs_requests (
                request_id TEXT PRIMARY KEY,
                method TEXT NOT NULL,
                decision TEXT NOT NULL,
                recorded_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS consumed_capabilities (
                capability_id TEXT PRIMARY KEY,
                consumed_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS protected_events (
                event_id TEXT PRIMARY KEY,
                capability_id TEXT NOT NULL UNIQUE,
                acs_request_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                value TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )


def argument(payload: dict[str, Any], name: str) -> Any:
    item = payload.get("arguments", {}).get(name)
    return item.get("value") if isinstance(item, dict) else None


def issue_capability(decision: str, request: dict[str, Any], value: str, now: int) -> tuple[str, int]:
    if decision != "allow":
        raise RequestFailure(500, "capability issuance requires ALLOW")
    params = request["params"]
    expires = now + 30
    claims = {
        "version": 1,
        "capability_id": str(uuid.uuid4()),
        "acs_request_id": params["request_id"],
        "subject": params["metadata"]["session_id"],
        "action": PROTECTED_ACTION,
        "resource": PROTECTED_RESOURCE,
        "value_sha256": hashlib.sha256(value.encode()).hexdigest(),
        "issued_at": now,
        "expires_at": expires,
    }
    payload = b64url(canonical(claims))
    signature = b64url(hmac.new(RESOURCE_KEY, payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{signature}", expires


def validate_acs_request(request: dict[str, Any]) -> bytes:
    if request.get("jsonrpc") != "2.0" or not isinstance(request.get("id"), str):
        raise RequestFailure(400, "invalid JSON-RPC envelope")
    params = request.get("params")
    if not isinstance(params, dict) or params.get("acs_version") != ACS_VERSION:
        raise RequestFailure(400, "invalid ACS parameters")
    try:
        uuid.UUID(params["request_id"])
        uuid.UUID(params["metadata"]["session_id"])
        timestamp = datetime.fromisoformat(params["timestamp"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as error:
        raise RequestFailure(400, "invalid request correlation") from error
    if abs((datetime.now(timezone.utc) - timestamp).total_seconds()) > 120:
        raise RequestFailure(401, "request timestamp is outside the freshness window")
    signature = params.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "HMAC-SHA256" or signature.get("key_id") != CLIENT_KEY_ID:
        raise RequestFailure(401, "request signature is missing or invalid")
    key = hkdf_session_key(params["metadata"]["session_id"])
    supplied = signature.get("value")
    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, envelope_signature(request, key)):
        raise RequestFailure(401, "request signature is missing or invalid")
    return key


def decide(request: dict[str, Any]) -> dict[str, Any]:
    method = request["method"]
    payload = request["params"].get("payload", {})
    if method == "handshake/hello":
        offered = payload.get("methods_implemented", [])
        return {
            "decision": "allow",
            "payload": {
                "negotiated_version": ACS_VERSION,
                "methods_evaluated": [method for method in offered if method in METHODS],
                "selected_transport": "https",
                "signature_algorithms_supported": ["HMAC-SHA256"],
                "timeout_config": {"default_ms": 2000},
                "on_decision_failure": "deny",
                "policy_requires_provenance": False,
                "profiles_accepted": [],
            },
        }
    if method not in METHODS:
        return {"decision": "deny", "reasoning": "method is outside the demo policy"}
    if method != "steps/toolCallRequest":
        return {"decision": "allow"}
    tool = payload.get("tool", {}).get("name")
    if tool != PROTECTED_TOOL:
        return {"decision": "deny", "reasoning": "only the protected demonstration tool is enrolled"}
    value = argument(payload, "value")
    if not isinstance(value, str) or not value or len(value.encode()) > 512:
        return {"decision": "deny", "reasoning": "protected value is invalid"}
    if "deny" in value.lower():
        return {"decision": "deny", "reasoning": "demo policy denied the requested value"}
    token, expires = issue_capability("allow", request, value, int(time.time()))
    return {"decision": "allow", "payload": {"capability": token, "expires_at": expires}}


def record_request(request_id: str, method: str, decision: str) -> None:
    try:
        with connect() as database:
            database.execute(
                "INSERT INTO acs_requests(request_id, method, decision, recorded_at) VALUES (?, ?, ?, ?)",
                (request_id, method, decision, int(time.time())),
            )
    except sqlite3.IntegrityError as error:
        raise RequestFailure(409, "ACS request has already been processed") from error


def handle_acs(request: dict[str, Any]) -> dict[str, Any]:
    key = validate_acs_request(request)
    selected = decide(request)
    record_request(request["params"]["request_id"], request["method"], selected["decision"])
    result = {
        "type": "final",
        "acs_version": ACS_VERSION,
        "request_id": request["params"]["request_id"],
        **selected,
    }
    response = {"jsonrpc": "2.0", "id": request["id"], "result": result}
    result["signature"] = {
        "algorithm": "HMAC-SHA256",
        "value": envelope_signature(response, key),
        "key_id": CLIENT_KEY_ID,
    }
    return response


def validate_capability(token: str, value: str, now: int) -> dict[str, Any]:
    try:
        payload, supplied = token.split(".")
        wanted = hmac.new(RESOURCE_KEY, payload.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(unb64url(supplied), wanted):
            raise ValueError("signature")
        claims = json.loads(unb64url(payload))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise RequestFailure(401, "capability is invalid") from error
    required = {"capability_id", "acs_request_id", "subject", "action", "resource", "value_sha256", "issued_at", "expires_at"}
    if claims.get("version") != 1 or not required.issubset(claims):
        raise RequestFailure(401, "capability is invalid")
    if claims["issued_at"] > now + 5 or claims["expires_at"] < now:
        raise RequestFailure(401, "capability is expired or not yet valid")
    if claims["action"] != PROTECTED_ACTION or claims["resource"] != PROTECTED_RESOURCE:
        raise RequestFailure(403, "capability is not bound to this resource")
    if not hmac.compare_digest(claims["value_sha256"], hashlib.sha256(value.encode()).hexdigest()):
        raise RequestFailure(403, "capability is not bound to this value")
    return claims


def consume_capability(token: str, value: str) -> str:
    now = int(time.time())
    claims = validate_capability(token, value, now)
    event_id = str(uuid.uuid4())
    database = connect()
    try:
        database.execute("BEGIN IMMEDIATE")
        database.execute(
            "INSERT INTO consumed_capabilities(capability_id, consumed_at) VALUES (?, ?)",
            (claims["capability_id"], now),
        )
        database.execute(
            "INSERT INTO protected_events(event_id, capability_id, acs_request_id, subject, value, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (event_id, claims["capability_id"], claims["acs_request_id"], claims["subject"], value, now),
        )
        database.execute("COMMIT")
    except sqlite3.IntegrityError as error:
        database.execute("ROLLBACK")
        raise RequestFailure(409, "capability has already been used") from error
    finally:
        database.close()
    return event_id


class Handler(BaseHTTPRequestHandler):
    server_version = "OpenCodeACSProtectedDemo/0.1"

    def log_message(self, format: str, *args: Any) -> None:
        print(f"{self.address_string()} {format % args}", flush=True)

    def json_response(self, status: int, value: dict[str, Any]) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.send_header("x-content-type-options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.json_response(200, {"status": "ok", "service": "opencode-acs-protected-demo"})
        else:
            self.json_response(404, {"error": "not found"})

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("content-length", "0"))
            if length < 1 or length > 1_048_576:
                raise RequestFailure(413, "request size is invalid")
            try:
                request = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise RequestFailure(400, "request is not valid JSON") from error
            if not isinstance(request, dict):
                raise RequestFailure(400, "request must be an object")
            if self.path.rstrip("/") == "/acs":
                self.json_response(200, handle_acs(request))
                return
            if self.path.rstrip("/") == "/protected":
                token = request.get("capability")
                value = request.get("value")
                if not isinstance(token, str) or not isinstance(value, str):
                    raise RequestFailure(401, "a capability and value are required")
                event_id = consume_capability(token, value)
                self.json_response(201, {"status": "appended", "event_id": event_id})
                return
            raise RequestFailure(404, "not found")
        except RequestFailure as error:
            self.json_response(error.status, {"error": str(error)})
        except Exception:
            self.json_response(500, {"error": "internal error"})


if __name__ == "__main__":
    initialize_database()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"listening on http://{HOST}:{PORT}", flush=True)
    server.serve_forever()
