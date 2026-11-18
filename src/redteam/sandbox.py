"""In-process sandbox that runs the target app and only accepts path-based probes."""

from __future__ import annotations

import importlib.util
import secrets
import shutil
import sys
import tempfile
import unicodedata
import uuid
from pathlib import Path
from types import ModuleType
from typing import Any

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from redteam.models import Probe, ProbeResult

ATTACKER_TOKEN = "mallory-token"
ALICE_TOKEN = "alice-token"
SEED_SOURCE_PATH = Path(__file__).parent / "target" / "vulnerable_app.py"
ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
BASE_URL = "http://target.sandbox"


class ProbeRejected(ValueError):
    """Raised when a probe falls outside the sandbox safety boundary."""


class TargetLoadError(RuntimeError):
    """Raised when a target source cannot be imported or does not build an app."""


def load_seed_source() -> str:
    """Return the source text of the seed target app."""
    return SEED_SOURCE_PATH.read_text(encoding="utf-8")


def validate_probe(probe: Probe) -> None:
    """Reject any probe that is not a plain path against the in-process app."""
    method = probe.method.upper()
    if method not in ALLOWED_METHODS:
        raise ProbeRejected(f"method not allowed: {probe.method!r}")
    if not probe.path.startswith("/"):
        raise ProbeRejected(f"path must start with '/': {probe.path!r}")
    if probe.path.startswith("//"):
        raise ProbeRejected(f"protocol-relative path rejected: {probe.path!r}")
    if "://" in probe.path:
        raise ProbeRejected(f"absolute URL rejected: {probe.path!r}")
    if any(ch.isspace() or unicodedata.category(ch) == "Cc" for ch in probe.path):
        raise ProbeRejected(f"path contains whitespace or control characters: {probe.path!r}")
    if any(name.lower() == "host" for name in probe.headers):
        raise ProbeRejected("explicit Host header rejected")


class Sandbox:
    """Holds one running copy of the target app plus its data directory.

    Requests go through a Starlette TestClient, so nothing leaves the process.
    """

    def __init__(
        self,
        source: str | None = None,
        *,
        workdir: str | Path | None = None,
        canary: str | None = None,
    ) -> None:
        self._owns_workdir = workdir is None
        if workdir is None:
            self.workdir = Path(tempfile.mkdtemp(prefix="redteam-"))
        else:
            self.workdir = Path(workdir)
            self.workdir.mkdir(parents=True, exist_ok=True)

        self.canary = canary or f"CANARY-{secrets.token_hex(8)}"
        self.data_dir = self.workdir / "data"
        self._write_data_dir()

        self._version = 0
        self.source: str | None = None
        self.app: Any = None
        self._client: TestClient | None = None
        try:
            self.load(source if source is not None else load_seed_source())
        except Exception:
            self.close()
            raise

    def _write_data_dir(self) -> None:
        public = self.data_dir / "public"
        public.mkdir(parents=True, exist_ok=True)
        (public / "readme.txt").write_text("Welcome to the notes service.\n", encoding="utf-8")
        (self.data_dir / "secrets.txt").write_text(f"db_password={self.canary}\n", encoding="utf-8")

    def load(self, source: str) -> None:
        """Build a new app from `source`. On failure the previous app stays in place."""
        self._version += 1
        path = self.workdir / f"target_v{self._version}.py"
        module_name = f"redteam_target_{uuid.uuid4().hex}"
        try:
            path.write_text(source, encoding="utf-8")
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                raise ImportError(f"cannot create import spec for {path}")
            module: ModuleType = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            try:
                spec.loader.exec_module(module)
                app = module.create_app(self.data_dir, self.canary)
            finally:
                sys.modules.pop(module_name, None)
            client = TestClient(app, base_url=BASE_URL, raise_server_exceptions=False)
        except Exception as exc:
            raise TargetLoadError(f"target source failed to load: {exc}") from exc

        if self._client is not None:
            self._client.close()
        self.source = source
        self.app = app
        self._client = client

    def send(self, probe: Probe, *, token: str | None = ATTACKER_TOKEN) -> ProbeResult:
        """Send one validated probe to the app and return the raw result."""
        validate_probe(probe)
        if self._client is None:
            raise RuntimeError("sandbox is closed")
        headers = {"X-Token": token} if token else {}
        headers.update(probe.headers)
        kwargs: dict[str, Any] = {"params": probe.params, "headers": headers}
        if probe.json_body is not None:
            kwargs["json"] = probe.json_body
        response = self._client.request(probe.method.upper(), probe.path, **kwargs)
        return ProbeResult(probe, response.status_code, response.text)

    def routes(self) -> list[str]:
        """Return sorted "METHOD /template" strings for every route in the app."""
        found: set[str] = set()
        for route in self.app.routes:
            if not isinstance(route, APIRoute):
                continue
            for method in route.methods - {"HEAD", "OPTIONS"}:
                found.add(f"{method} {route.path}")
        return sorted(found)

    def close(self) -> None:
        """Close the client and delete the workdir if this sandbox created it."""
        if self._client is not None:
            self._client.close()
            self._client = None
        if self._owns_workdir:
            shutil.rmtree(self.workdir, ignore_errors=True)

    def __enter__(self) -> Sandbox:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
