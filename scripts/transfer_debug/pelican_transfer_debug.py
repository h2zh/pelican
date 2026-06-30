#!/usr/bin/env python3
# ***************************************************************
#
#  Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you
#  may not use this file except in compliance with the License.  You may
#  obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
# ***************************************************************

"""
pelican_transfer_debug.py -- a debugging multitool for object-transfer failures
in a Pelican federation (e.g. the Open Science Data Federation / OSDF).

When an object transfer fails, the operator's job is to localize the fault:
is the problem the *object*, its *origin / object store*, a specific *cache*,
the *network* between origin and cache, the *token / authorization*, or the
*TLS* credentials of a service?  This tool encodes the questions an operator
asks by hand and runs them automatically, then prints a results table and a
ranked diagnosis of where the failure most likely lives.

It is intentionally dependency-free (Python 3 standard library only) so it can
be dropped onto any debugging host.  Transfers are run by shelling out to the
`pelican` (or `osdf`) client so they exercise the exact code path the operator
uses; discovery, namespace/authorization and TLS introspection are done with
direct HTTP/TLS so we can read the structured detail the CLI hides.

Usage:
    pelican_transfer_debug.py -c config.yaml
    pelican_transfer_debug.py -c config.yaml --json
    pelican_transfer_debug.py --tips

See config.example.yaml for the configuration format.
"""

import argparse
import base64
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
SKIP = "SKIP"
INFO = "INFO"

# Logical components a transfer flows through; the diagnosis localizes the
# fault to one (or a few) of these.
C_DIRECTOR = "Director / discovery"
C_OBJECT = "The specific object"
C_ORIGIN = "Origin / object store"
C_FAILED_CACHE = "The failed cache"
C_GOOD_CACHE = "The known-good cache"
C_ORIGIN_CACHE_NET = "Origin<->cache network / advertisement"
C_TOKEN = "Token / authorization"
C_TLS = "TLS credentials"
C_CLIENT = "Local client / network"


@dataclass
class Result:
    pid: str                       # stable probe id, e.g. "xfer.direct.object"
    question: str                  # human readable question this answers
    status: str                    # PASS / FAIL / WARN / SKIP / INFO
    detail: str = ""               # one-line summary of what happened
    seconds: float = None          # wall-clock time, when meaningful
    extra: dict = field(default_factory=dict)  # structured payload for --json

    @property
    def ok(self):
        return self.status == PASS


class Results:
    """An ordered, id-addressable collection of probe results."""

    def __init__(self):
        self._items = []
        self._by_id = {}

    def add(self, r: Result):
        self._items.append(r)
        self._by_id[r.pid] = r
        return r

    def get(self, pid):
        return self._by_id.get(pid)

    def status(self, pid):
        r = self._by_id.get(pid)
        return r.status if r else None

    def is_pass(self, pid):
        return self.status(pid) == PASS

    def is_fail(self, pid):
        return self.status(pid) == FAIL

    def ran(self, pid):
        """True if the probe produced a definitive PASS/FAIL (not skipped)."""
        return self.status(pid) in (PASS, FAIL)

    def __iter__(self):
        return iter(self._items)


# ---------------------------------------------------------------------------
# Minimal YAML loader (flat key: value).  Prefer PyYAML when available so the
# operator can use richer YAML, but never *require* it.
# ---------------------------------------------------------------------------

def load_config(path):
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text) or {}
        if not isinstance(data, dict):
            raise ValueError("config must be a mapping of keys to values")
        return {k: _normalize(v) for k, v in data.items()}
    except ImportError:
        return _parse_flat_yaml(text)


def _normalize(v):
    if isinstance(v, str):
        v = v.strip()
        return v or None
    return v


def _parse_flat_yaml(text):
    """Parse the small flat `key: value` subset of YAML we need.

    Handles comments, blank lines, quoted strings and `key:` (empty -> None).
    Deliberately rejects nested structures so misuse fails loudly rather than
    silently dropping configuration.
    """
    out = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw)
        if not line.strip():
            continue
        if line[0] in " \t":
            raise ValueError(
                f"config line {lineno}: nested/indented YAML is not supported by "
                f"the built-in parser; install PyYAML for richer configs"
            )
        if ":" not in line:
            raise ValueError(f"config line {lineno}: expected 'key: value', got {raw!r}")
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()
        if val and val[0] in "\"'" and val[-1] == val[0] and len(val) >= 2:
            val = val[1:-1]
        out[key] = val if val else None
    return out


def _strip_comment(line):
    in_quote = None
    for i, ch in enumerate(line):
        if in_quote:
            if ch == in_quote:
                in_quote = None
        elif ch in "\"'":
            in_quote = ch
        elif ch == "#":
            return line[:i]
    return line


# ---------------------------------------------------------------------------
# HTTP / TLS helpers
# ---------------------------------------------------------------------------

USER_AGENT = "pelican-transfer-debug/1.0"


def _ssl_context(ca_bundle, insecure):
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if ca_bundle:
        return ssl.create_default_context(cafile=ca_bundle)
    return ssl.create_default_context()


@dataclass
class HttpResp:
    status: int
    headers: dict           # lower-cased name -> list of values
    location: str = None
    body: str = ""
    error: str = None

    def header(self, name):
        vals = self.headers.get(name.lower())
        return vals[0] if vals else None

    def header_all(self, name):
        return self.headers.get(name.lower(), [])


def http_get(url, ca_bundle=None, insecure=False, timeout=15, token=None,
             allow_redirects=False):
    """GET a URL without following redirects so we can inspect Director headers."""
    headers = {"User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = "Bearer " + token

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    handlers = [urllib.request.HTTPSHandler(context=_ssl_context(ca_bundle, insecure))]
    if not allow_redirects:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            return _to_resp(resp)
    except urllib.error.HTTPError as e:
        # 3xx (redirect not followed) and 4xx/5xx land here; both are useful.
        return _to_resp(e)
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError) as e:
        return HttpResp(status=0, headers={}, error=str(getattr(e, "reason", e)))


def _to_resp(resp):
    headers = {}
    for k, v in resp.headers.items():
        headers.setdefault(k.lower(), []).append(v)
    try:
        body = resp.read().decode("utf-8", "replace")
    except Exception:
        body = ""
    status = getattr(resp, "status", None) or getattr(resp, "code", 0) or 0
    return HttpResp(status=status, headers=headers,
                    location=headers.get("location", [None])[0], body=body)


def discover_federation(federation, ca_bundle, insecure, timeout):
    """Resolve a federation name/URL to its discovery metadata."""
    if federation.startswith("http://") or federation.startswith("https://"):
        base = federation.rstrip("/")
    else:
        base = "https://" + federation.strip("/")
    url = base + "/.well-known/pelican-configuration"
    resp = http_get(url, ca_bundle, insecure, timeout, allow_redirects=True)
    if resp.error or resp.status != 200:
        raise RuntimeError(
            f"federation discovery failed at {url}: "
            f"{resp.error or 'HTTP ' + str(resp.status)}")
    try:
        meta = json.loads(resp.body)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"federation discovery returned non-JSON at {url}: {e}")
    if not meta.get("director_endpoint"):
        raise RuntimeError(f"federation discovery at {url} has no director_endpoint")
    return meta


def parse_namespace_header(value):
    """Parse `namespace=..., require-token=..., collections-url=...`."""
    out = {}
    if not value:
        return out
    for part in value.split(","):
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip()] = v.strip()
    return out


def parse_link_caches(link_values):
    """Extract cache/object-server URLs from one or more RFC-8288 Link headers."""
    caches = []
    for header in link_values:
        for entry in header.split(","):
            entry = entry.strip()
            if entry.startswith("<") and ">" in entry:
                caches.append(entry[1:entry.index(">")])
    return caches


# ---------------------------------------------------------------------------
# TLS introspection
# ---------------------------------------------------------------------------

def _host_port(target, default_port):
    """Accept a bare host, host:port, or full URL and return (host, port)."""
    if "://" in target:
        u = urlsplit(target)
        return u.hostname, (u.port or default_port)
    if target.count(":") == 1 and "]" not in target:
        host, _, port = target.partition(":")
        try:
            return host, int(port)
        except ValueError:
            return target, default_port
    return target, default_port


def tls_inspect(target, default_port, ca_bundle, insecure, timeout):
    """Inspect a service's TLS endpoint: verification, hostname, expiry."""
    host, port = _host_port(target, default_port)
    extra = {"host": host, "port": port}

    # Pass 1: verify against the trust store (and hostname) the way clients do.
    verified, verify_err = True, None
    try:
        vctx = _ssl_context(ca_bundle, insecure=False)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with vctx.wrap_socket(sock, server_hostname=host):
                pass
    except ssl.SSLCertVerificationError as e:
        verified, verify_err = False, str(e)
    except (ssl.SSLError, socket.timeout, OSError) as e:
        # Could not even establish a TLS session -- reachability/handshake issue.
        return Result(
            pid="tls." + target, question=f"TLS to {host}:{port} healthy?",
            status=FAIL, detail=f"could not establish TLS: {e}", extra=extra)

    # Pass 2: grab the leaf certificate details regardless of verification.
    cert = None
    try:
        ictx = _ssl_context(None, insecure=True)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ictx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                if not cert:  # insecure handshake omits the parsed cert
                    der = ss.getpeercert(binary_form=True)
                    cert = _parse_der_dates(der)
    except (ssl.SSLError, socket.timeout, OSError) as e:
        extra["cert_error"] = str(e)

    days_left = None
    if cert and cert.get("notAfter"):
        try:
            not_after = ssl.cert_time_to_seconds(cert["notAfter"])
            days_left = (not_after - time.time()) / 86400.0
            extra["not_after"] = cert["notAfter"]
            extra["days_to_expiry"] = round(days_left, 1)
        except Exception:
            pass
    if cert and cert.get("issuer"):
        extra["issuer"] = _rdn_to_str(cert["issuer"])
    if cert and cert.get("subject"):
        extra["subject"] = _rdn_to_str(cert["subject"])

    extra["verified"] = verified
    if not verified:
        return Result(pid="tls." + target,
                      question=f"TLS to {host}:{port} healthy?",
                      status=FAIL, detail=f"certificate verification failed: {verify_err}",
                      extra=extra)
    if days_left is not None and days_left < 0:
        return Result(pid="tls." + target,
                      question=f"TLS to {host}:{port} healthy?",
                      status=FAIL, detail=f"certificate EXPIRED ({cert['notAfter']})",
                      extra=extra)
    if days_left is not None and days_left < 14:
        return Result(pid="tls." + target,
                      question=f"TLS to {host}:{port} healthy?",
                      status=WARN,
                      detail=f"certificate expires soon ({round(days_left,1)} days)",
                      extra=extra)
    detail = "valid"
    if days_left is not None:
        detail = f"valid, expires in {round(days_left)} days"
    return Result(pid="tls." + target,
                  question=f"TLS to {host}:{port} healthy?",
                  status=PASS, detail=detail, extra=extra)


def _rdn_to_str(rdn):
    parts = []
    for tup in rdn:
        for k, v in tup:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def _parse_der_dates(_der):
    # The stdlib does not expose DER cert parsing without verification; when the
    # peer cert is only available in binary form we simply skip date extraction.
    return {}


# ---------------------------------------------------------------------------
# Token (JWT) decoding & matching
# ---------------------------------------------------------------------------

def _b64url_json(segment):
    pad = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + pad))


def decode_token(token_file):
    with open(token_file, "r", encoding="utf-8") as fh:
        raw = fh.read().strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    parts = raw.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT (expected at least header.payload)")
    header = _b64url_json(parts[0])
    payload = _b64url_json(parts[1])
    return header, payload, raw


def read_scopes(payload):
    scope = payload.get("scope") or payload.get("scp") or ""
    if isinstance(scope, list):
        return scope
    return scope.split()


def token_matches_namespace(payload, object_path, ns_path, advertised_issuers):
    """Return (status, [reasons]) for whether the token authorizes the object.

    Checks issuer against the Director-advertised issuer(s), expiry, and that a
    storage.read scope covers the object path relative to the namespace base.
    """
    reasons = []
    status = PASS

    # Expiry / not-before
    now = time.time()
    exp = payload.get("exp")
    if exp is not None and now > exp:
        status = FAIL
        reasons.append(f"token EXPIRED at {_fmt_ts(exp)}")
    elif exp is not None:
        reasons.append(f"expires {_fmt_ts(exp)}")
    nbf = payload.get("nbf")
    if nbf is not None and now < nbf:
        status = FAIL
        reasons.append(f"token not valid until {_fmt_ts(nbf)}")

    # Issuer match against what the Director advertises for the namespace.
    iss = payload.get("iss")
    if advertised_issuers:
        if iss in advertised_issuers:
            reasons.append(f"issuer matches Director ({iss})")
        else:
            status = FAIL
            reasons.append(
                f"issuer {iss!r} not among Director-advertised issuers "
                f"{advertised_issuers}")
    elif iss:
        reasons.append(f"issuer={iss} (Director advertised none to compare)")

    # Scope coverage.  WLCG storage scopes are relative to the issuer base path,
    # which corresponds to the namespace path; compare the object's path under
    # the namespace against each storage.read resource.
    rel = object_path
    if ns_path and object_path.startswith(ns_path):
        rel = object_path[len(ns_path):]
    if not rel.startswith("/"):
        rel = "/" + rel
    read_resources = read_scopes_list(payload)
    if read_resources:
        covered = any(rel == res or res == "/" or rel.startswith(res.rstrip("/") + "/")
                      for res in read_resources)
        if covered:
            reasons.append(f"a storage.read scope covers {rel}")
        else:
            status = FAIL
            reasons.append(
                f"no storage.read scope covers {rel} (have: {read_resources})")
    else:
        # No read scope at all -- only a problem if the namespace needs a token.
        reasons.append("token carries no storage.read scope")

    return status, reasons


def read_scopes_list(payload):
    out = []
    for s in read_scopes(payload):
        if s.startswith("storage.read:"):
            out.append(s[len("storage.read:"):] or "/")
        elif s in ("storage.read", "read"):
            out.append("/")
    return out


def _fmt_ts(ts):
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    except Exception:
        return str(ts)


# ---------------------------------------------------------------------------
# Transfer execution (shells out to the pelican / osdf client)
# ---------------------------------------------------------------------------

@dataclass
class Transfer:
    ok: bool
    seconds: float
    returncode: int
    cmd: list
    reason: str = ""      # concise failure reason (empty on success)
    bytes: int = 0


def run_transfer(binary, federation, obj, dest_dir, token=None, cache=None,
                 direct=False, timeout=120):
    """Run `<binary> object get` for one probe and summarize the outcome."""
    cmd = [binary, "object", "get"]
    if federation:
        cmd += ["-f", federation]
    if token:
        cmd += ["--token", token]
    if direct:
        cmd += ["--direct"]
    elif cache:
        # Bare cache (no trailing '+') means "only this cache, no fallback" so a
        # cache-specific fault is not masked by the client silently failing over.
        cmd += ["--cache", cache]
    out_name = os.path.join(dest_dir, "obj_" + str(int(time.time() * 1000)))
    cmd += [obj, out_name]

    start = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return Transfer(ok=False, seconds=timeout, returncode=-1, cmd=cmd,
                        reason=f"timed out after {timeout}s")
    except FileNotFoundError:
        return Transfer(ok=False, seconds=0, returncode=-1, cmd=cmd,
                        reason=f"client binary {binary!r} not found")
    elapsed = time.time() - start

    size = 0
    if os.path.exists(out_name):
        size = os.path.getsize(out_name)
    ok = proc.returncode == 0 and size > 0
    reason = "" if ok else _summarize_failure(proc)
    return Transfer(ok=ok, seconds=elapsed, returncode=proc.returncode,
                    cmd=cmd, reason=reason, bytes=size)


def _summarize_failure(proc):
    text = (proc.stderr or "") + "\n" + (proc.stdout or "")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    # Prefer lines that look like an error or carry a pelican error code.
    keyed = [ln for ln in lines
             if any(tok in ln.lower() for tok in
                    ("error", "fail", "denied", "forbidden", "not found",
                     "timeout", "refused", "unauthorized", "no such"))]
    pick = (keyed or lines)[-3:]
    summary = " | ".join(pick) if pick else f"exit code {proc.returncode}"
    return summary[:300]


# ---------------------------------------------------------------------------
# Probe orchestration
# ---------------------------------------------------------------------------

class Debugger:
    def __init__(self, cfg, args):
        self.cfg = cfg
        self.args = args
        self.results = Results()
        self.meta = None              # federation discovery metadata
        self.director = None          # director base URL
        self.ns = {}                  # parsed namespace header for the object
        self.issuers = []             # Director-advertised issuers for object
        self.caches = []              # cache list from Director Link header
        self.origin = cfg.get("origin")
        self.tmpdir = tempfile.mkdtemp(prefix="pelican-debug-")

    # -- configuration accessors --------------------------------------------
    def _req(self, key):
        v = self.cfg.get(key)
        if not v:
            raise SystemExit(f"config error: required key '{key}' is missing")
        return v

    @property
    def binary(self):
        return self.cfg.get("binary") or "pelican"

    @property
    def federation(self):
        return self.cfg.get("federation")

    # -- top-level driver ----------------------------------------------------
    def run(self):
        self.probe_discovery()
        self.probe_namespace()
        self.probe_tls()
        self.probe_token()
        self.probe_transfers()
        return self.results

    # -- discovery -----------------------------------------------------------
    def probe_discovery(self):
        fed = self.federation
        if not fed:
            self.results.add(Result(
                "disc.director",
                "Is the Director reachable / federation discoverable?",
                SKIP, "no 'federation' configured; skipping discovery"))
            return
        try:
            self.meta = discover_federation(
                fed, self.args.ca_bundle, self.args.insecure, self.args.timeout)
            self.director = self.meta["director_endpoint"].rstrip("/")
            self.results.add(Result(
                "disc.director",
                "Is the Director reachable / federation discoverable?",
                PASS, f"director_endpoint = {self.director}",
                extra={k: self.meta.get(k) for k in
                       ("director_endpoint", "namespace_registration_endpoint",
                        "jwks_uri")}))
        except RuntimeError as e:
            self.results.add(Result(
                "disc.director",
                "Is the Director reachable / federation discoverable?",
                FAIL, str(e)))

    def _director_object_query(self, obj):
        """Query the Director's object endpoint; return HttpResp or None."""
        if not self.director:
            return None
        url = self.director + "/api/v1.0/director/object" + obj
        return http_get(url, self.args.ca_bundle, self.args.insecure,
                        self.args.timeout, allow_redirects=False)

    def probe_namespace(self):
        obj = self._req("object")
        resp = self._director_object_query(obj)
        if resp is None:
            self.results.add(Result(
                "disc.namespace",
                "Does the Director know an origin/namespace for the object?",
                SKIP, "Director not discovered"))
            return
        if resp.error:
            self.results.add(Result(
                "disc.namespace",
                "Does the Director know an origin/namespace for the object?",
                FAIL, f"director query failed: {resp.error}"))
            return

        self.ns = parse_namespace_header(resp.header("X-Pelican-Namespace"))
        self.issuers = [v.split("=", 1)[1] for v in
                        resp.header_all("X-Pelican-Authorization") if "=" in v]
        self.caches = parse_link_caches(resp.header_all("Link"))
        token_gen = resp.header("X-Pelican-Token-Generation")

        extra = {
            "http_status": resp.status,
            "namespace": self.ns,
            "advertised_issuers": self.issuers,
            "director_cache_count": len(self.caches),
            "token_generation": token_gen,
        }
        # A 307 with a namespace header is the healthy "I know this object" case.
        if resp.status in (301, 302, 307, 308) and self.ns.get("namespace"):
            req_tok = self.ns.get("require-token")
            detail = (f"namespace={self.ns.get('namespace')} "
                      f"require-token={req_tok} "
                      f"caches_advertised={len(self.caches)}")
            self.results.add(Result(
                "disc.namespace",
                "Does the Director know an origin/namespace for the object?",
                PASS, detail, extra=extra))
        elif resp.status == 404:
            self.results.add(Result(
                "disc.namespace",
                "Does the Director know an origin/namespace for the object?",
                FAIL,
                "Director returned 404 -- no origin advertises this namespace "
                "(registration/advertisement problem or wrong path)",
                extra=extra))
        else:
            self.results.add(Result(
                "disc.namespace",
                "Does the Director know an origin/namespace for the object?",
                WARN, f"unexpected Director response (HTTP {resp.status})",
                extra=extra))

        # Discover the origin if the operator did not pin one.
        if not self.origin and self.director:
            ourl = self.director + "/api/v1.0/director/origin" + obj
            oresp = http_get(ourl, self.args.ca_bundle, self.args.insecure,
                             self.args.timeout, allow_redirects=False)
            loc = oresp.location if oresp else None
            if loc:
                self.origin = loc
                self.results.add(Result(
                    "disc.origin",
                    "Which origin does the Director redirect direct reads to?",
                    INFO, f"origin = {loc}", extra={"origin": loc}))

    # -- TLS -----------------------------------------------------------------
    def probe_tls(self):
        targets = []
        if self.director:
            targets.append(("director", self.director))
        if self.cfg.get("failed_cache"):
            targets.append(("failed_cache", self.cfg["failed_cache"]))
        if self.cfg.get("known_good_cache"):
            targets.append(("known_good_cache", self.cfg["known_good_cache"]))
        if self.origin:
            targets.append(("origin", self.origin))

        seen = set()
        for label, target in targets:
            key = target
            if key in seen:
                continue
            seen.add(key)
            r = tls_inspect(target, self.args.tls_port,
                            self.args.ca_bundle, self.args.insecure,
                            self.args.timeout)
            r.pid = f"tls.{label}"
            r.question = f"Are the TLS credentials of the {label} working?"
            self.results.add(r)

    # -- token ---------------------------------------------------------------
    def probe_token(self):
        token_file = self.cfg.get("token")
        require_token = (self.ns.get("require-token") == "true")
        if not token_file:
            status = WARN if require_token else SKIP
            detail = ("namespace requires a token but none configured"
                      if require_token else "no token configured")
            self.results.add(Result(
                "token.match",
                "Does my token match the Director's authorization for the object?",
                status, detail))
            return
        try:
            header, payload, _ = decode_token(token_file)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            self.results.add(Result(
                "token.match",
                "Does my token match the Director's authorization for the object?",
                FAIL, f"could not decode token: {e}"))
            return
        status, reasons = token_matches_namespace(
            payload, self.cfg["object"], self.ns.get("namespace"), self.issuers)
        self.results.add(Result(
            "token.match",
            "Does my token match the Director's authorization for the object?",
            status, "; ".join(reasons),
            extra={"iss": payload.get("iss"), "aud": payload.get("aud"),
                   "scope": payload.get("scope"), "exp": payload.get("exp"),
                   "alg": header.get("alg")}))

    # -- transfers -----------------------------------------------------------
    def _xfer(self, pid, question, obj, token=None, cache=None, direct=False):
        if not obj:
            self.results.add(Result(pid, question, SKIP, "object not configured"))
            return None
        if self.args.no_transfers:
            self.results.add(Result(pid, question, SKIP, "--no-transfers set"))
            return None
        t = run_transfer(self.binary, self.federation, obj, self.tmpdir,
                         token=token, cache=cache, direct=direct,
                         timeout=self.args.transfer_timeout)
        status = PASS if t.ok else FAIL
        if t.ok:
            detail = f"{t.bytes} bytes in {t.seconds:.1f}s"
        else:
            detail = t.reason
        self.results.add(Result(pid, question, status, detail,
                                seconds=t.seconds,
                                extra={"cmd": " ".join(t.cmd),
                                       "returncode": t.returncode}))
        return t

    def probe_transfers(self):
        obj = self.cfg.get("object")
        backup = self.cfg.get("backup_object")
        control = self.cfg.get("control_object")
        token = self.cfg.get("token")
        control_token = self.cfg.get("control_token")
        failed_cache = self.cfg.get("failed_cache")
        good_cache = self.cfg.get("known_good_cache")

        # 0. Reproduce the reported failure through the failed cache.
        self._xfer("xfer.failed_cache.object",
                   "Reproduce: does the object fail through the failed cache?",
                   obj, token=token, cache=failed_cache)

        # 1. Cache-miss exercise: pull a control object from a *different* object
        #    store through the failed cache.  Forces the cache to discover a new
        #    origin and network with it; success implicates the first origin.
        self._xfer("xfer.failed_cache.control",
                   "Can the failed cache pull a control object from a different "
                   "origin (cache-miss path / new-origin discovery)?",
                   control, token=control_token, cache=failed_cache)

        # 2. Same cache, backup object from the same namespace/origin: isolates a
        #    single-object fault from an origin-wide one.
        self._xfer("xfer.failed_cache.backup",
                   "Can the failed cache pull a different object from the same "
                   "origin?",
                   backup, token=token, cache=failed_cache)

        # 3. Direct origin read of the target object (bypass caches entirely).
        self._xfer("xfer.direct.object",
                   "Can the object be read directly from the origin "
                   "(bypassing caches)?",
                   obj, token=token, direct=True)

        # 4. Direct origin read of the backup object.
        self._xfer("xfer.direct.backup",
                   "Can a different object be read directly from the same origin?",
                   backup, token=token, direct=True)

        # 5. Same object through a known-good cache.
        self._xfer("xfer.good_cache.object",
                   "Can the same object be read through a known-good cache?",
                   obj, token=token, cache=good_cache)

        # 6. Control object through the known-good cache (baseline sanity).
        self._xfer("xfer.good_cache.control",
                   "Baseline: can the known-good cache pull the control object?",
                   control, token=control_token, cache=good_cache)

    def cleanup(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Diagnosis engine: combine probe results into ranked findings.
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    component: str
    confidence: str          # high / medium / low
    summary: str
    evidence: list


def diagnose(res: Results):
    findings = []

    def passed(pid):
        return res.is_pass(pid)

    def failed(pid):
        return res.is_fail(pid)

    def ran(pid):
        return res.ran(pid)

    # ---- Director / discovery -------------------------------------------
    if failed("disc.director"):
        findings.append(Finding(
            C_DIRECTOR, "high",
            "The Director could not be reached or the federation could not be "
            "discovered. Every downstream result is unreliable until this is fixed.",
            ["disc.director failed"]))
        return findings  # nothing else is trustworthy
    if failed("disc.namespace"):
        findings.append(Finding(
            C_DIRECTOR, "high",
            "The Director does not advertise an origin/namespace for this object "
            "(404). This is a registration/advertisement issue or a wrong object "
            "path -- not a cache or transfer problem.",
            ["disc.namespace failed"]))

    # ---- TLS -------------------------------------------------------------
    for r in res:
        if r.pid.startswith("tls.") and r.status in (FAIL, WARN):
            findings.append(Finding(
                C_TLS, "high" if r.status == FAIL else "low",
                f"TLS issue on {r.pid.split('.',1)[1]}: {r.detail}",
                [f"{r.pid} {r.status}"]))

    # ---- Token / authorization ------------------------------------------
    if failed("token.match"):
        # Strong signal if authed reads fail but an unauthenticated/control read
        # works.
        ev = ["token.match failed"]
        conf = "medium"
        if failed("xfer.direct.object") and passed("xfer.failed_cache.control"):
            conf = "high"
            ev.append("direct object read failed while a control object succeeded")
        findings.append(Finding(
            C_TOKEN, conf,
            "The access token does not satisfy the Director's advertised "
            "authorization for this namespace (issuer mismatch, missing "
            "storage.read scope, or expired). Reads that need auth will be denied.",
            ev))

    # ---- Localize the transfer fault ------------------------------------
    direct_obj = res.status("xfer.direct.object")
    direct_bak = res.status("xfer.direct.backup")
    fc_obj = res.status("xfer.failed_cache.object")
    fc_ctrl = res.status("xfer.failed_cache.control")
    fc_bak = res.status("xfer.failed_cache.backup")
    gc_obj = res.status("xfer.good_cache.object")
    gc_ctrl = res.status("xfer.good_cache.control")

    # The failed cache is the culprit: the object is served elsewhere (directly
    # and/or by a second cache) but not through the failed cache.  Require that
    # the failure is *isolated* to this cache -- if the good cache also fails the
    # object, it is not cache-specific and the origin<->cache rule below handles
    # it instead.
    cache_isolated = (fc_obj == FAIL and gc_obj == PASS) or \
                     (fc_obj == FAIL and direct_obj == PASS and gc_obj != FAIL)
    if cache_isolated:
        ev = ["xfer.failed_cache.object failed"]
        if direct_obj == PASS:
            ev.append("direct origin read succeeded")
        if gc_obj == PASS:
            ev.append("known-good cache served the same object")
        if fc_ctrl == PASS:
            ev.append("failed cache served a control object from another origin")
        findings.append(Finding(
            C_FAILED_CACHE, "high",
            "The object is served elsewhere but not through the failed cache. "
            "The fault is local to that cache" +
            (" (it can reach other origins, so suspect this object's cached "
             "copy, its link to this origin, or cache-side errors)."
             if fc_ctrl == PASS else
             "; if it also cannot reach other origins it may be down or "
             "network-isolated."),
            ev))

    # The specific object is broken/missing/unauthorized at the origin, but the
    # origin is otherwise healthy.
    if direct_obj == FAIL and (direct_bak == PASS or fc_bak == PASS):
        findings.append(Finding(
            C_OBJECT, "high",
            "The target object cannot be read even directly from the origin, but "
            "a different object from the same origin can. The problem is specific "
            "to this object (missing, corrupt, wrong permissions, or path).",
            [p for p in ["xfer.direct.object failed",
                         "xfer.direct.backup passed" if direct_bak == PASS else None,
                         "xfer.failed_cache.backup passed" if fc_bak == PASS else None]
             if p]))

    # The origin / object store itself is unhealthy: nothing from this namespace
    # reads directly or via cache, but a control object from a different origin
    # works.
    no_origin_obj_reads = (direct_obj == FAIL and
                           direct_bak in (FAIL, None, SKIP) and
                           fc_obj == FAIL)
    control_ok = (fc_ctrl == PASS or gc_ctrl == PASS)
    if no_origin_obj_reads and control_ok:
        findings.append(Finding(
            C_ORIGIN, "high",
            "No object from this namespace can be read directly or through a "
            "cache, while a control object from a different origin works. The "
            "origin or its object-store backend for this namespace is the likely "
            "culprit.",
            [p for p in ["xfer.direct.object failed",
                         "xfer.direct.backup failed" if direct_bak == FAIL else None,
                         "xfer.failed_cache.object failed",
                         "a control object from another origin succeeded"] if p]))

    # Caches can serve other origins, and the origin serves the object directly,
    # but no cache can serve this origin's object: suspect the origin<->cache
    # network/path or the origin not advertising to caches.
    if (direct_obj == PASS and fc_obj == FAIL and gc_obj == FAIL and
            (fc_ctrl == PASS or gc_ctrl == PASS)):
        findings.append(Finding(
            C_ORIGIN_CACHE_NET, "medium",
            "The origin serves the object directly and caches serve other "
            "origins, yet no cache can serve this object. Suspect the network "
            "path between this origin and the caches, a firewall, or the origin "
            "not advertising/permitting these caches.",
            ["xfer.direct.object passed", "both cache reads of the object failed",
             "caches served a control object from another origin"]))

    # Everything failed, including the control through the known-good cache:
    # the problem is most likely local to the debugging host/network.
    transfer_pids = ["xfer.failed_cache.object", "xfer.failed_cache.control",
                     "xfer.direct.object", "xfer.good_cache.object",
                     "xfer.good_cache.control"]
    ran_any = [p for p in transfer_pids if res.ran(p)]
    if ran_any and all(res.status(p) == FAIL for p in ran_any):
        findings.append(Finding(
            C_CLIENT, "medium",
            "Every transfer failed, including a control object from a different "
            "origin through a known-good cache. The problem is most likely local "
            "to this debugging host: network egress, client configuration, "
            "system clock, or trust store.",
            ["all attempted transfers failed"]))

    if not findings:
        findings.append(Finding(
            "Inconclusive", "low",
            "No single component stands out. Review the table: re-run with more "
            "of the optional config fields (backup_object, control_object, "
            "known_good_cache) populated so the tool can triangulate, and consult "
            "the additional debugging questions (--tips).",
            []))

    # Rank: high before medium before low.
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: order.get(f.confidence, 3))
    return findings


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_COLORS = {
    PASS: "\033[32m", FAIL: "\033[31m", WARN: "\033[33m",
    SKIP: "\033[90m", INFO: "\033[36m",
}
_RESET = "\033[0m"


def _color(status, enabled):
    if not enabled:
        return status
    return f"{_COLORS.get(status, '')}{status}{_RESET}"


def render_table(res: Results, color):
    rows = []
    for r in res:
        secs = f"{r.seconds:.1f}s" if r.seconds is not None else ""
        rows.append((r.status, secs, r.question, r.detail))
    qw = min(max((len(q) for _, _, q, _ in rows), default=8), 60)
    print()
    print(f"{'RESULT':<6}  {'TIME':>6}  {'QUESTION':<{qw}}  DETAIL")
    print(f"{'-'*6}  {'-'*6}  {'-'*qw}  {'-'*6}")
    for status, secs, q, detail in rows:
        q_disp = (q[:qw - 1] + "…") if len(q) > qw else q
        detail = detail.replace("\n", " ")
        if len(detail) > 90:
            detail = detail[:89] + "…"
        print(f"{_color(status, color):<{6 + (len(_color(status,color))-len(status))}}  "
              f"{secs:>6}  {q_disp:<{qw}}  {detail}")
    print()


def render_findings(findings, color):
    print("Diagnosis -- most likely location of the failure:")
    print("=" * 64)
    for i, f in enumerate(findings, 1):
        marker = {"high": "●", "medium": "◐", "low": "○"}.get(
            f.confidence, "○")
        head = f"{i}. [{f.confidence.upper()}] {f.component}"
        if color:
            col = {"high": "\033[1;31m", "medium": "\033[1;33m",
                   "low": "\033[1;90m"}.get(f.confidence, "")
            head = f"{col}{marker} {head}{_RESET}"
        else:
            head = f"{marker} {head}"
        print(head)
        for line in _wrap(f.summary, 64):
            print("    " + line)
        if f.evidence:
            print("    evidence: " + "; ".join(f.evidence))
        print()


def _wrap(text, width):
    words, line, out = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line)
            line = w
        else:
            line = (line + " " + w).strip()
    if line:
        out.append(line)
    return out


# ---------------------------------------------------------------------------
# Additional debugging questions (printed with --tips).
# ---------------------------------------------------------------------------

TIPS = """\
Additional questions worth asking when localizing an OSDF/Pelican transfer failure
==================================================================================

Director & routing
  * Is the Director itself healthy and not rate-limiting/rebooting? Check
    /api/v1.0/director/healthTest and the Director's own logs. A just-rebooted
    Director returns 429 until it re-learns advertisements.
  * Does the Director's cache list for this object actually include the cache you
    are testing, and in what geo/priority order? (Inspect the `Link` header.)
    A "failed cache" the Director never routes to is a red herring.
  * Is the origin (or the cache) in a declared downtime window? Check
    `pelican ... downtime list` and the Director's downtime view.

Origin & object store
  * Does the origin's exported namespace prefix actually cover the object path,
    and is the object present in the backing store (S3/POSIX/etc.) at the mapped
    key? A read that fails directly but `object ls` shows nothing points here.
  * Is the object-store backend (S3 bucket, POSIX mount) reachable and within
    quota from the origin? Origin logs / the origin's XRootD logs will show
    backend errors distinct from Pelican-level errors.
  * Has the origin successfully advertised to the Director recently (heartbeat)?
    An origin that is up but not advertising is invisible to caches.

Caches
  * Cache hit vs miss: was the object resident? A cache HEAD with an `Age`
    header, or a fast second read after a slow first, indicates a hit. A failure
    only on a miss points at the cache's ability to reach the origin.
  * Is the cache's disk full / LotMan purging aggressively, or is the cached
    copy corrupt? `pelican cache introspect` / cache logs help here. Try
    `pelican object evict` then re-pull to rule out a poisoned cached copy.
  * Does the cache trust the same federation/Director and have current TLS and
    JWKS? A cache with stale JWKS will reject otherwise-valid tokens.

Tokens & authorization
  * Does the token's `aud` (audience) match what the origin/cache expects, in
    addition to issuer and scope? Audience mismatches are a common silent 403.
  * Is the token issuer's JWKS reachable from the origin AND the cache so they
    can verify signatures? A network-isolated issuer breaks auth federation-wide.
  * Are origin/cache clocks in sync? `exp`/`nbf`/`iat` skew causes intermittent
    auth failures that look like flapping.

Network, TLS & DNS
  * Can the failed cache reach the origin's host:port directly (not just the
    Director)? Path/firewall problems between origin and cache are invisible from
    the client. Test from the cache host if you can.
  * Do the service hostnames resolve consistently (no split-horizon DNS), and do
    the TLS SANs match the advertised hostnames?
  * Is an intermediate (ingress/Traefik/load balancer) terminating or
    re-routing? A response "not from a Pelican process" suggests an ingress hop.

Reproducibility & scope
  * Is the failure deterministic or intermittent? Intermittent failures across a
    cache fleet suggest one bad backend behind a load balancer.
  * Does it fail for all clients/sites or just yours? Compare from a second
    network/site to separate client-local issues from federation issues.
  * Does the same object fail for both authenticated and public reads, and for
    both `object get` and `object stat`? `stat` failing but `get` differing
    narrows it to metadata vs data paths.
"""


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        description="Debugging multitool for Pelican/OSDF object-transfer failures.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run with --tips for additional debugging questions.")
    p.add_argument("-c", "--config", help="Path to the YAML config file.")
    p.add_argument("--json", action="store_true",
                   help="Emit machine-readable JSON instead of a table.")
    p.add_argument("--no-transfers", action="store_true",
                   help="Skip client transfers; run only discovery/TLS/token probes.")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    p.add_argument("--tips", action="store_true",
                   help="Print additional debugging questions and exit.")
    p.add_argument("--timeout", type=int, default=15,
                   help="HTTP/TLS probe timeout in seconds (default 15).")
    p.add_argument("--transfer-timeout", type=int, default=120,
                   help="Per-transfer timeout in seconds (default 120).")
    p.add_argument("--tls-port", type=int, default=8443,
                   help="Default TLS port when a service is given as a bare host "
                        "(default 8443).")
    p.add_argument("--ca-bundle", help="CA bundle for verification (PEM).")
    p.add_argument("--insecure", action="store_true",
                   help="Do not verify TLS when probing (still reports cert info).")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.tips:
        print(TIPS)
        return 0

    if not args.config:
        print("error: --config/-c is required (or use --tips)", file=sys.stderr)
        return 2

    try:
        cfg = load_config(args.config)
    except (OSError, ValueError) as e:
        print(f"error: could not load config: {e}", file=sys.stderr)
        return 2
    if not cfg.get("object"):
        print("error: config must set 'object'", file=sys.stderr)
        return 2

    color = sys.stdout.isatty() and not args.no_color and not args.json

    dbg = Debugger(cfg, args)
    try:
        results = dbg.run()
        findings = diagnose(results)
    finally:
        dbg.cleanup()

    if args.json:
        print(json.dumps({
            "config": {k: v for k, v in cfg.items() if k not in ("token", "control_token")},
            "results": [{"id": r.pid, "question": r.question, "status": r.status,
                         "detail": r.detail, "seconds": r.seconds, "extra": r.extra}
                        for r in results],
            "diagnosis": [{"component": f.component, "confidence": f.confidence,
                           "summary": f.summary, "evidence": f.evidence}
                          for f in findings],
        }, indent=2))
        return 0

    render_table(results, color)
    render_findings(findings, color)
    print("Tip: run with --tips for more questions to ask, and populate the "
          "optional config fields (backup_object, control_object, "
          "known_good_cache) for a sharper diagnosis.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
