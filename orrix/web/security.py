"""Session, CSRF and header handling for the Orrix UI.

One admin account, whose password is hashed once at startup and never held
in plain text afterwards. Sessions live in memory and are addressed by an
opaque random id, so a cookie carries no data of its own to forge.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field

SESSION_COOKIE = "orrix_session"
CSRF_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"

_PBKDF2_ROUNDS = 200_000

# AG Grid and HTMX are served from jsdelivr at pinned versions. Nothing else
# is allowed, and script-src carries no 'unsafe-inline': no script anywhere
# in the UI is built from data.
CDN_ORIGIN = "https://cdn.jsdelivr.net"

# Exactly one remote host. Scripts stay strict: no 'unsafe-inline' and no
# 'unsafe-eval', so nothing on the page can execute injected code.
SCRIPT_SRC_ALLOWLIST = ("'self'", CDN_ORIGIN)

# style-src permits inline styles because AG Grid requires them. It sets row
# and cell geometry through inline style attributes and injects style
# elements of its own, and a strict style-src blocked every one: production
# logged hundreds of "Applying inline style violates ..." and the grid
# layout collapsed. The earlier assumption that it only used the CSSOM
# (element.style, which CSP does not govern) was wrong.
#
# This relaxes styling only. Script execution is unaffected: injected markup
# could at worst restyle the page, and our own templates still carry no
# style attributes and no inline script bodies, which
# tests/test_boundaries.py enforces.
STYLE_SRC_ALLOWLIST = ("'self'", CDN_ORIGIN, "'unsafe-inline'")

CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        "script-src " + " ".join(SCRIPT_SRC_ALLOWLIST),
        "style-src " + " ".join(STYLE_SRC_ALLOWLIST),
        "img-src 'self' data:",
        f"font-src 'self' {CDN_ORIGIN} data:",
        "connect-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "object-src 'none'",
    ]
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def hash_password(password: str, salt: bytes | None = None) -> str:
    """PBKDF2-SHA256. Returns `salt_hex:digest_hex`."""
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PBKDF2_ROUNDS
    )
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time comparison against a stored hash."""
    if not stored or ":" not in stored:
        return False
    salt_hex, digest_hex = stored.split(":", 1)
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ROUNDS)
    return hmac.compare_digest(candidate.hex(), digest_hex)


@dataclass
class LoginThrottle:
    """Counts failed logins per client address.

    In memory, which is right for one small instance and honest about its
    limits: a restart clears it, and several instances would each keep their
    own tally. It raises the cost of guessing; it is not a rate limiter for a
    distributed attack.
    """

    max_failures: int = 5
    window_seconds: int = 600
    _failures: dict[str, list[float]] = field(default_factory=dict, repr=False)

    def _recent(self, client: str, now: float) -> list[float]:
        cutoff = now - self.window_seconds
        recent = [stamp for stamp in self._failures.get(client, []) if stamp > cutoff]
        if recent:
            self._failures[client] = recent
        else:
            self._failures.pop(client, None)
        return recent

    def is_locked(self, client: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return len(self._recent(client, now)) >= self.max_failures

    def record_failure(self, client: str, now: float | None = None) -> int:
        """Record a failure and return how many are counted in the window."""
        now = time.time() if now is None else now
        recent = self._recent(client, now)
        recent.append(now)
        self._failures[client] = recent
        return len(recent)

    def clear(self, client: str) -> None:
        """Called on a successful login, so one bad typo costs nothing."""
        self._failures.pop(client, None)

    def retry_after(self, client: str, now: float | None = None) -> int:
        """Seconds until the oldest counted failure leaves the window."""
        now = time.time() if now is None else now
        recent = self._recent(client, now)
        if not recent:
            return 0
        return max(int(self.window_seconds - (now - min(recent))), 1)

    def failures(self, client: str) -> int:
        return len(self._recent(client, time.time()))


@dataclass
class Session:
    session_id: str
    created_at: float
    expires_at: float


@dataclass
class SessionStore:
    """In-memory sessions. A restart logs everyone out, which is fine here."""

    secret: str = field(repr=False)
    ttl_seconds: int = 8 * 3600
    _sessions: dict[str, Session] = field(default_factory=dict, repr=False)

    def create(self) -> Session:
        now = time.time()
        session = Session(
            session_id=secrets.token_urlsafe(32),
            created_at=now,
            expires_at=now + self.ttl_seconds,
        )
        self._sessions[session.session_id] = session
        return session

    def get(self, session_id: str | None) -> Session | None:
        if not session_id:
            return None
        session = self._sessions.get(session_id)
        if session is None:
            return None
        if session.expires_at < time.time():
            self._sessions.pop(session_id, None)
            return None
        return session

    def destroy(self, session_id: str | None) -> None:
        if session_id:
            self._sessions.pop(session_id, None)

    def csrf_token(self, session_id: str) -> str:
        """Derived from the session id under the app secret.

        Nothing to store, and a token is useless without the matching
        session cookie.
        """
        return hmac.new(
            self.secret.encode("utf-8"), session_id.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def verify_csrf(self, session_id: str | None, token: str | None) -> bool:
        if not session_id or not token:
            return False
        return hmac.compare_digest(self.csrf_token(session_id), token)
