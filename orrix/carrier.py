"""Carrier delivery status, reduced to validated enums.

A carrier API is a third party relaying text a shipper typed. Orrix treats
its response exactly as it treats a buyer message: untrusted input that may
fill one closed schema and nothing else. Every free-text field a provider
returns -- checkpoint messages, location names, courier notes, signatory
names -- is dropped here and never stored, never shown, never reasoned on.

What survives a lookup is four values: one of five status enums, a nullable
ISO timestamp, the time of the check, and the provider's name. That is the
whole surface.

This module holds no write capability, reads no environment, and is never
reached by the Reader. It takes a CarrierConfig from its caller.

Everything here is inert unless CARRIER_ENABLED is true. With the flag off no
client is constructed, no lookup is attempted and no carrier fact is ever
added, so Facts, the policy decision and the approval id are exactly what
they were before this module existed.
"""

from __future__ import annotations

import logging
import re
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Mapping, Protocol

from .facts import (
    CARRIER_DELIVERED_AT,
    CARRIER_STATUS,
    SOURCE_CARRIER_API,
    Fact,
    Facts,
    FactStatus,
)

logger = logging.getLogger("orrix.carrier")

#: Providers this module knows how to talk to. Anything else is unavailable.
PROVIDER_AFTERSHIP = "aftership"
PROVIDER_NONE = "none"

#: The one host the real adapter may address, as a bare host. The full URL is
#: assembled at call time and never logged.
AFTERSHIP_HOST = "api.aftership.com"
#: Dated API version. Bumping this is a deliberate edit, not a float.
AFTERSHIP_API_VERSION = "2024-04"
#: AfterShip authenticates with its own header, not a bearer token.
AFTERSHIP_KEY_HEADER = "as-api-key"

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_LOOKUPS_PER_HOUR = 60
DEFAULT_CACHE_TTL_SECONDS = 3600.0
#: Total attempts per lookup, including the first. Documented cap: 3.
MAX_ATTEMPTS = 3
_BACKOFF_BASE_SECONDS = 0.5

# A carrier name or tracking number we are willing to put in a URL. Stricter
# than the facts layer's tracking pattern on purpose: that one tolerates
# spaces and slashes because a human types into it, but these two values
# become path segments in a request, so a slash could retarget the URL and a
# space means the value is prose rather than a tracking number. No spaces, no
# slashes, no query characters: a sentence fails this and is never sent.
_LOOKUP_KEY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,47}$")
# Timestamps a provider may hand back. Anything else is dropped.
_TIMESTAMP_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?$"
)
_PROVIDER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


class CarrierStatus(str, Enum):
    """The complete set of delivery states Orrix will hold.

    Deliberately coarse. A provider's richer vocabulary is collapsed into
    these five, because anything finer would be a claim Orrix cannot check.
    """

    DELIVERED = "delivered"
    IN_TRANSIT = "in_transit"
    EXCEPTION = "exception"
    NOT_FOUND = "not_found"
    UNAVAILABLE = "unavailable"


#: Statuses that say something about the shipment, as opposed to saying the
#: lookup did not work. Only these become a carrier_reported fact.
REPORTED_STATUSES = frozenset(
    {CarrierStatus.DELIVERED, CarrierStatus.IN_TRANSIT, CarrierStatus.EXCEPTION}
)

#: Fact values, as codes. Uppercased so they pass the facts layer's code
#: pattern and read like every other status value on the case page.
_STATUS_CODES = {
    CarrierStatus.DELIVERED: "DELIVERED",
    CarrierStatus.IN_TRANSIT: "IN_TRANSIT",
    CarrierStatus.EXCEPTION: "EXCEPTION",
}

#: The value the discrepancy detector compares against.
CARRIER_DELIVERED_CODE = "DELIVERED"


@dataclass(frozen=True)
class CarrierResult:
    """One lookup, reduced to what Orrix keeps.

    Constructed only through `carrier_result`, which validates every field.
    A provider cannot widen this: extra keys in its response have nowhere to
    go, and a value failing its pattern is dropped rather than carried.
    """

    status: CarrierStatus
    delivered_at: str | None
    checked_at: str
    source: str

    @property
    def is_reported(self) -> bool:
        """True when the carrier actually said something about the shipment."""
        return self.status in REPORTED_STATUSES

    @property
    def status_code(self) -> str | None:
        """The fact value for this status, or None when nothing is reported."""
        return _STATUS_CODES.get(self.status)

    def as_dict(self) -> dict[str, Any]:
        """Display-only view. Carries no provider text, because none is kept."""
        return {
            "status": self.status.value,
            "delivered_at": self.delivered_at,
            "checked_at": self.checked_at,
            "source": self.source,
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def carrier_result(
    status: Any,
    delivered_at: Any = None,
    checked_at: Any = None,
    source: Any = PROVIDER_NONE,
) -> CarrierResult:
    """Build a CarrierResult, validating every field. Never raises.

    This is the choke point. A provider's response reaches it as loose
    values and leaves as four checked ones; anything unrecognised becomes
    `unavailable` rather than an exception into the pipeline.
    """
    try:
        resolved = status if isinstance(status, CarrierStatus) else CarrierStatus(str(status))
    except ValueError:
        resolved = CarrierStatus.UNAVAILABLE

    # Only a delivery may carry a delivery time, and only a well-formed one.
    stamp: str | None = None
    if resolved is CarrierStatus.DELIVERED and isinstance(delivered_at, str):
        candidate = delivered_at.strip()
        if _TIMESTAMP_PATTERN.match(candidate):
            stamp = candidate

    when = checked_at if isinstance(checked_at, str) and checked_at.strip() else _now_iso()

    name = str(source).strip().lower()
    provider = name if _PROVIDER_PATTERN.match(name) else PROVIDER_NONE

    return CarrierResult(
        status=resolved, delivered_at=stamp, checked_at=when.strip(), source=provider
    )


def unavailable(source: str = PROVIDER_NONE, checked_at: str | None = None) -> CarrierResult:
    """The result every failure mode produces."""
    return carrier_result(CarrierStatus.UNAVAILABLE, None, checked_at, source)


# -- configuration -------------------------------------------------------


@dataclass(frozen=True)
class CarrierConfig:
    """Carrier settings, resolved by orrix.config and handed down.

    `api_key` is repr=False so a traceback or a log line cannot print it.
    """

    enabled: bool = False
    provider: str = PROVIDER_NONE
    api_key: str | None = field(default=None, repr=False)
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_lookups_per_hour: int = DEFAULT_MAX_LOOKUPS_PER_HOUR
    cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS

    @property
    def is_usable(self) -> bool:
        """Enabled, with a known provider and a key to talk to it."""
        return bool(self.enabled and self.provider == PROVIDER_AFTERSHIP and self.api_key)

    def summary(self) -> dict[str, Any]:
        """Safe to log: presence and settings, never the key."""
        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "api_key_set": bool(self.api_key),
            "timeout_seconds": self.timeout_seconds,
            "max_lookups_per_hour": self.max_lookups_per_hour,
            "cache_ttl_seconds": self.cache_ttl_seconds,
        }


# -- the interface -------------------------------------------------------


class CarrierClient(Protocol):
    """One method. A carrier connector can do nothing else."""

    def lookup(self, carrier: str, tracking_number: str) -> CarrierResult: ...


class NullCarrierClient:
    """The client used when the connector is off or misconfigured.

    It makes no network call and always reports unavailable, so every caller
    can treat "disabled" and "could not reach the provider" identically.
    """

    source = PROVIDER_NONE

    def lookup(self, carrier: str, tracking_number: str) -> CarrierResult:
        return unavailable(self.source)


class FakeCarrierClient:
    """Scripted client for tests. Contacts nothing.

    Hand it a result, a list of results to return in order, or a callable.
    It records every lookup so a test can assert a cache hit avoided a call.
    """

    source = "fake"

    def __init__(self, results: Any = None, raises: BaseException | None = None):
        self._results = results
        self._raises = raises
        self.calls: list[tuple[str, str]] = []

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def lookup(self, carrier: str, tracking_number: str) -> CarrierResult:
        self.calls.append((carrier, tracking_number))
        if self._raises is not None:
            raise self._raises

        candidate = self._results
        if callable(candidate):
            candidate = candidate(carrier, tracking_number)
        elif isinstance(candidate, list):
            index = min(len(self.calls) - 1, len(candidate) - 1)
            candidate = candidate[index] if candidate else None

        if candidate is None:
            return unavailable(self.source)
        if isinstance(candidate, CarrierResult):
            return candidate
        # A mapping, as a provider would hand it over: parsed, not trusted.
        return parse_aftership(candidate, source=self.source)


# -- the AfterShip adapter ----------------------------------------------


def parse_aftership(
    body: Any, source: str = PROVIDER_AFTERSHIP, checked_at: str | None = None
) -> CarrierResult:
    """Map an AfterShip tracking body onto the enum. Strict; never raises.

    Only two keys are read: the status tag and the delivery timestamp.
    Everything else in the response -- checkpoints, addresses, courier
    notes, the shipment title, the customer's name -- is never visited, so
    none of it can reach a fact, a payload or a page.

    Two envelope shapes are accepted because the documentation for the
    dated API versions is not public: the legacy `data.tracking` wrapper and
    a bare `data` object. An envelope matching neither is unavailable.
    """
    if not isinstance(body, Mapping):
        return unavailable(source, checked_at)

    data = body.get("data")
    tracking: Any = None
    if isinstance(data, Mapping):
        nested = data.get("tracking")
        tracking = nested if isinstance(nested, Mapping) else data
    elif isinstance(body.get("tracking"), Mapping):
        tracking = body["tracking"]
    else:
        # A bare tracking object, as the fake and some SDKs hand it over.
        tracking = body if "tag" in body else None

    if not isinstance(tracking, Mapping):
        return unavailable(source, checked_at)

    tag = tracking.get("tag")
    if not isinstance(tag, str):
        return unavailable(source, checked_at)

    status = _AFTERSHIP_TAGS.get(tag.strip())
    if status is None:
        # An unknown tag is not a guess. Report nothing.
        return unavailable(source, checked_at)

    delivered_at = tracking.get("shipment_delivery_date")
    return carrier_result(status, delivered_at, checked_at, source)


#: Documented `tag` vocabulary, mapped onto Orrix's five states. Pending and
#: InfoReceived mean the carrier has the shipment on file but has not moved
#: it yet, which is in_transit as far as Orrix is concerned -- it is not a
#: delivery and not a failure.
_AFTERSHIP_TAGS: dict[str, CarrierStatus] = {
    "Delivered": CarrierStatus.DELIVERED,
    "InTransit": CarrierStatus.IN_TRANSIT,
    "OutForDelivery": CarrierStatus.IN_TRANSIT,
    "InfoReceived": CarrierStatus.IN_TRANSIT,
    "Pending": CarrierStatus.IN_TRANSIT,
    "AvailableForPickup": CarrierStatus.IN_TRANSIT,
    "AttemptFail": CarrierStatus.EXCEPTION,
    "Exception": CarrierStatus.EXCEPTION,
    "Expired": CarrierStatus.EXCEPTION,
}


class AfterShipCarrierClient:
    """Real adapter for AfterShip's tracking API.

    Verified against the current public documentation: the host, the dated
    path family, the `as-api-key` header, the `tag` vocabulary, the
    `shipment_delivery_date` field and the per-endpoint rate limits. The
    response envelope for the dated versions is NOT public, so the parser
    accepts the two plausible shapes and reports unavailable for anything
    else rather than guessing. See the README for what that means.

    Never raises into the pipeline: a timeout, a 4xx, a 5xx, a rate limit,
    an unparseable body or a transport error all come back as unavailable.
    The key is sent in a header and never logged; only the host and the
    status code are ever written to a log line.
    """

    source = PROVIDER_AFTERSHIP

    def __init__(
        self,
        api_key: str,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        session: Any | None = None,
        host: str = AFTERSHIP_HOST,
        api_version: str = AFTERSHIP_API_VERSION,
    ):
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._session = session
        self._host = host
        self._api_version = api_version

    def _request(self, carrier: str, tracking_number: str) -> Any:
        session = self._session
        if session is None:  # pragma: no cover - exercised only against the live API
            import requests

            session = requests
        url = (
            f"https://{self._host}/tracking/{self._api_version}/trackings"
            f"/{carrier}/{tracking_number}"
        )
        return session.get(
            url,
            headers={AFTERSHIP_KEY_HEADER: self._api_key, "Accept": "application/json"},
            timeout=self._timeout,
        )

    def lookup(self, carrier: str, tracking_number: str) -> CarrierResult:
        try:
            response = self._request(carrier, tracking_number)
        except Exception as error:  # noqa: BLE001 - a transport failure is unavailable
            logger.warning(
                "carrier lookup failed provider=%s host=%s exception=%s",
                self.source,
                self._host,
                type(error).__name__,
            )
            return unavailable(self.source)

        status_code = getattr(response, "status_code", None)
        if status_code == 404:
            return carrier_result(CarrierStatus.NOT_FOUND, None, None, self.source)
        if status_code != 200:
            # 429 and every other non-200 are the same to a caller: no answer.
            logger.warning(
                "carrier lookup refused provider=%s host=%s http_status=%s",
                self.source,
                self._host,
                status_code,
            )
            return unavailable(self.source)

        try:
            body = response.json()
        except Exception:  # noqa: BLE001 - an unparseable body is unavailable
            logger.warning(
                "carrier response was not json provider=%s host=%s", self.source, self._host
            )
            return unavailable(self.source)

        return parse_aftership(body, self.source)


class StubCarrierClient:
    """A provider named in config that has no adapter here.

    Always unavailable. Present so that setting CARRIER_API_PROVIDER to
    something unimplemented degrades honestly instead of failing at startup.
    """

    def __init__(self, provider: str):
        self.source = provider if _PROVIDER_PATTERN.match(provider or "") else PROVIDER_NONE

    def lookup(self, carrier: str, tracking_number: str) -> CarrierResult:
        logger.info("carrier provider has no adapter provider=%s", self.source)
        return unavailable(self.source)


def build_client(config: CarrierConfig, session: Any | None = None) -> CarrierClient:
    """The one factory for a carrier client.

    Returns a client that contacts nothing whenever the connector is off,
    has no key, or names a provider with no adapter.
    """
    if not config.enabled:
        return NullCarrierClient()
    if not config.api_key:
        logger.info("carrier connector enabled without a key; lookups are unavailable")
        return NullCarrierClient()
    if config.provider != PROVIDER_AFTERSHIP:
        return StubCarrierClient(config.provider)
    return AfterShipCarrierClient(
        api_key=config.api_key, timeout_seconds=config.timeout_seconds, session=session
    )


# -- cache, cap and retries ---------------------------------------------


@dataclass
class _CacheEntry:
    result: CarrierResult
    stored_at: float


class CarrierLookup:
    """A client plus the three guards every lookup goes through.

    - a per-tracking-number cache with a TTL, so opening the same case twice
      costs one call;
    - a global hourly cap, enforced here rather than trusted to the
      provider's own limiter;
    - retries with exponential backoff, capped at MAX_ATTEMPTS attempts.

    A refusal from any guard is a normal `unavailable` result. Nothing here
    raises, so a carrier problem can never become a pipeline problem.
    """

    def __init__(
        self,
        client: CarrierClient | None = None,
        config: CarrierConfig | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.config = config or CarrierConfig()
        self._client = client if client is not None else build_client(self.config)
        self._clock = clock
        self._sleep = sleep
        self._cache: dict[tuple[str, str], _CacheEntry] = {}
        self._calls: deque[float] = deque()

    @property
    def enabled(self) -> bool:
        return bool(self.config.enabled)

    @property
    def provider(self) -> str:
        return getattr(self._client, "source", self.config.provider)

    # -- guards ----------------------------------------------------------

    def _cap_reached(self) -> bool:
        """True when this hour's lookups are spent. Prunes as it goes."""
        cutoff = self._clock() - 3600.0
        while self._calls and self._calls[0] < cutoff:
            self._calls.popleft()
        return len(self._calls) >= max(int(self.config.max_lookups_per_hour), 0)

    def lookups_this_hour(self) -> int:
        self._cap_reached()
        return len(self._calls)

    def cached(self, carrier: str, tracking_number: str) -> CarrierResult | None:
        """A live cache entry for this pair, or None."""
        key = _cache_key(carrier, tracking_number)
        if key is None:
            return None
        entry = self._cache.get(key)
        if entry is None:
            return None
        if self._clock() - entry.stored_at >= self.config.cache_ttl_seconds:
            del self._cache[key]
            return None
        return entry.result

    # -- the lookup ------------------------------------------------------

    def lookup(self, carrier: Any, tracking_number: Any) -> CarrierResult:
        """Look this shipment up, or say unavailable and why in the log."""
        if not self.config.enabled:
            return unavailable(PROVIDER_NONE)

        key = _cache_key(carrier, tracking_number)
        if key is None:
            # Prose, an empty value or something not a string. No request.
            logger.info("carrier lookup skipped: tracking key failed validation")
            return unavailable(self.provider)

        hit = self.cached(*key)
        if hit is not None:
            return hit

        if self._cap_reached():
            logger.warning(
                "carrier lookup capped provider=%s limit=%s per hour",
                self.provider,
                self.config.max_lookups_per_hour,
            )
            return unavailable(self.provider)

        self._calls.append(self._clock())
        result = self._attempt(*key)

        # Only a real answer is cached. Caching "unavailable" for an hour
        # would turn one provider blip into an hour of silence.
        if result.is_reported or result.status is CarrierStatus.NOT_FOUND:
            self._cache[key] = _CacheEntry(result=result, stored_at=self._clock())
        return result

    def _attempt(self, carrier: str, tracking_number: str) -> CarrierResult:
        """Up to MAX_ATTEMPTS tries, backing off between them."""
        result = unavailable(self.provider)
        for attempt in range(MAX_ATTEMPTS):
            try:
                result = self._client.lookup(carrier, tracking_number)
            except Exception as error:  # noqa: BLE001 - a client that raises is unavailable
                logger.warning(
                    "carrier client raised provider=%s exception=%s",
                    self.provider,
                    type(error).__name__,
                )
                result = unavailable(self.provider)

            if not isinstance(result, CarrierResult):
                result = unavailable(self.provider)

            if result.status is not CarrierStatus.UNAVAILABLE:
                return result
            if attempt < MAX_ATTEMPTS - 1:
                self._sleep(_BACKOFF_BASE_SECONDS * (2**attempt))
        return result


def _cache_key(carrier: Any, tracking_number: Any) -> tuple[str, str] | None:
    """The validated (carrier, number) pair, or None if either is unusable."""
    if not isinstance(carrier, str) or not isinstance(tracking_number, str):
        return None
    left, right = carrier.strip(), tracking_number.strip()
    if not _LOOKUP_KEY_PATTERN.match(left) or not _LOOKUP_KEY_PATTERN.match(right):
        return None
    return left, right


# -- onto the facts ------------------------------------------------------


def apply_carrier(facts: Facts, result: CarrierResult | None) -> Facts:
    """Overlay a carrier result onto Facts as carrier_reported facts.

    Adds exactly two names, both outside the PayPal fact allowlist and both
    stamped `carrier API` / `carrier_reported`. It never touches an existing
    fact, never promotes anything to confirmed, and never removes a fact.

    A lookup that failed or found nothing adds the names with status
    `unavailable` and no value, so the page can say "we asked and got
    nothing" without that absence becoming a negative claim.

    Called only from the console's lazy lookup path. With CARRIER_ENABLED
    off it is never called, and Facts are byte-for-byte what they were
    before this module existed.
    """
    if not isinstance(facts, Facts) or result is None:
        return facts

    status_code = result.status_code
    reported = result.is_reported and status_code is not None

    overlay = dict(facts.facts)
    overlay[CARRIER_STATUS] = Fact(
        name=CARRIER_STATUS,
        value=status_code if reported else None,
        status=FactStatus.CARRIER_REPORTED if reported else FactStatus.UNAVAILABLE,
        source=SOURCE_CARRIER_API,
        entity_id=facts.dispute_id,
        retrieved_at=facts.retrieved_at,
    )
    delivered = result.delivered_at if reported else None
    overlay[CARRIER_DELIVERED_AT] = Fact(
        name=CARRIER_DELIVERED_AT,
        value=delivered,
        status=(
            FactStatus.CARRIER_REPORTED
            if reported and delivered is not None
            else FactStatus.UNAVAILABLE
        ),
        source=SOURCE_CARRIER_API,
        entity_id=facts.dispute_id,
        retrieved_at=facts.retrieved_at,
    )
    return Facts(
        dispute_id=facts.dispute_id, retrieved_at=facts.retrieved_at, facts=overlay
    )


def carrier_binding(result: CarrierResult | None) -> tuple[str | None, str | None]:
    """The carrier values an approval must be bound to.

    Returns (status code, checked_at) when the carrier actually reported
    something, and (None, None) otherwise -- including when the connector is
    off. An approval with no carrier binding keeps the id it has always had,
    so turning the flag on for the first time cannot invalidate a past
    approval retroactively; turning it on and then getting a *different*
    reading does, which is the point.
    """
    if result is None or not result.is_reported:
        return None, None
    return result.status_code, result.checked_at
