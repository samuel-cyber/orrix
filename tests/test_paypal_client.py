"""Client tests against a fake session. Nothing leaves the process."""

from __future__ import annotations

import pytest

from orrix.paypal import SANDBOX_BASE_URL, PayPalError, SandboxPayPalClient

DISPUTES_URL = f"{SANDBOX_BASE_URL}/v1/customer/disputes"


class FakeResponse:
    def __init__(self, payload, status_code=200, debug_id="dbg-1"):
        self._payload = payload
        self.status_code = status_code
        self.headers = {"Paypal-Debug-Id": debug_id}

    def json(self):
        return self._payload


class FakeSession:
    """Serves queued pages and records the URLs asked for."""

    def __init__(self, pages):
        self._pages = list(pages)
        self.get_urls: list[str] = []

    def post(self, url, **kwargs):
        # Only the token call is expected here.
        return FakeResponse({"access_token": "fake-token", "expires_in": 32400})

    def get(self, url, **kwargs):
        self.get_urls.append(url)
        if not self._pages:
            return FakeResponse({"items": []})
        return self._pages.pop(0)


def build_client(session):
    return SandboxPayPalClient(
        client_id="fake-id",
        client_secret="fake-secret",
        webhook_id="WH-FAKE",
        session=session,
    )


def page(items, next_href=None):
    links = [{"rel": "self", "href": DISPUTES_URL, "method": "GET"}]
    if next_href:
        links.append({"rel": "next", "href": next_href, "method": "GET"})
    return FakeResponse({"items": items, "links": links})


def test_list_disputes_follows_next_links():
    session = FakeSession(
        [
            page([{"dispute_id": "PP-D-1"}], next_href=f"{DISPUTES_URL}?page=2"),
            page([{"dispute_id": "PP-D-2"}], next_href=f"{DISPUTES_URL}?page=3"),
            page([{"dispute_id": "PP-D-3"}]),
        ]
    )

    disputes = build_client(session).list_disputes()

    assert [d["dispute_id"] for d in disputes] == ["PP-D-1", "PP-D-2", "PP-D-3"]
    assert len(session.get_urls) == 3
    assert session.get_urls[1] == f"{DISPUTES_URL}?page=2"


def test_list_disputes_stops_at_the_page_cap():
    # Every page points to a new next link, so only the cap ends this.
    pages = [
        page([{"dispute_id": f"PP-D-{i}"}], next_href=f"{DISPUTES_URL}?page={i + 1}")
        for i in range(1, 60)
    ]
    session = FakeSession(pages)

    disputes = build_client(session).list_disputes(max_pages=5)

    assert len(session.get_urls) == 5
    assert len(disputes) == 5


def test_list_disputes_breaks_a_pagination_loop():
    # Two pages pointing at each other must not spin to the cap.
    session = FakeSession(
        [
            page([{"dispute_id": "PP-D-1"}], next_href=f"{DISPUTES_URL}?page=2"),
            page([{"dispute_id": "PP-D-2"}], next_href=f"{DISPUTES_URL}?page=2"),
        ]
    )

    build_client(session).list_disputes(max_pages=20)

    assert len(session.get_urls) == 2


def test_list_disputes_ignores_an_offsite_next_link():
    session = FakeSession(
        [page([{"dispute_id": "PP-D-1"}], next_href="https://evil.example.com/v1/customer/disputes")]
    )

    disputes = build_client(session).list_disputes()

    assert len(disputes) == 1
    assert session.get_urls == [DISPUTES_URL]


def test_list_disputes_raises_with_status_and_debug_id():
    session = FakeSession([FakeResponse({"name": "INTERNAL"}, status_code=500, debug_id="dbg-500")])

    with pytest.raises(PayPalError) as caught:
        build_client(session).list_disputes()

    assert caught.value.status_code == 500
    assert caught.value.debug_id == "dbg-500"


def test_list_disputes_tolerates_a_missing_items_key():
    session = FakeSession([FakeResponse({"links": []})])

    assert build_client(session).list_disputes() == []


def test_token_is_cached_between_calls():
    session = FakeSession([page([]), page([])])
    client = build_client(session)

    client.list_disputes()
    client.list_disputes()

    # One token fetch, reused for both listings.
    assert client.token() == "fake-token"


def test_live_base_url_is_refused():
    with pytest.raises(ValueError, match="sandbox only"):
        SandboxPayPalClient(base_url="https://api-m.paypal.com")
