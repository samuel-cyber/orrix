"""Records demo clips of the HOSTED Orrix console for a demo video.

Everything in this script runs against https://orrix.onrender.com. It never
starts the app locally and never touches a local database -- there is
nothing here that imports orrix at all.

Usage:

    python scripts/record_demo.py --dispute PP-R-XXXX \\
        --only 01_landing,02_overview,03_cases,04_case_read

    python scripts/record_demo.py --dispute PP-R-YYYY --approve \\
        --only 05_seller_input,06_payload,07_approve,08_audit,09_lab,10_evaluation

Without --approve the script never clicks "Approve and submit evidence".
That click is irreversible against the hosted sandbox, so it is gated by a
flag that must be typed on purpose, every time.

The admin password comes from ORRIX_DEMO_PASSWORD in the local .env and is
never printed, logged, or written to a file. A fresh, unrecorded sign-in
produces demo/state.json (a Playwright storage state -- the session cookie
and CSRF token, not the password), and every scene after that loads from
that file rather than signing in again on camera.
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable

from dotenv import load_dotenv
from playwright.sync_api import Locator, Page, TimeoutError as PlaywrightTimeoutError, sync_playwright

BASE_URL = "https://orrix.onrender.com"

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = REPO_ROOT / "demo"
RAW_DIR = DEMO_DIR / "raw"
STATE_PATH = DEMO_DIR / "state.json"

VIEWPORT = {"width": 1920, "height": 1080}

DEFAULT_CARRIER = "DHL"
DEFAULT_TRACKING = "1Z999AA10123456784"

# The app's dark theme is the one this console is designed for, but a fresh
# Playwright context reports prefers-color-scheme: light by default, and
# theme.js (orrix/web/static/theme.js) falls back to that OS preference
# whenever no stored choice exists -- which every fresh context starts as.
# That is what rendered every earlier clip in the light theme.
#
# Two layers, matching how theme.js itself resolves a theme:
#   1. color_scheme="dark" on the browser context, so matchMedia and any
#      @media (prefers-color-scheme) CSS rule see dark.
#   2. An init script that writes the same localStorage key theme.js reads
#      (orrix.theme.v1) and sets data-theme directly, so the choice holds
#      even if something about (1) does not apply -- belt and suspenders,
#      not a guess about which layer actually matters.
# The init script runs before any page script on every navigation in the
# context, so it always wins the race against theme.js rather than fighting
# it after the fact.
THEME_STORAGE_KEY = "orrix.theme.v1"
FORCE_DARK_INIT_SCRIPT = f"""
try {{ window.localStorage.setItem({THEME_STORAGE_KEY!r}, 'dark'); }} catch (e) {{}}
document.documentElement.setAttribute('data-theme', 'dark');
document.documentElement.setAttribute('data-resolved-theme', 'dark');
"""

# Every scene the --only flag may select, in the fixed order they run.
SCENE_NAMES = (
    "01_landing",
    "02_overview",
    "03_cases",
    "04_case_read",
    "05_seller_input",
    "06_payload",
    "07_approve",
    "08_audit",
    "09_lab",
    "10_evaluation",
)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("record_demo")


class DemoError(RuntimeError):
    """Something about the recording setup is wrong. Stop, don't guess."""


# -- pacing helpers --------------------------------------------------------
#
# Every helper here exists so a scene reads as a person using the app, not a
# script poking at it: the mouse glides to a target before it clicks, pages
# get a beat to settle, and scrolling moves in small steps.


def move_to(page: Page, locator: Locator, steps: int = 25) -> tuple[float, float]:
    """Glide the mouse to the centre of an element and return that point."""
    locator.scroll_into_view_if_needed()
    box = locator.bounding_box()
    if box is None:
        raise DemoError(f"no bounding box for {locator}; is it visible?")
    x = box["x"] + box["width"] / 2
    y = box["y"] + box["height"] / 2
    page.mouse.move(x, y, steps=steps)
    return x, y


def click_smoothly(page: Page, locator: Locator) -> None:
    move_to(page, locator)
    page.wait_for_timeout(150)
    locator.click()


def select_smoothly(page: Page, locator: Locator, value: str) -> None:
    move_to(page, locator)
    page.wait_for_timeout(150)
    locator.select_option(value)


def fill_smoothly(page: Page, locator: Locator, value: str) -> None:
    move_to(page, locator)
    page.wait_for_timeout(150)
    locator.click()
    locator.fill(value)


def after_load(page: Page) -> None:
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1500)


def after_action(page: Page) -> None:
    page.wait_for_timeout(1200)


def hold(page: Page, seconds: float) -> None:
    page.wait_for_timeout(int(seconds * 1000))


def wheel_steps(page: Page, total_px: int, step: int = 120, interval_ms: int = 60) -> None:
    """Scroll in small wheel steps, never a jump, over whatever is under the pointer."""
    direction = 1 if total_px >= 0 else -1
    remaining = abs(total_px)
    while remaining > 0:
        delta = min(step, remaining)
        page.mouse.wheel(0, direction * delta)
        page.wait_for_timeout(interval_ms)
        remaining -= delta


def slow_scroll_to_bottom(page: Page, step: int = 120, interval_ms: int = 60, max_steps: int = 400) -> None:
    previous = -1
    for _ in range(max_steps):
        page.mouse.wheel(0, step)
        page.wait_for_timeout(interval_ms)
        current = page.evaluate("window.scrollY")
        at_bottom = page.evaluate(
            "window.scrollY + window.innerHeight >= document.body.scrollHeight - 2"
        )
        if at_bottom or current == previous:
            break
        previous = current


def slow_scroll_to_top(page: Page, step: int = 120, interval_ms: int = 60, max_steps: int = 400) -> None:
    previous = -1
    for _ in range(max_steps):
        page.mouse.wheel(0, -step)
        page.wait_for_timeout(interval_ms)
        current = page.evaluate("window.scrollY")
        if current <= 0 or current == previous:
            break
        previous = current


def hover_and_scroll_within(page: Page, locator: Locator, total_px: int = 300) -> bool:
    """Scroll slowly inside an element if it overflows. Returns whether it did.

    Hovering first means the wheel event lands on the scrollable element
    itself, the same way a person scrolling a long quote box would.
    """
    locator.scroll_into_view_if_needed()
    move_to(page, locator)
    overflowing = locator.evaluate("(el) => el.scrollHeight > el.clientHeight + 2")
    if overflowing:
        wheel_steps(page, total_px)
    return bool(overflowing)


def panel(page: Page, heading: str) -> Locator:
    """The card or section whose own <h2> reads exactly `heading`."""
    return page.locator(f"section.card:has(h2:text-is('{heading}'))").first


def wait_for_selector_soft(page: Page, selector: str, timeout: int, what: str) -> bool:
    """wait_for_selector that logs and continues rather than failing the scene.

    Used for elements whose presence depends on the data in the dispute the
    caller picked (a discrepancy, a preset result) rather than on the page
    itself being broken.
    """
    try:
        page.wait_for_selector(selector, timeout=timeout)
        return True
    except PlaywrightTimeoutError:
        logger.warning("  (expected but not found: %s -- continuing)", what)
        return False


# -- setup ------------------------------------------------------------------


def read_demo_password() -> str:
    """ORRIX_DEMO_PASSWORD from the local .env. Never printed, never logged."""
    load_dotenv(REPO_ROOT / ".env")
    password = os.environ.get("ORRIX_DEMO_PASSWORD")
    if not password:
        raise DemoError(
            "ORRIX_DEMO_PASSWORD is not set in .env. Add it (the hosted app's "
            "admin password) and try again. Never pass it on the command line "
            "-- it would land in shell history."
        )
    return password


def sign_in_and_save_state(playwright, password: str) -> None:
    """One unrecorded sign-in. Every scene context loads the state this writes.

    A fresh context with no storage_state, so this never reuses a stale
    cookie from a previous run. Scoped to the login form specifically: the
    app shell's own "Sign out" form also has a type=submit button and sits
    earlier in the DOM, so an unscoped selector posts /logout instead.
    """
    browser = playwright.chromium.launch(headless=False)
    try:
        context = browser.new_context(viewport=VIEWPORT, color_scheme="dark")
        # So the saved storage_state's localStorage already has the dark
        # choice recorded for this origin, and every later scene inherits it
        # even before its own init script runs.
        context.add_init_script(FORCE_DARK_INIT_SCRIPT)
        page = context.new_page()
        page.goto(f"{BASE_URL}/login", wait_until="networkidle")

        form = page.locator('form:has(input[type="password"])')
        form.locator('input[type="password"]').fill(password)
        with page.expect_navigation(wait_until="load", timeout=30000):
            form.locator('button[type="submit"]').click()

        if "/login" in page.url:
            raise DemoError(
                "sign-in did not leave /login -- check ORRIX_DEMO_PASSWORD "
                "against the hosted app's admin password."
            )

        DEMO_DIR.mkdir(parents=True, exist_ok=True)
        context.storage_state(path=str(STATE_PATH))
        context.close()
    finally:
        browser.close()
    logger.info("signed in; storage state saved to %s", STATE_PATH.relative_to(REPO_ROOT))


def new_recorded_context(playwright_browser, name: str):
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    context = playwright_browser.new_context(
        storage_state=str(STATE_PATH),
        viewport=VIEWPORT,
        color_scheme="dark",
        record_video_dir=str(RAW_DIR),
        record_video_size=VIEWPORT,
    )
    # Redundant with the dark choice already in STATE_PATH's localStorage,
    # but cheap and makes every scene correct on its own regardless of what
    # state.json happens to hold.
    context.add_init_script(FORCE_DARK_INIT_SCRIPT)
    return context


# -- scenes -------------------------------------------------------------
#
# Each scene gets its own freshly recorded context and navigates straight to
# its own URL, rather than chaining off the previous scene's navigation, so
# any scene can be recorded alone via --only without depending on another.


def scene_01_landing(page: Page, args: argparse.Namespace) -> None:
    page.goto(f"{BASE_URL}/", wait_until="networkidle")
    after_load(page)
    slow_scroll_to_bottom(page)
    hold(page, 1)
    slow_scroll_to_top(page)


def scene_02_overview(page: Page, args: argparse.Namespace) -> None:
    page.goto(f"{BASE_URL}/overview", wait_until="networkidle")
    after_load(page)
    hold(page, 4)


def scene_03_cases(page: Page, args: argparse.Namespace) -> None:
    page.goto(f"{BASE_URL}/cases", wait_until="networkidle")
    after_load(page)
    page.wait_for_selector(".ag-center-cols-container .ag-row", timeout=20000)
    hold(page, 2)

    link = page.get_by_role("link", name=args.dispute, exact=True)
    if link.count() == 0:
        raise DemoError(
            f"no row for dispute {args.dispute!r} on /cases. Check the id is "
            f"stored on the hosted app, or pick one from the grid."
        )
    move_to(page, link)
    hold(page, 1)
    click_smoothly(page, link)
    page.wait_for_load_state("networkidle")


def scene_04_case_read(page: Page, args: argparse.Namespace) -> None:
    page.goto(f"{BASE_URL}/cases/{args.dispute}", wait_until="networkidle")
    after_load(page)

    buyer_box = page.locator("section.lane.lane-untrusted")
    overflowed = hover_and_scroll_within(page, buyer_box, total_px=240)
    hold(page, 4 if not overflowed else 2)

    facts = page.locator("section.lane.lane-trusted")
    facts.scroll_into_view_if_needed()
    move_to(page, facts)
    wheel_steps(page, 360)
    after_action(page)

    decision = panel(page, "Orrix decision")
    decision.scroll_into_view_if_needed()
    move_to(page, decision)
    hold(page, 3)

    reader = panel(page, "Reader result")
    reader.scroll_into_view_if_needed()
    move_to(page, reader)
    hold(page, 4)


def scene_05_seller_input(page: Page, args: argparse.Namespace) -> None:
    page.goto(f"{BASE_URL}/cases/{args.dispute}", wait_until="networkidle")
    after_load(page)

    carrier_field = page.locator("#carrier")
    carrier_field.scroll_into_view_if_needed()
    fill_smoothly(page, carrier_field, args.carrier)
    after_action(page)

    tracking_field = page.locator("#tracking_number")
    fill_smoothly(page, tracking_field, args.tracking)
    after_action(page)

    status_select = page.locator("#delivery_status")
    select_smoothly(page, status_select, "DELIVERED")
    after_action(page)

    save_button = page.locator('form[action*="/seller-input"] button[type="submit"]')
    with page.expect_navigation(wait_until="load", timeout=30000):
        click_smoothly(page, save_button)
    after_load(page)

    conflict = page.locator(".alert:has(ul.discrepancy-facts)")
    if wait_for_selector_soft(
        page, ".alert:has(ul.discrepancy-facts)", 5000, "the discrepancy banner"
    ):
        conflict.scroll_into_view_if_needed()
        move_to(page, conflict)
        hold(page, 3)

    decision = panel(page, "Orrix decision")
    decision.scroll_into_view_if_needed()
    move_to(page, decision)
    hold(page, 3)


def scene_06_payload(page: Page, args: argparse.Namespace) -> None:
    page.goto(f"{BASE_URL}/cases/{args.dispute}", wait_until="networkidle")
    after_load(page)

    details = page.locator(
        "details.payload-details:has-text('Exactly what will be sent')"
    )
    details.scroll_into_view_if_needed()
    click_smoothly(page, details.locator("summary"))
    hold(page, 4)


def scene_07_approve(page: Page, args: argparse.Namespace) -> None:
    page.goto(f"{BASE_URL}/cases/{args.dispute}", wait_until="networkidle")
    after_load(page)

    already = page.locator("[data-evidence-submitted]")
    if already.count() > 0:
        logger.warning(
            "  dispute %s already carries an executed approval; showing the "
            "submitted state without clicking Approve again.",
            args.dispute,
        )
        already.scroll_into_view_if_needed()
        move_to(page, already)
        hold(page, 3)
        return

    approve_form = page.locator("form.approve-form")
    if approve_form.count() == 0:
        raise DemoError(
            f"neither an approve form nor an executed-approval state was "
            f"found for {args.dispute}; the case page may not have loaded."
        )

    approve_button = approve_form.locator('button:has-text("Approve and submit evidence")')
    approve_button.scroll_into_view_if_needed()
    if approve_button.is_disabled():
        raise DemoError(
            f"the Approve button is disabled for {args.dispute} (policy does "
            f"not currently permit provide_evidence, or no payload exists). "
            f"Pick a dispute that is actually ready, or check the Seller "
            f"input / Payload scenes ran first."
        )

    move_to(page, approve_button)
    hold(page, 1)
    # Irreversible against the real hosted sandbox. Reaching this line at
    # all already required --approve; this is the one click that flag exists
    # to gate.
    with page.expect_navigation(wait_until="load", timeout=30000):
        approve_button.click()

    page.wait_for_selector('.alert:has-text("Execution result")', timeout=30000)
    hold(page, 4)

    submitted = page.locator("[data-evidence-submitted]")
    submitted.scroll_into_view_if_needed()
    move_to(page, submitted)
    hold(page, 3)


def scene_08_audit(page: Page, args: argparse.Namespace) -> None:
    page.goto(f"{BASE_URL}/audit", wait_until="networkidle")
    after_load(page)

    verify_button = page.locator('form[action="/audit/verify"] button[type="submit"]')
    click_smoothly(page, verify_button)

    page.wait_for_function(
        "document.querySelector('[data-chain-title]')?.textContent.includes('Chain intact')",
        timeout=20000,
    )
    hold(page, 3)

    first_entry = page.locator("#audit-timeline details.payload-details").first
    first_entry.scroll_into_view_if_needed()
    click_smoothly(page, first_entry.locator("summary"))
    hold(page, 2)


def scene_09_lab(page: Page, args: argparse.Namespace) -> None:
    page.goto(f"{BASE_URL}/lab", wait_until="networkidle")
    after_load(page)

    preset_select = page.locator("#lab-preset")
    if preset_select.count() == 0:
        raise DemoError(
            "no preset select on /lab -- the hosted build may be missing "
            "orrix/web/lab_presets.json."
        )
    select_smoothly(page, preset_select, "authority_paypal_support")
    after_action(page)

    run_button = page.locator('form.lab-form button:has-text("Run both lanes")')
    move_to(page, run_button)
    hold(page, 1)
    with page.expect_navigation(wait_until="load", timeout=90000):
        # click()'s own built-in navigation wait defaults to 30s and fires
        # before the surrounding expect_navigation's 90s gets a chance --
        # that mismatch is what timed this scene out on a slow model call.
        # Both waits need the same ceiling.
        run_button.click(timeout=90000)

    page.wait_for_selector("section.lanes[aria-label='Comparison result']", timeout=90000)
    lanes = page.locator("section.lanes[aria-label='Comparison result']")
    lanes.scroll_into_view_if_needed()
    move_to(page, lanes)
    hold(page, 5)


def scene_10_evaluation(page: Page, args: argparse.Namespace) -> None:
    page.goto(f"{BASE_URL}/evaluation", wait_until="networkidle")
    after_load(page)
    slow_scroll_to_bottom(page)


SCENES: dict[str, Callable[[Page, argparse.Namespace], None]] = {
    "01_landing": scene_01_landing,
    "02_overview": scene_02_overview,
    "03_cases": scene_03_cases,
    "04_case_read": scene_04_case_read,
    "05_seller_input": scene_05_seller_input,
    "06_payload": scene_06_payload,
    "07_approve": scene_07_approve,
    "08_audit": scene_08_audit,
    "09_lab": scene_09_lab,
    "10_evaluation": scene_10_evaluation,
}


# -- recording, renaming, converting -----------------------------------


def run_scene(playwright_browser, name: str, args: argparse.Namespace) -> Path | None:
    logger.info("recording %s ...", name)
    context = new_recorded_context(playwright_browser, name)
    page = context.new_page()
    try:
        SCENES[name](page, args)
        hold(page, 2)  # the final-view hold, on top of whatever the scene already held
    finally:
        video = page.video
        context.close()

    if video is None:
        logger.warning("  no video captured for %s", name)
        return None
    raw_path = Path(video.path())
    final_name = f"{name}_{args.dispute}.webm"
    final_path = RAW_DIR / final_name
    raw_path.replace(final_path)
    return final_path


def convert_to_mp4(webm_path: Path) -> Path | None:
    mp4_path = webm_path.with_suffix(".mp4")
    try:
        subprocess.run(
            [
                "ffmpeg",
                "-y",
                "-loglevel",
                "error",
                "-i",
                str(webm_path),
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                "-r",
                "30",
                "-crf",
                "18",
                str(mp4_path),
            ],
            check=True,
            capture_output=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as error:
        logger.warning(
            "  ffmpeg conversion failed for %s (%s); keeping the .webm",
            webm_path.name,
            type(error).__name__,
        )
        return None
    webm_path.unlink()
    return mp4_path


def probe_duration(path: Path) -> str:
    try:
        completed = subprocess.run(
            [
                "ffprobe",
                "-v",
                "error",
                "-show_entries",
                "format=duration",
                "-of",
                "default=noprint_wrappers=1:nokey=1",
                str(path),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return f"{float(completed.stdout.strip()):.1f}s"
    except (FileNotFoundError, subprocess.CalledProcessError, ValueError):
        return "unknown"


# -- CLI ------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dispute", required=True, help="dispute id to record, e.g. PP-R-XXXX")
    parser.add_argument("--carrier", default=DEFAULT_CARRIER)
    parser.add_argument("--tracking", default=DEFAULT_TRACKING)
    parser.add_argument(
        "--approve",
        action="store_true",
        help="allow the 07_approve scene to click Approve and submit evidence. "
        "Irreversible against the hosted sandbox.",
    )
    parser.add_argument(
        "--only",
        default=",".join(SCENE_NAMES),
        help="comma-separated scene names to record (default: all)",
    )
    args = parser.parse_args(argv)

    requested = [name.strip() for name in args.only.split(",") if name.strip()]
    unknown = sorted(set(requested) - set(SCENE_NAMES))
    if unknown:
        raise DemoError(f"unknown scene name(s): {unknown}. Valid: {list(SCENE_NAMES)}")
    # Keep the fixed order regardless of how --only listed them.
    args.scenes = [name for name in SCENE_NAMES if name in requested]
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if "07_approve" in args.scenes and not args.approve:
        logger.warning(
            "07_approve was requested but --approve was not passed; skipping "
            "it. The Approve click is irreversible against the hosted "
            "sandbox and only runs with --approve."
        )
        args.scenes = [name for name in args.scenes if name != "07_approve"]

    password = read_demo_password()

    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []

    with sync_playwright() as playwright:
        sign_in_and_save_state(playwright, password)
        del password  # nothing after this point needs it

        browser = playwright.chromium.launch(headless=False)
        try:
            for name in args.scenes:
                path = run_scene(browser, name, args)
                if path is not None:
                    written.append(path)
        finally:
            browser.close()

    final_files: list[Path] = []
    for webm_path in written:
        mp4_path = convert_to_mp4(webm_path)
        final_files.append(mp4_path or webm_path)

    logger.info("")
    logger.info("wrote %d file(s):", len(final_files))
    for path in final_files:
        logger.info("  %s  (%s)", path.relative_to(REPO_ROOT), probe_duration(path))

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except DemoError as error:
        logger.error("error: %s", error)
        sys.exit(1)
