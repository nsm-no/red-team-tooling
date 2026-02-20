# NSM-FPP-20260218-001
# OPERATOR: LT Kristoffersen
# TIMESTAMP: 2026-02-20T08:25:31+01:00
# CLASSIFICATION: STRENGT FORTROLIG � TS
# HONEYTOKEN: This file contains unique identifier 0x7a9b3c8d
# LICENSE: MIT
"""
Stealth Browser Automation Module (REVISED)
Classification: TOP SECRET // FORSVARET // NOFORN
Author: VALKYRIE-7

Implements human-like browser interaction using Playwright with stealth enhancements.
Changes:
- Fixed Playwright resource leak (return playwright object, stop it in cleanup)
- Mouse click now accounts for page scroll
- Improved response waiting (polling instead of fixed delay)
- Clear localStorage/sessionStorage on cleanup
- Exception handling in random_tab_switch
- Optional browser health check in send_messages
"""

import logging
import random
import time
import math
from typing import List, Dict, Any, Optional, Tuple

from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext, ElementHandle, TimeoutError as PlaywrightTimeoutError

# Configure module logger
logger = logging.getLogger(__name__)

# Default user agent list (will be rotated if none provided)
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
]

def bezier_curve_points(start: Tuple[float, float], end: Tuple[float, float],
                        steps: int = 20, jitter: float = 5.0) -> List[Tuple[float, float]]:
    """
    Generate a Bézier curve path from start to end with some randomness.
    Uses a quadratic Bézier with a random control point offset.
    """
    # Random control point offset
    ctrl_x = (start[0] + end[0]) / 2 + random.uniform(-jitter, jitter)
    ctrl_y = (start[1] + end[1]) / 2 + random.uniform(-jitter, jitter)
    control = (ctrl_x, ctrl_y)

    points = []
    for t in range(steps + 1):
        t_norm = t / steps
        # Quadratic Bézier: B(t) = (1-t)^2 * P0 + 2*(1-t)*t * P1 + t^2 * P2
        x = (1 - t_norm)**2 * start[0] + 2 * (1 - t_norm) * t_norm * control[0] + t_norm**2 * end[0]
        y = (1 - t_norm)**2 * start[1] + 2 * (1 - t_norm) * t_norm * control[1] + t_norm**2 * end[1]
        points.append((x, y))
    return points

def human_click(page: Page, element: ElementHandle, config: Dict[str, Any]) -> None:
    """
    Simulate a human-like click: move mouse along Bézier curve, then click.
    Now accounts for page scroll offset.
    """
    if not config['stealth']['mouse']['enable_curves']:
        element.click()
        return

    # Get element bounding box
    bbox = element.bounding_box()
    if not bbox:
        # Fallback
        element.click()
        return

    # Get current scroll offset
    scroll = page.evaluate('({ x: window.scrollX, y: window.scrollY })')
    # Target center of element, adjusted for scroll
    target_x = bbox['x'] + bbox['width'] / 2 - scroll['x']
    target_y = bbox['y'] + bbox['height'] / 2 - scroll['y']

    # Get current mouse position (approximate: viewport center)
    viewport = page.viewport_size
    start_x = viewport['width'] / 2 if viewport else 500
    start_y = viewport['height'] / 2 if viewport else 500

    steps = config['stealth']['mouse'].get('steps', 20)
    path = bezier_curve_points((start_x, start_y), (target_x, target_y), steps)

    # Move mouse along path with small delays
    for x, y in path:
        page.mouse.move(x, y)
        time.sleep(random.uniform(0.01, 0.03))  # tiny delay between moves

    # Slight random delay before click
    time.sleep(random.uniform(0.1, 0.3))
    element.click()

def human_type(page: Page, selector: str, text: str, config: Dict[str, Any]) -> None:
    """
    Type text into an input field with per-character random delays.
    """
    element = page.wait_for_selector(selector, state="attached")
    element.click()  # focus

    min_delay = config['stealth']['typing']['min_delay_ms'] / 1000.0
    max_delay = config['stealth']['typing']['max_delay_ms'] / 1000.0

    for char in text:
        page.keyboard.type(char)
        time.sleep(random.uniform(min_delay, max_delay))

def random_scroll(page: Page, probability: float = 0.3) -> None:
    """Randomly scroll the page up/down to simulate human behavior."""
    if random.random() > probability:
        return
    # Random scroll distance
    scroll_y = random.randint(100, 500)
    page.evaluate(f"window.scrollBy(0, {scroll_y})")
    time.sleep(random.uniform(0.5, 1.5))
    # Maybe scroll back a bit
    if random.random() < 0.5:
        page.evaluate(f"window.scrollBy(0, -{random.randint(50, 200)})")
        time.sleep(random.uniform(0.3, 0.8))

def random_tab_switch(page: Page, context: BrowserContext, probability: float = 0.1) -> None:
    """
    Randomly open a new tab, switch to it briefly, then come back.
    This mimics human multitasking.
    """
    if random.random() > probability:
        return
    try:
        # Open a new blank tab
        new_page = context.new_page()
        new_page.goto("about:blank")
        time.sleep(random.uniform(1.0, 2.0))
        new_page.close()
    except Exception as e:
        logger.warning(f"Tab switch failed (non-critical): {e}")

def check_browser_health(page: Page) -> bool:
    """
    Quick check to see if the page is still responsive.
    Returns True if healthy, False otherwise.
    """
    try:
        page.evaluate("1+1", timeout=5000)
        return True
    except:
        return False

def init_browser(config: Dict[str, Any]) -> Tuple[Any, Browser, BrowserContext, Page]:
    """
    Initialize a stealth browser instance with configured options.
    Returns (playwright, browser, context, page) for use in sending messages.
    """
    logger.info("Initializing browser")
    playwright = sync_playwright().start()
    browser_type = playwright.chromium  # Could be configurable

    # Launch options
    launch_options = {
        "headless": config['browser'].get('headless', False),
        "args": [
            "--disable-blink-features=AutomationControlled",
            "--disable-automation",
            "--no-sandbox",
            "--disable-setuid-sandbox"
        ]
    }

    # Proxy support
    if config['browser'].get('proxy'):
        launch_options["proxy"] = {"server": config['browser']['proxy']}

    browser = browser_type.launch(**launch_options)

    # Context options
    context_options = {
        "ignore_https_errors": True,
        "viewport": {"width": 1280, "height": 800},
        "user_agent": config['browser'].get('user_agent') or random.choice(DEFAULT_USER_AGENTS)
    }

    if config['browser'].get('incognito', True):
        context_options["storage_state"] = None  # incognito

    context = browser.new_context(**context_options)
    page = context.new_page()

    # Stealth: override navigator.webdriver
    page.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined
        });
    """)

    logger.info(f"Browser initialized (user-agent: {context_options['user_agent']})")
    return playwright, browser, context, page

def send_messages(browser_tuple: Tuple[Any, Browser, BrowserContext, Page],
                  messages: List[Dict[str, str]],
                  config: Dict[str, Any]) -> List[str]:
    """
    Send a sequence of messages (multi-turn) to the target chat interface.
    Each message is a dict with 'role' (user) and 'content'.
    Returns list of response texts (one per assistant turn).
    """
    playwright, browser, context, page = browser_tuple
    target_config = config['target']
    stealth_config = config['stealth']

    # Check browser health
    if not check_browser_health(page):
        logger.warning("Browser seems unresponsive; attempting to reload page")
        try:
            page.reload(timeout=30000)
            time.sleep(2)
        except:
            # If reload fails, we cannot continue; raise exception
            raise RuntimeError("Browser is dead and cannot be recovered")

    # Navigate to target URL if not already there
    if page.url != target_config['url']:
        logger.info(f"Navigating to {target_config['url']}")
        page.goto(target_config['url'])
        time.sleep(random.uniform(2, 4))  # initial load delay

    responses = []

    for idx, msg in enumerate(messages):
        if msg['role'] != 'user':
            continue  # only user messages

        logger.debug(f"Sending message {idx+1}/{len(messages)}")

        # Random scroll before typing
        if stealth_config['scroll']['enabled']:
            random_scroll(page, stealth_config['scroll']['probability'])

        # Random tab switch (only occasionally)
        if stealth_config['tab_switch']['enabled']:
            random_tab_switch(page, context, stealth_config['tab_switch']['probability'])

        # Find input element and type
        input_selector = target_config['input_selector']
        send_selector = target_config['send_selector']
        response_selector = target_config['response_selector']

        # Before sending, count current responses
        try:
            prev_responses = page.query_selector_all(response_selector)
            prev_count = len(prev_responses)
        except:
            prev_count = 0

        # Human-like typing
        human_type(page, input_selector, msg['content'], config)

        # Random pause before sending
        time.sleep(random.uniform(1, 3))

        # Click send button with human-like mouse movement
        send_button = page.wait_for_selector(send_selector, state="attached")
        human_click(page, send_button, config)

        # Poll for new response
        start_time = time.time()
        timeout = 30  # seconds
        new_response = ""
        while time.time() - start_time < timeout:
            time.sleep(0.5)  # poll interval
            try:
                current_responses = page.query_selector_all(response_selector)
                current_count = len(current_responses)
                if current_count > prev_count:
                    # New response appeared; get the latest one
                    new_response = current_responses[-1].inner_text()
                    logger.debug(f"Response received after {time.time()-start_time:.1f}s")
                    break
            except:
                pass

        if not new_response:
            logger.warning(f"No new response detected within {timeout}s")
        responses.append(new_response)

        # Pause between turns
        time.sleep(random.uniform(2, 5))

    return responses

def cleanup_browser(browser_tuple: Tuple[Any, Browser, BrowserContext, Page],
                    config: Dict[str, Any]) -> None:
    """
    Close browser, clear all storage, and stop Playwright.
    """
    playwright, browser, context, page = browser_tuple
    if config['stealth']['session_cleanup'].get('clear_cache_on_exit', True):
        try:
            context.clear_cookies()
            # Clear localStorage and sessionStorage
            page.evaluate("localStorage.clear(); sessionStorage.clear();")
            logger.debug("Cookies and storage cleared")
        except Exception as e:
            logger.warning(f"Storage cleanup failed: {e}")
    try:
        browser.close()
        logger.info("Browser closed")
    except Exception as e:
        logger.warning(f"Browser close failed: {e}")
    try:
        playwright.stop()
        logger.info("Playwright stopped")
    except Exception as e:
        logger.warning(f"Playwright stop failed: {e}")
