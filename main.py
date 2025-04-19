#!/usr/bin/env python3
"""
Batch-capture URLs to AVIF screenshots via the Urlbox API, with built-in rate-limit handling,
error logging, and parallel execution.

Requirements:
  - Python 3.6+
  - requests
  - python-dotenv

Usage:
  Set environment variables URLBOX_PUBLIC_KEY and URLBOX_SECRET_KEY (e.g. via a `.env` file).
  Run:
    python batch_capture.py [--dry-run] [--workers N] [--count M] [--mobile]

Outputs:
  - Saves AVIF screenshots in `screenshots/` directory.
  - Tracks processed URLs in `data/processed-urls.txt`.
  - Tracks errored URLs in `data/errored-urls.txt`.
"""

import os
import hmac
import json
import argparse
import threading
import sys
import time
from hashlib import sha256
from urllib.parse import urlencode

import requests
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

# ----------------------------------------------------------------------------
# Global rate limit state (protected by a lock)
# ----------------------------------------------------------------------------
rate_limit = {
    "limit": None,  # Maximum requests per minute
    "remaining": None,  # Requests left in current window
    "reset": None,  # Epoch seconds when window resets
}
rate_limit_lock = threading.Lock()


def wait_for_rate_limit():
    """
    Pause execution if we've exhausted the rate-limit quota until reset time.
    """
    with rate_limit_lock:
        rem = rate_limit.get("remaining")
        reset_ts = rate_limit.get("reset")
    if rem is not None and rem <= 0 and reset_ts:
        now = time.time()
        sleep_time = reset_ts - now
        if sleep_time > 0:
            print(
                f"[RATE LIMIT] None remaining, sleeping for {sleep_time:.2f}s until reset."
            )
            time.sleep(sleep_time + 1)


def update_rate_limit_from_headers(headers):
    """
    Parse rate-limit headers from the HTTP response and update global state.

    Expected headers:
      - x-ratelimit-limit
      - x-ratelimit-remaining
      - x-ratelimit-reset
    """
    with rate_limit_lock:
        if "x-ratelimit-limit" in headers:
            rate_limit["limit"] = int(headers["x-ratelimit-limit"])
        if "x-ratelimit-remaining" in headers:
            rate_limit["remaining"] = int(headers["x-ratelimit-remaining"])
        if "x-ratelimit-reset" in headers:
            rate_limit["reset"] = int(headers["x-ratelimit-reset"])


def load_urls_from_json(path):
    """
    Load JSON file containing `websites` entries and return the first URL from each doc.

    Args:
        path (str): Path to the JSON file. Can contain a list or single object.
    Returns:
        List[str]: URLs extracted from the documents.
    Raises:
        FileNotFoundError: If the JSON file does not exist.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"JSON file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    docs = data if isinstance(data, list) else [data]
    urls = []
    for doc in docs:
        websites = doc.get("websites")
        if isinstance(websites, list) and websites:
            first = websites[0]
            if isinstance(first, dict) and "url" in first:
                urls.append(first["url"])
            elif isinstance(first, str):
                urls.append(first)
        else:
            print(f"[WARN] No websites list or empty for document: {doc}")
    return urls


def load_list(path):
    """
    Read a file line-by-line and return non-empty lines, or an empty list if file is missing.

    Args:
        path (str): Path to the list file.
    Returns:
        List[str]: Non-empty lines from the file.
    """
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def append_line(path, line, lock):
    """
    Append a single line safely to a file, ensuring thread-safety via a lock.

    Args:
        path (str): File path to append to.
        line (str): Line content (newline appended automatically).
        lock (threading.Lock): Lock to synchronize writes.
    """
    with lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def save_screenshot_bytes(content, url, out_dir, suffix):
    """
    Save raw AVIF bytes to a sanitized filename based on the URL.

    Args:
        content (bytes): AVIF image data.
        url (str): Source URL (used to derive filename).
        out_dir (str): Directory to save into.
        suffix (str): Filename suffix (e.g., '-mobile').
    Returns:
        str: Full path to the saved file.
    """
    safe = url.replace("https://", "").replace("http://", "").replace("/", "_")
    fn = os.path.join(out_dir, f"{safe}{suffix}.avif")
    with open(fn, "wb") as img:
        img.write(content)
    return fn


def generate_urlbox_url(params):
    """
    Construct a signed Urlbox API URL for AVIF screenshot rendering.

    Uses HMAC-SHA256 with secret key to sign the querystring.

    Args:
        params (dict): Query parameters for the API call.
    Returns:
        str: Fully signed Urlbox request URL.
    Raises:
        RuntimeError: If API keys are missing from environment.
    """
    key = os.getenv("URLBOX_PUBLIC_KEY")
    sec = os.getenv("URLBOX_SECRET_KEY")
    if not key or not sec:
        raise RuntimeError("Missing URLBOX_PUBLIC_KEY/SECRET_KEY")
    qs = urlencode(params, doseq=True)
    token = hmac.new(sec.encode(), qs.encode(), sha256).hexdigest()
    return f"https://api.urlbox.com/v1/{key}/{token}/avif?{qs}"


def process_url(url, processed_file, errored_file, out_dir, lock, mobile):
    """
    Fetch a screenshot for a given URL (desktop or mobile) and record success or errors.

    Args:
        url (str): Webpage to capture.
        processed_file (str): File to log successful captures.
        errored_file (str): File to log failed URLs.
        out_dir (str): Directory to save screenshots.
        lock (threading.Lock): Lock for file operations.
        mobile (bool): Whether to capture mobile (_-mobile suffix).
    """
    base = {
        "url": url,
        "block_ads": "true",
        "hide_cookie_banners": "true",
        "wait_until": "mostrequestsfinished",
        "fail_on_4xx": "true",
        "fail_on_5xx": "true",
    }
    if mobile:
        suffix = "-mobile"
        params = {**base, "width": "390", "height": "844", "thumb_width": "200"}
    else:
        suffix = ""
        params = base

    signed = generate_urlbox_url(params)

    # Retry loop handling rate limits and errors
    while True:
        wait_for_rate_limit()
        resp = requests.get(signed, timeout=90)
        update_rate_limit_from_headers(resp.headers)

        if resp.status_code == 400:
            append_line(errored_file, url, lock)
            print(f"[ERROR 400] {url}")
            return
        if resp.status_code == 429:
            ra = resp.headers.get("Retry-After", "60")
            to_sleep = int(ra) if ra.isdigit() else 60
            print(f"[RATE LIMIT HIT] {url}, sleeping {to_sleep}s")
            time.sleep(to_sleep + 1)
            continue

        resp.raise_for_status()
        break

    # Save on success
    outpath = save_screenshot_bytes(resp.content, url, out_dir, suffix)
    print(f"[OK] {url} → {outpath}")
    append_line(processed_file, url + suffix, lock)


def main():
    """
    Entry point: parse CLI arguments, load URL lists, manage blacklist,
    and dispatch concurrent workers to capture screenshots.
    """
    load_dotenv()
    p = argparse.ArgumentParser(description="Batch-capture URLs to AVIF via Urlbox")
    p.add_argument(
        "--dry-run",
        "-n",
        action="store_true",
        help="Only process the first unprocessed URL and then exit",
    )
    p.add_argument(
        "--workers",
        "-w",
        type=int,
        default=5,
        help="Number of parallel workers (default: 5)",
    )
    p.add_argument(
        "--count",
        "-c",
        type=int,
        default=None,
        help="Limit the number of screenshots to process",
    )
    p.add_argument(
        "-m",
        "--mobile",
        action="store_true",
        help="Capture mobile-sized only (suffix '-mobile')",
    )
    args = p.parse_args()

    # File & directory settings
    json_file = "./data/urls.json"
    processed_file = "./data/processed-urls.txt"
    errored_file = "./data/errored-urls.txt"
    output_dir = "screenshots"
    os.makedirs(output_dir, exist_ok=True)

    all_urls = load_urls_from_json(json_file)
    done = set(load_list(processed_file))
    errored = set(load_list(errored_file))

    # Filter by mobile flag suffix
    if args.mobile:
        done = {u for u in done if u.endswith("-mobile")}
        errored = {u for u in errored if u.endswith("-mobile")}
        suffix = "-mobile"
    else:
        done = {u for u in done if not u.endswith("-mobile")}
        errored = {u for u in errored if not u.endswith("-mobile")}
        suffix = ""

    # Determine URLs to process
    to_process = [
        u for u in all_urls if (u + suffix) not in done and (u + suffix) not in errored
    ]

    # Respect blacklist prefixes if present
    blacklist_file = "./data/blacklist.txt"
    blacklist_prefixes = load_list(blacklist_file)
    if blacklist_prefixes:
        filtered = []
        for url in to_process:
            if any(url.startswith(prefix) for prefix in blacklist_prefixes):
                print(f"[SKIP] {url} (blacklisted)")
            else:
                filtered.append(url)
        to_process = filtered

    # Apply dry-run and count limits
    if args.dry_run:
        print("⚡ Dry run: will only process the first URL")
        to_process = to_process[:1]
    if args.count is not None:
        to_process = to_process[: args.count]

    if not to_process:
        print("No new URLs to process.")
        return

    # Launch thread pool
    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {
            ex.submit(
                process_url,
                url,
                processed_file,
                errored_file,
                output_dir,
                lock,
                args.mobile,
            ): url
            for url in to_process
        }
        try:
            for _ in as_completed(futures):
                pass
        except KeyboardInterrupt:
            print("\n[INFO] Cancelled, shutting down…")
            try:
                ex.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                ex.shutdown(wait=False)
            sys.exit(0)


if __name__ == "__main__":
    main()
