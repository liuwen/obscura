#!/usr/bin/env python3
"""Run one bounded Goodhope screenshot-and-coordinate Weatherstack attempt on Obscura.

The controller intentionally exposes no DOM, selectors, page text, JavaScript,
storage, or network bodies to the model. Screenshots stay in memory; the only
persisted output is a redacted, metadata-only evidence summary.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import re
import secrets
import signal
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import websockets


WIDTH = 1280
HEIGHT = 800
START_URL = "https://marketplace.apilayer.com/signup"
GOODHOPE_BASE_URL = "https://ghc-tyo.lvtu.in"
GOODHOPE_MODEL = "gpt-5.6-luna"
GOODHOPE_REASONING_EFFORT = "medium"
GOODHOPE_MAX_OUTPUT_TOKENS = 500
MAX_ACTIONS = 100
MAX_SECONDS = 1200
ALLOWED_HOSTS = frozenset(
    {"marketplace.apilayer.com", "weatherstack.com", "www.weatherstack.com"}
)
ALLOWED_KEYS = frozenset(
    {
        "Tab",
        "Enter",
        "Escape",
        "Backspace",
        "ArrowUp",
        "ArrowDown",
        "ArrowLeft",
        "ArrowRight",
        "Space",
    }
)
ACTION_FIELDS = {
    "click": frozenset({"action", "x", "y", "reason"}),
    "type": frozenset({"action", "value_ref", "reason"}),
    "keypress": frozenset({"action", "key", "reason"}),
    "scroll": frozenset({"action", "delta_y", "reason"}),
    "wait": frozenset({"action", "milliseconds", "reason"}),
    "finish": frozenset({"action", "reason"}),
}
TURNSTILE_HOST = "challenges.cloudflare.com"

SYSTEM_PROMPT = """You are the sole visual operator of a browser. You receive only a
current 1280x800 screenshot, a nonsecret URL, a goal, private value references,
and recent action outcomes. Return exactly one JSON action. Do not ask for or use
DOM, selectors, HTML, accessibility trees, JavaScript, page text, network calls,
direct signup APIs, or a CAPTCHA-solving service. Choose an action solely from
visible evidence. Never include private values in output.

Goal: create at most one APILayer marketplace account, then activate only the
free Weatherstack product and reach its API-key screen. Never select a paid plan,
trial, billing, checkout, payment, or another product. If an interactive
Cloudflare challenge or Turnstile is visibly blocking progress, stop immediately
with {"action":"finish","reason":"Cloudflare Turnstile visible: <short visible marker>"}.
If email verification is required, stop immediately with a short visible reason;
there is no email tool. Do not attempt a second account.

Schema:
- click: {"action":"click","x":integer,"y":integer,"reason":"short visible rationale"}
- type: {"action":"type","value_ref":"one offered reference","reason":"short visible rationale"}
- keypress: {"action":"keypress","key":"one supported key","reason":"short visible rationale"}
- scroll: {"action":"scroll","delta_y":integer,"reason":"short visible rationale"}
- wait: {"action":"wait","milliseconds":integer,"reason":"short visible rationale"}
- finish: {"action":"finish","reason":"short visible terminal rationale"}
Never return a private value, password, API key, verification URL, hidden reasoning,
or fields not in the chosen schema."""


class CdpError(RuntimeError):
    pass


@dataclass
class CdpClient:
    websocket: Any
    events: list[dict[str, Any]]

    def __post_init__(self) -> None:
        self._next_id = 1
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._reader = asyncio.create_task(self._read())

    @classmethod
    async def connect(cls, websocket_url: str) -> "CdpClient":
        websocket = await websockets.connect(websocket_url, max_size=32 * 1024 * 1024)
        return cls(websocket=websocket, events=[])

    async def _read(self) -> None:
        try:
            async for raw in self.websocket:
                message = json.loads(raw)
                message_id = message.get("id")
                if isinstance(message_id, int) and message_id in self._pending:
                    future = self._pending.pop(message_id)
                    if not future.done():
                        future.set_result(message)
                elif isinstance(message, dict):
                    self.events.append(message)
        except Exception as error:
            for future in self._pending.values():
                if not future.done():
                    future.set_exception(CdpError(type(error).__name__))
            self._pending.clear()

    async def call(
        self, method: str, params: dict[str, Any] | None = None, session_id: str | None = None
    ) -> dict[str, Any]:
        message_id = self._next_id
        self._next_id += 1
        request: dict[str, Any] = {"id": message_id, "method": method}
        if params:
            request["params"] = params
        if session_id:
            request["sessionId"] = session_id
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[message_id] = future
        await self.websocket.send(json.dumps(request, separators=(",", ":")))
        response = await asyncio.wait_for(future, timeout=45)
        if "error" in response:
            message = str((response["error"] or {}).get("message") or "CDP command failed")
            raise CdpError(message[:240])
        return dict(response.get("result") or {})

    async def close(self) -> None:
        self._reader.cancel()
        try:
            await self._reader
        except asyncio.CancelledError:
            pass
        await self.websocket.close()


def safe_url(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = f"{host}:{port}" if port is not None else host
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def allowed_navigation(url: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme == "https" and (parts.hostname or "").lower() in ALLOWED_HOSTS


def redact(text: str, values: dict[str, str]) -> str:
    output = text
    for value in sorted(values.values(), key=len, reverse=True):
        if len(value) >= 3:
            output = output.replace(value, "[REDACTED]")
    output = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[REDACTED_EMAIL]", output)
    return output[:240]


def extract_action(text: str, values: dict[str, str]) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    raw: dict[str, Any] | None = None
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            candidate, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict) and isinstance(candidate.get("action"), str):
            raw = candidate
            break
    if raw is None:
        raise ValueError("Goodhope output has no action JSON")
    action = raw.get("action")
    if action not in ACTION_FIELDS or set(raw) != ACTION_FIELDS[action]:
        raise ValueError("Goodhope action schema is invalid")
    reason = raw.get("reason")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
        raise ValueError("Goodhope action reason is invalid")
    if action == "click":
        x, y = raw.get("x"), raw.get("y")
        if any(isinstance(value, bool) or not isinstance(value, int) for value in (x, y)):
            raise ValueError("Goodhope click coordinates are invalid")
        if not 0 <= x < WIDTH or not 0 <= y < HEIGHT:
            raise ValueError("Goodhope click is outside the viewport")
    elif action == "type" and raw.get("value_ref") not in values:
        raise ValueError("Goodhope requested an unavailable value")
    elif action == "keypress" and raw.get("key") not in ALLOWED_KEYS:
        raise ValueError("Goodhope requested an unsupported key")
    elif action == "scroll":
        delta = raw.get("delta_y")
        if isinstance(delta, bool) or not isinstance(delta, int) or not -1200 <= delta <= 1200 or not delta:
            raise ValueError("Goodhope scroll is invalid")
    elif action == "wait":
        milliseconds = raw.get("milliseconds")
        if isinstance(milliseconds, bool) or not isinstance(milliseconds, int) or not 250 <= milliseconds <= 2000:
            raise ValueError("Goodhope wait is invalid")
    raw["reason"] = redact(reason, values)
    return raw


def response_text(payload: dict[str, Any]) -> str:
    direct = payload.get("output_text")
    if isinstance(direct, str) and direct.strip():
        return direct
    chunks: list[str] = []
    for item in payload.get("output") or []:
        if not isinstance(item, dict):
            continue
        for content in item.get("content") or []:
            if isinstance(content, dict) and isinstance(content.get("text"), str):
                chunks.append(content["text"])
    return "\n".join(chunks)


def collect_usage(payload: dict[str, Any], totals: dict[str, int]) -> None:
    def visit(prefix: str, value: Any) -> None:
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            totals[prefix] = totals.get(prefix, 0) + value
        elif isinstance(value, dict):
            for key, nested in value.items():
                if isinstance(key, str):
                    visit(f"{prefix}.{key}" if prefix else key, nested)

    usage = payload.get("usage")
    if isinstance(usage, dict):
        visit("", usage)


def goodhope_request(api_key: str, screenshot: bytes, context: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = {
        "model": GOODHOPE_MODEL,
        "reasoning": {"effort": GOODHOPE_REASONING_EFFORT},
        "max_output_tokens": GOODHOPE_MAX_OUTPUT_TOKENS,
        "input": [
            {"role": "system", "content": [{"type": "input_text", "text": SYSTEM_PROMPT}]},
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": json.dumps(context, separators=(",", ":"))},
                    {
                        "type": "input_image",
                        "image_url": "data:image/png;base64," + base64.b64encode(screenshot).decode("ascii"),
                        "detail": "original",
                    },
                ],
            },
        ],
    }
    request = urllib.request.Request(
        f"{GOODHOPE_BASE_URL}/v1/responses",
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            returned = json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"Goodhope HTTP {error.code}") from None
    return returned, {"status": 200}


def randomized_values() -> dict[str, str]:
    suffix = secrets.token_hex(5)
    first_names = ("Avery", "Jordan", "Morgan", "Taylor", "Casey")
    last_names = ("Reed", "Hayes", "Blake", "Parker", "Quinn")
    streets = ("1842 Maple Avenue", "728 Cedar Lane", "431 Juniper Drive", "916 Willow Street")
    cities = (("Denver", "CO", "80202"), ("Austin", "TX", "78701"), ("Phoenix", "AZ", "85004"), ("Raleigh", "NC", "27601"))
    first_name = secrets.choice(first_names)
    last_name = secrets.choice(last_names)
    city, state, post_code = secrets.choice(cities)
    return {
        "full_name": f"{first_name} {last_name}",
        "first_name": first_name,
        "last_name": last_name,
        "email": f"obscura-vision-{suffix}@example.invalid",
        "password": f"Obscura-{secrets.token_urlsafe(18)}-A9",
        "country": "United States",
        "address": secrets.choice(streets),
        "city": city,
        "state": state,
        "post_code": post_code,
    }


def browser_env() -> dict[str, str]:
    return {
        key: value
        for key in ("HOME", "PATH", "TMPDIR")
        if (value := os.environ.get(key))
    } | {
        "TZ": "America/New_York",
        "OBSCURA_GEOLOCATION": "40.7128,-74.0060",
        "OBSCURA_PROFILE": "2",
    }


def websocket_url(port: int) -> str:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=3) as response:
        payload = json.loads(response.read().decode())
    url = payload.get("webSocketDebuggerUrl")
    if not isinstance(url, str) or not url.startswith("ws://127.0.0.1:"):
        raise RuntimeError("Obscura did not expose a loopback CDP endpoint")
    return url


async def wait_for_cdp(port: int, process: subprocess.Popen[bytes]) -> str:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Obscura exited before its CDP endpoint was ready")
        try:
            return await asyncio.to_thread(websocket_url, port)
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            await asyncio.sleep(0.25)
    raise RuntimeError("Obscura CDP endpoint did not become ready")


async def event_markers(client: CdpClient) -> tuple[list[str], str | None]:
    markers: list[str] = []
    last_url: str | None = None
    for event in client.events:
        method = event.get("method")
        params = event.get("params")
        if not isinstance(params, dict):
            continue
        if method == "Network.requestWillBeSent":
            request = params.get("request")
            if isinstance(request, dict) and isinstance(request.get("url"), str):
                url = safe_url(request["url"])
                host = (urlsplit(url).hostname or "").lower()
                if host == TURNSTILE_HOST and url not in markers:
                    markers.append(url)
        elif method == "Page.frameNavigated":
            frame = params.get("frame")
            if isinstance(frame, dict) and "parentId" not in frame and isinstance(frame.get("url"), str):
                last_url = safe_url(frame["url"])
    client.events.clear()
    return markers, last_url


async def capture_screenshot(client: CdpClient, session_id: str) -> bytes:
    response = await client.call(
        "Page.captureScreenshot", {"format": "png", "fromSurface": True}, session_id
    )
    encoded = response.get("data")
    if not isinstance(encoded, str):
        raise CdpError("Page.captureScreenshot returned no PNG")
    return base64.b64decode(encoded, validate=True)


async def click(client: CdpClient, session_id: str, x: int, y: int) -> None:
    base = {"x": x, "y": y, "button": "left", "clickCount": 1}
    await client.call("Input.dispatchMouseEvent", {"type": "mousePressed", **base}, session_id)
    await client.call("Input.dispatchMouseEvent", {"type": "mouseReleased", **base}, session_id)


async def keypress(client: CdpClient, session_id: str, key: str) -> None:
    code = " " if key == "Space" else key
    payload = {"key": " " if key == "Space" else key, "code": code}
    await client.call("Input.dispatchKeyEvent", {"type": "keyDown", **payload}, session_id)
    await client.call("Input.dispatchKeyEvent", {"type": "keyUp", **payload}, session_id)


async def run(args: argparse.Namespace) -> dict[str, Any]:
    os.umask(0o077)
    api_key = os.environ.pop("GOODHOPE_API_KEY", None)
    if not api_key:
        raise RuntimeError("GOODHOPE_API_KEY is required")
    values = randomized_values()
    run_dir = Path(args.run_dir)
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    run_dir.chmod(0o700)
    version = subprocess.run(
        [args.obscura_bin, "--version"], env=browser_env(), check=True, capture_output=True, text=True
    ).stdout.strip()
    process = subprocess.Popen(
        [args.obscura_bin, "--stealth", "serve", "--host", "127.0.0.1", "--port", str(args.port), "--quiet"],
        env=browser_env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    result: dict[str, Any] = {
        "verdict": "failed",
        "browser": {"engine": "Obscura", "version": version, "stealth": True, "viewport": [WIDTH, HEIGHT]},
        "target": safe_url(START_URL),
        "model": {"endpoint": GOODHOPE_BASE_URL, "name": GOODHOPE_MODEL, "reasoning_effort": GOODHOPE_REASONING_EFFORT, "request_count": 0, "usage": {}},
        "stages": [],
        "turnstile": {"visible_marker": None, "network_markers": []},
        "actions": 0,
        "account_created": False,
        "weatherstack_free_product": False,
        "api_key_present": False,
        "cleanup": {"obscura_process": "not_yet_released"},
    }
    client: CdpClient | None = None
    seen_markers: set[str] = set()
    started = time.monotonic()
    try:
        websocket = await wait_for_cdp(args.port, process)
        client = await CdpClient.connect(websocket)
        target = await client.call("Target.createTarget", {"url": "about:blank"})
        target_id = target.get("targetId")
        if not isinstance(target_id, str):
            raise CdpError("Target.createTarget returned no targetId")
        attached = await client.call("Target.attachToTarget", {"targetId": target_id, "flatten": True})
        session_id = attached.get("sessionId")
        if not isinstance(session_id, str):
            raise CdpError("Target.attachToTarget returned no sessionId")
        await client.call("Page.enable", session_id=session_id)
        await client.call("Network.enable", session_id=session_id)
        await client.call(
            "Emulation.setDeviceMetricsOverride",
            {"width": WIDTH, "height": HEIGHT, "deviceScaleFactor": 1, "mobile": False},
            session_id,
        )
        await client.call("Page.navigate", {"url": START_URL}, session_id)
        await asyncio.sleep(1.5)
        history: list[dict[str, Any]] = []
        last_url = safe_url(START_URL)
        for step in range(1, MAX_ACTIONS + 1):
            if time.monotonic() - started >= MAX_SECONDS:
                result.update(verdict="blocked", blocker="run timeout reached")
                break
            markers, navigated = await event_markers(client)
            for marker in markers:
                seen_markers.add(marker)
            if navigated:
                last_url = navigated
            if not allowed_navigation(last_url):
                result.update(verdict="blocked", blocker="disallowed top-level navigation", final_url=last_url)
                break
            screenshot = await capture_screenshot(client, session_id)
            result["stages"].append(
                {"step": step, "url": last_url, "screenshot_sha256": hashlib.sha256(screenshot).hexdigest()}
            )
            context = {
                "goal": "Complete the approved free-only Weatherstack path, or stop at a visible challenge or email-verification boundary.",
                "url": last_url,
                "available_value_refs": sorted(values),
                "supported_keys": sorted(ALLOWED_KEYS),
                "recent_outcomes": history[-8:],
            }
            payload, _ = await asyncio.to_thread(goodhope_request, api_key, screenshot, context)
            result["model"]["request_count"] += 1
            collect_usage(payload, result["model"]["usage"])
            action = extract_action(response_text(payload), values)
            result["actions"] = step
            reason = action["reason"]
            if action["action"] == "finish":
                lower_reason = reason.lower()
                if "cloudflare" in lower_reason or "turnstile" in lower_reason:
                    result.update(
                        verdict="blocked",
                        blocker="Cloudflare Turnstile visible",
                        final_url=last_url,
                    )
                    result["turnstile"]["visible_marker"] = reason
                else:
                    result.update(verdict="blocked", blocker=reason, final_url=last_url)
                break
            kind = action["action"]
            if kind == "click":
                await click(client, session_id, action["x"], action["y"])
                outcome = "click_dispatched"
            elif kind == "type":
                await client.call("Input.insertText", {"text": values[action["value_ref"]]}, session_id)
                outcome = "private_text_inserted"
            elif kind == "keypress":
                await keypress(client, session_id, action["key"])
                outcome = "keypress_dispatched"
            elif kind == "scroll":
                await client.call(
                    "Input.dispatchMouseEvent",
                    {"type": "mouseWheel", "x": WIDTH // 2, "y": HEIGHT // 2, "deltaX": 0, "deltaY": action["delta_y"]},
                    session_id,
                )
                outcome = "scroll_dispatched"
            elif kind == "wait":
                await asyncio.sleep(action["milliseconds"] / 1000)
                outcome = "wait_completed"
            else:
                raise AssertionError(f"unhandled action {kind}")
            history.append({"step": step, "action": kind, "reason": reason, "outcome": outcome, "url": last_url})
            await asyncio.sleep(0.6)
        else:
            result.update(verdict="blocked", blocker="action limit reached", final_url=last_url)
        result["turnstile"]["network_markers"] = sorted(seen_markers)
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    except Exception as error:
        result.update(verdict="failed", blocker=type(error).__name__)
        result["error_kind"] = type(error).__name__
        result["error_detail"] = redact(str(error), values)
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    finally:
        if client is not None:
            try:
                await client.close()
            except Exception:
                pass
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        result["turnstile"]["network_markers"] = sorted(seen_markers)
        result["cleanup"]["obscura_process"] = "released" if process.poll() is not None else "release_failed"
        output = run_dir / "evidence.json"
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
        output.chmod(0o600)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--obscura-bin", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--port", type=int, default=19222)
    args = parser.parse_args()
    result = asyncio.run(run(args))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
