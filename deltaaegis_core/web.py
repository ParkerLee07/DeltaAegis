#!/usr/bin/env python3
"""HTTP routing, response, rendering, and server lifecycle for DeltaAegis v0.44."""

from __future__ import annotations

import html
import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlsplit

from deltaaegis_core import api_v1 as _api_v1
from deltaaegis_core import auth as _auth
from deltaaegis_core import identity as _identity
from deltaaegis_core import detection as _detection
from deltaaegis_core import operations as _operations
from deltaaegis_core.auth import (
    ACCESS_CSRF_COOKIE_NAME,
    ACCESS_SESSION_COOKIE_NAME,
    ACCESS_SESSION_TTL_SECONDS,
)


_OWNED_NAMES = {
    "dashboard_json_response",
    "dashboard_inject_operator_floating_button",
    "dashboard_inject_netsniper_navigation",
    "dashboard_html_response",
    "dashboard_text_response",
    "dashboard_read_request_payload",
    "dashboard_session_cookie_header",
    "dashboard_clear_session_cookie_header",
    "dashboard_redirect_response",
    "dashboard_security_headers",
    "dashboard_inject_csrf_fetch_boundary",
    "dashboard_csrf_cookie_header",
    "dashboard_clear_csrf_cookie_header",
    "dashboard_login_html",
    "render_netsniper_page",
    "dashboard_bind_host_is_loopback",
    "command_dashboard",
    "install_namespace",
    "_OWNED_NAMES",
}


DASHBOARD_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "base-uri 'none'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


_DASHBOARD_FORCE_SECURE_COOKIES = False


def _dashboard_public_origin_identity(
    value: str | None,
    *,
    secure_cookies: bool,
) -> tuple[str, str, int] | None:
    """Validate one explicitly trusted browser-facing origin.

    Forwarded headers remain untrusted.  A reverse proxy must preserve the
    configured authority in ``Host`` and the browser must supply this exact
    origin for every cookie-authenticated mutation.
    """

    raw = str(value or "").strip()
    if not raw:
        if secure_cookies:
            raise ValueError(
                "--secure-cookies requires an explicit HTTPS --public-origin"
            )
        return None
    if len(raw) > 512 or any(ord(character) < 33 for character in raw):
        raise ValueError("--public-origin contains invalid characters")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("--public-origin is not a valid HTTP origin") from exc
    scheme = str(parsed.scheme or "").casefold()
    hostname = str(parsed.hostname or "").rstrip(".").casefold()
    if (
        scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "--public-origin must be an HTTP(S) origin without credentials, path, query, or fragment"
        )
    try:
        ipaddress.ip_address(hostname.split("%", 1)[0])
    except ValueError:
        if (
            re.fullmatch(r"[a-z0-9.-]+", hostname) is None
            or hostname.startswith(".")
            or hostname.endswith(".")
            or ".." in hostname
        ):
            raise ValueError("--public-origin hostname is invalid")
    if secure_cookies and scheme != "https":
        raise ValueError("--secure-cookies requires an HTTPS --public-origin")
    if scheme == "https" and not secure_cookies:
        raise ValueError("an HTTPS --public-origin requires --secure-cookies")
    return scheme, hostname, int(port or (443 if scheme == "https" else 80))


def dashboard_security_headers() -> dict[str, str]:
    return dict(DASHBOARD_SECURITY_HEADERS)


def _dashboard_send_security_headers(handler) -> None:
    for name, value in DASHBOARD_SECURITY_HEADERS.items():
        handler.send_header(name, value)


def _dashboard_send_extra_headers(handler, headers: Any) -> None:
    protected = {name.casefold() for name in DASHBOARD_SECURITY_HEADERS}
    if not headers:
        return
    entries = headers.items() if hasattr(headers, "items") else headers
    for name, value in entries:
        if str(name).casefold() in protected:
            continue
        values = value if isinstance(value, (list, tuple)) else (value,)
        for item in values:
            handler.send_header(str(name), str(item))


def install_namespace(namespace: dict[str, Any]) -> None:
    """Refresh root-facade collaborators before servicing an HTTP request."""
    for name, value in namespace.items():
        if name.startswith("__") or name in _OWNED_NAMES:
            continue
        globals()[name] = value


def dashboard_json_response(handler, payload, status=200, headers=None):
    body = json.dumps(payload, indent=2, default=str).encode("utf-8")

    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    _dashboard_send_security_headers(handler)
    handler.send_header("Content-Length", str(len(body)))
    _dashboard_send_extra_headers(handler, headers)
    handler.end_headers()
    try:
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionResetError):
        return


def dashboard_inject_operator_floating_button(html_text: str) -> str:
    # Do not inject dashboard-only polish into auth/operator pages.
    if (
        "<title>DeltaAegis Operator" in html_text
        or "<title>DeltaAegis Login" in html_text
        or "<title>DeltaAegis First Admin Setup" in html_text
    ):
        return html_text

    if not isinstance(html_text, str):
        return html_text

    if "</body>" not in html_text:
        return html_text

    # Do not inject dashboard-only polish into operator pages.
    if "DeltaAegis Operator Session" in html_text or "DeltaAegis User Management" in html_text:
        return html_text

    polish_style = """
<style id="deltaaegis-v026-dashboard-polish-style">
  a[href="/operator"]:not(#deltaaegis-operator-floating-button) {
    display: none !important;
  }
</style>
"""

    polish_script = """
<script id="deltaaegis-v026-dashboard-polish-script">
(function () {
  function replaceText(node, fromText, toText) {
    if (!node || !node.childNodes) { return; }

    for (const child of Array.from(node.childNodes)) {
      if (child.nodeType === Node.TEXT_NODE && child.nodeValue && child.nodeValue.includes(fromText)) {
        child.nodeValue = child.nodeValue.replaceAll(fromText, toText);
      } else {
        replaceText(child, fromText, toText);
      }
    }
  }

  function removeLegacyOperatorLinks() {
    document.querySelectorAll('a[href="/operator"]').forEach(function (link) {
      if (link.id !== "deltaaegis-operator-floating-button") {
        link.remove();
      }
    });
  }

  function hideDashboardAccessAuditTrail() {
    const headings = Array.from(document.querySelectorAll("h1,h2,h3,h4"));
    headings.forEach(function (heading) {
      if ((heading.textContent || "").trim() !== "Access Audit Trail") {
        return;
      }

      let node = heading;
      while (node) {
        const next = node.nextElementSibling;
        node.setAttribute("data-deltaaegis-v026-moved-audit", "true");
        node.style.display = "none";

        if (next && /^H[1-4]$/.test(next.tagName || "")) {
          break;
        }

        node = next;
      }
    });
  }

  function applyDashboardPolish() {
    replaceText(document.body, "v0.26 User Management", "v0.26 User Management");
    replaceText(document.body, "v0.26 user management", "v0.26 user management");
    removeLegacyOperatorLinks();
    hideDashboardAccessAuditTrail();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", applyDashboardPolish);
  } else {
    applyDashboardPolish();
  }

  const observer = new MutationObserver(applyDashboardPolish);
  observer.observe(document.documentElement, { childList: true, subtree: true });
})();
</script>
"""

    floating_button = """
  <a
    id="deltaaegis-operator-floating-button"
    href="/operator"
    aria-label="Open operator session page"
    title="Open operator session page"
    style="
      position: fixed;
      right: 20px;
      bottom: 20px;
      z-index: 9999;
      border: 1px solid rgba(34, 211, 238, 0.38);
      border-radius: 999px;
      background: rgba(8, 145, 178, 0.92);
      color: #ecfeff;
      box-shadow: 0 18px 40px rgba(0, 0, 0, 0.35);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 13px;
      font-weight: 950;
      padding: 11px 15px;
      text-decoration: none;
      backdrop-filter: blur(10px);
    "
  >Operator</a>
"""

    if 'id="deltaaegis-v026-dashboard-polish-style"' not in html_text and "</head>" in html_text:
        html_text = html_text.replace("</head>", polish_style + "\n</head>", 1)

    if 'id="deltaaegis-v026-dashboard-polish-script"' not in html_text:
        html_text = html_text.replace("</body>", polish_script + "\n</body>", 1)

    if 'id="deltaaegis-operator-floating-button"' not in html_text:
        html_text = html_text.replace("</body>", floating_button + "\n</body>", 1)

    return html_text


def dashboard_inject_netsniper_navigation(html_text: str) -> str:
    if not isinstance(html_text, str):
        return html_text

    if "</body>" not in html_text:
        return html_text

    # Keep auth, operator, and the NetSniper page itself clean.
    if (
        "<title>DeltaAegis Login" in html_text
        or "<title>DeltaAegis First Admin Setup" in html_text
        or "<title>DeltaAegis Operator" in html_text
        or "<title>DeltaAegis User Management" in html_text
        or "<title>DeltaAegis NetSniper" in html_text
    ):
        return html_text

    style = """
<style id="deltaaegis-v028-netsniper-navigation-style">
  #deltaaegis-netsniper-dashboard-link {
    position: fixed;
    right: 24px;
    bottom: 86px;
    z-index: 9999;
    border: 1px solid rgba(34, 211, 238, 0.38);
    border-radius: 999px;
    background: rgba(8, 145, 178, 0.18);
    box-shadow: 0 16px 48px rgba(0, 0, 0, 0.34);
    color: #67e8f9;
    padding: 10px 14px;
    text-decoration: none;
    font-size: 13px;
    font-weight: 950;
    letter-spacing: 0.01em;
  }

  #deltaaegis-netsniper-dashboard-link:hover {
    background: rgba(8, 145, 178, 0.30);
  }

  @media (max-width: 720px) {
    #deltaaegis-netsniper-dashboard-link {
      right: 16px;
      bottom: 78px;
    }
  }
</style>
"""

    link = """
<a
  id="deltaaegis-netsniper-dashboard-link"
  href="/netsniper"
  aria-label="Open NetSniper telemetry source tab"
  title="Open NetSniper telemetry source tab"
>NetSniper</a>
"""

    if 'id="deltaaegis-v028-netsniper-navigation-style"' not in html_text and "</head>" in html_text:
        html_text = html_text.replace("</head>", style + "\n</head>", 1)

    if 'id="deltaaegis-netsniper-dashboard-link"' not in html_text:
        html_text = html_text.replace("</body>", link + "\n</body>", 1)

    return html_text


def dashboard_inject_csrf_fetch_boundary(html_text: str) -> str:
    if not isinstance(html_text, str) or "</body>" not in html_text:
        return html_text
    if 'id="deltaaegis-v1-csrf-fetch-boundary"' in html_text:
        return html_text
    script = r'''
<script id="deltaaegis-v1-csrf-fetch-boundary">
(function () {
  const originalFetch = window.fetch.bind(window);
  function cookieValue(name) {
    const prefix = encodeURIComponent(name) + "=";
    for (const part of document.cookie.split(";")) {
      const value = part.trim();
      if (value.startsWith(prefix)) {
        return decodeURIComponent(value.slice(prefix.length));
      }
    }
    return "";
  }
  window.fetch = function (input, init) {
    const options = Object.assign({}, init || {});
    const request = input instanceof Request ? input : null;
    const url = new URL(request ? request.url : String(input), window.location.href);
    const method = String(options.method || (request && request.method) || "GET").toUpperCase();
    if (url.origin === window.location.origin && !["GET", "HEAD", "OPTIONS"].includes(method)) {
      const csrf = cookieValue("deltaaegis_csrf");
      if (csrf) {
        const headers = new Headers(request ? request.headers : undefined);
        new Headers(options.headers || {}).forEach(function (value, name) {
          headers.set(name, value);
        });
        headers.set("X-DeltaAegis-CSRF", csrf);
        options.headers = headers;
      }
    }
    return originalFetch(input, options);
  };
  function attachLogoutBoundary() {
    document.querySelectorAll('a[href="/logout"]').forEach(function (link) {
      link.addEventListener("click", async function (event) {
        event.preventDefault();
        try {
          await window.fetch("/logout", {
            method: "POST",
            credentials: "same-origin",
            cache: "no-store"
          });
        } finally {
          window.location.href = "/login";
        }
      });
    });
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", attachLogoutBoundary);
  } else {
    attachLogoutBoundary();
  }
})();
</script>
'''
    return html_text.replace("</body>", script + "\n</body>", 1)


def dashboard_html_response(handler, body, status=200, headers=None):
    body = dashboard_inject_operator_floating_button(body)
    body = dashboard_inject_netsniper_navigation(body)
    body = dashboard_inject_csrf_fetch_boundary(body)
    body = body.encode("utf-8")

    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    _dashboard_send_security_headers(handler)
    handler.send_header("Content-Length", str(len(body)))
    _dashboard_send_extra_headers(handler, headers)
    handler.end_headers()
    handler.wfile.write(body)


def dashboard_text_response(handler, body, status=200):
    body = str(body).encode("utf-8")

    handler.send_response(status)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    _dashboard_send_security_headers(handler)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def dashboard_read_request_payload(handler: Any) -> dict[str, Any]:
    length_text = handler.headers.get("Content-Length", "0")
    try:
        length = int(length_text or "0")
    except ValueError:
        raise DashboardAdminUserActionError(
            "invalid Content-Length header",
            status_code=400,
        )

    if length < 0:
        raise DashboardAdminUserActionError(
            "invalid Content-Length header",
            status_code=400,
        )
    if length > DASHBOARD_MAX_REQUEST_BODY_BYTES:
        raise DashboardAdminUserActionError(
            "POST body is too large",
            status_code=413,
        )

    raw = handler.rfile.read(length).decode("utf-8", "replace")
    if not raw.strip():
        return {}

    content_type = handler.headers.get("Content-Type", "").lower()
    if "application/json" in content_type:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise DashboardAdminUserActionError(
                f"invalid JSON body: {exc.msg}",
                status_code=400,
            ) from exc
        if not isinstance(parsed, dict):
            raise DashboardAdminUserActionError(
                "JSON body must be an object",
                status_code=400,
            )
        return parsed

    form = parse_qs(raw, keep_blank_values=True)
    return {
        key: values[-1] if values else ""
        for key, values in form.items()
    }


def dashboard_session_cookie_header(
    session_token: str,
    max_age: int = ACCESS_SESSION_TTL_SECONDS,
) -> str:
    header = (
        f"{ACCESS_SESSION_COOKIE_NAME}={session_token}; "
        "Path=/; "
        f"Max-Age={max(300, int(max_age or ACCESS_SESSION_TTL_SECONDS))}; "
        "HttpOnly; "
        "SameSite=Strict"
    )
    return header + ("; Secure" if _DASHBOARD_FORCE_SECURE_COOKIES else "")


def dashboard_clear_session_cookie_header() -> str:
    header = (
        f"{ACCESS_SESSION_COOKIE_NAME}=; "
        "Path=/; "
        "Max-Age=0; "
        "HttpOnly; "
        "SameSite=Strict"
    )
    return header + ("; Secure" if _DASHBOARD_FORCE_SECURE_COOKIES else "")


def dashboard_csrf_cookie_header(
    csrf_token: str,
    max_age: int = ACCESS_SESSION_TTL_SECONDS,
) -> str:
    header = (
        f"{ACCESS_CSRF_COOKIE_NAME}={csrf_token}; "
        "Path=/; "
        f"Max-Age={max(300, int(max_age or ACCESS_SESSION_TTL_SECONDS))}; "
        "SameSite=Strict"
    )
    return header + ("; Secure" if _DASHBOARD_FORCE_SECURE_COOKIES else "")


def dashboard_clear_csrf_cookie_header() -> str:
    header = (
        f"{ACCESS_CSRF_COOKIE_NAME}=; "
        "Path=/; "
        "Max-Age=0; "
        "SameSite=Strict"
    )
    return header + ("; Secure" if _DASHBOARD_FORCE_SECURE_COOKIES else "")


def dashboard_redirect_response(
    handler,
    location: str,
    cookie_header: str | None = None,
) -> None:
    handler.send_response(303)
    handler.send_header("Location", location)
    handler.send_header("Cache-Control", "no-store")
    _dashboard_send_security_headers(handler)

    if cookie_header:
        cookie_headers = (
            cookie_header
            if isinstance(cookie_header, (list, tuple))
            else (cookie_header,)
        )
        for value in cookie_headers:
            handler.send_header("Set-Cookie", str(value))

    handler.end_headers()


def dashboard_login_html(
    message: str = "",
    username: str = "",
) -> str:
    safe_message = html.escape(str(message or ""))
    safe_username = html.escape(str(username or ""))

    error_block = ""

    if safe_message:
        error_block = (
            '<div class="login-error">'
            + safe_message
            + '</div>'
        )

    lines = [
        '<!doctype html>',
        '<html lang="en">',
        '<head>',
        '  <meta charset="utf-8">',
        '  <meta name="viewport" content="width=device-width,initial-scale=1">',
        '  <title>DeltaAegis Login</title>',
        '  <style>',
        '    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #020617; color: #e2e8f0; }',
        '    body { min-height: 100vh; margin: 0; display: grid; place-items: center; background: radial-gradient(circle at top left, rgba(34, 211, 238, 0.14), transparent 34rem), radial-gradient(circle at bottom right, rgba(59, 130, 246, 0.14), transparent 34rem), #020617; }',
        '    .login-shell { width: min(420px, calc(100vw - 32px)); border: 1px solid rgba(148, 163, 184, 0.24); border-radius: 24px; background: rgba(15, 23, 42, 0.94); box-shadow: 0 24px 80px rgba(0, 0, 0, 0.42); padding: 28px; }',
        '    .eyebrow { color: #67e8f9; font-size: 12px; font-weight: 900; letter-spacing: 0.16em; text-transform: uppercase; }',
        '    h1 { margin: 8px 0 8px; font-size: 30px; letter-spacing: -0.04em; }',
        '    p { margin: 0 0 22px; color: #94a3b8; line-height: 1.55; }',
        '    label { display: block; margin: 14px 0 6px; color: #cbd5e1; font-size: 13px; font-weight: 800; }',
        '    input { width: 100%; box-sizing: border-box; border: 1px solid rgba(148, 163, 184, 0.28); border-radius: 14px; background: rgba(2, 6, 23, 0.82); color: #f8fafc; padding: 12px 13px; font-size: 15px; outline: none; }',
        '    input:focus { border-color: rgba(34, 211, 238, 0.65); box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.12); }',
        '    button { width: 100%; margin-top: 20px; border: 0; border-radius: 14px; background: linear-gradient(135deg, #06b6d4, #2563eb); color: white; padding: 12px 14px; font-size: 15px; font-weight: 900; cursor: pointer; }',
        '    .login-error { margin: 14px 0 4px; border: 1px solid rgba(248, 113, 113, 0.34); border-radius: 14px; background: rgba(127, 29, 29, 0.28); color: #fecaca; padding: 10px 12px; font-size: 13px; font-weight: 700; }',
        '    .login-note { margin-top: 16px; color: #64748b; font-size: 12px; line-height: 1.45; }',
        '  </style>',
        '</head>',
        '<body>',
        '  <main class="login-shell">',
        '    <div class="eyebrow">DeltaAegis</div>',
        '    <h1>Operator Login</h1>',
        '    <p>Sign in with your local DeltaAegis username and password.</p>',
        error_block,
        '    <form method="post" action="/login" autocomplete="on">',
        '      <label for="username">Username</label>',
        '      <input id="username" name="username" autocomplete="username" required autofocus>',
        '      <label for="password">Password</label>',
        '      <input id="password" name="password" type="password" autocomplete="current-password" required>',
        '      <button type="submit">Sign in</button>',
        '    </form>',
        '    <div class="login-note">API tokens are still supported for automation through <code>X-DeltaAegis-Token</code>, but browser login uses sessions.</div>',
        '  </main>',
        '</body>',
        '</html>',
    ]

    return "\n".join(lines)


def render_netsniper_page() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>DeltaAegis NetSniper</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #020617; color: #e2e8f0; }
    body { margin: 0; min-height: 100vh; background: radial-gradient(circle at top left, rgba(34,211,238,.13), transparent 34rem), #020617; }
    main { width: min(1120px, calc(100vw - 32px)); margin: 0 auto; padding: 44px 0; }
    .panel { border: 1px solid rgba(148,163,184,.22); border-radius: 24px; background: rgba(15,23,42,.92); box-shadow: 0 24px 80px rgba(0,0,0,.34); padding: 28px; }
    .eyebrow { color: #67e8f9; font-size: 12px; font-weight: 900; letter-spacing: .16em; text-transform: uppercase; }
    h1 { margin: 8px 0 8px; font-size: 32px; letter-spacing: -.04em; }
    h2 { margin: 26px 0 12px; font-size: 18px; }
    p { margin: 0 0 20px; color: #94a3b8; line-height: 1.55; }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin: 18px 0; }
    a, button { border: 1px solid rgba(34,211,238,.28); border-radius: 999px; background: rgba(8,145,178,.14); color: #67e8f9; cursor: pointer; padding: 9px 13px; text-decoration: none; font-size: 13px; font-weight: 900; }
    button:hover, a:hover { background: rgba(8,145,178,.26); }
    .status { border: 1px solid rgba(148,163,184,.18); border-radius: 16px; background: rgba(2,6,23,.38); color: #cbd5e1; margin: 18px 0; padding: 12px 14px; font-weight: 700; white-space: pre-wrap; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 12px; margin: 18px 0 22px; }
    .card { border: 1px solid rgba(148,163,184,.18); border-radius: 18px; background: rgba(2,6,23,.34); padding: 14px; }
    .card-label { color: #94a3b8; font-size: 11px; font-weight: 900; letter-spacing: .11em; text-transform: uppercase; }
    .card-value { color: #f8fafc; font-size: 20px; font-weight: 950; margin-top: 4px; overflow-wrap: anywhere; }
    .pill { display: inline-flex; border: 1px solid rgba(148,163,184,.22); border-radius: 999px; padding: 4px 8px; font-size: 11px; font-weight: 950; text-transform: uppercase; letter-spacing: .06em; }
    .ok { color: #bbf7d0; border-color: rgba(34,197,94,.35); background: rgba(22,163,74,.12); }
    .warn { color: #fde68a; border-color: rgba(251,191,36,.35); background: rgba(217,119,6,.12); }
    .scan-form { display: flex; flex-wrap: wrap; gap: 10px; align-items: end; margin: 12px 0 14px; }
    .scan-form label { color: #94a3b8; display: grid; gap: 6px; font-size: 11px; font-weight: 900; letter-spacing: .08em; text-transform: uppercase; }
    .scan-form input { border: 1px solid rgba(148,163,184,.22); border-radius: 12px; background: rgba(2,6,23,.48); color: #e2e8f0; padding: 10px 12px; min-width: 240px; font-weight: 800; }
    .table-wrap { overflow-x: auto; border: 1px solid rgba(148,163,184,.18); border-radius: 18px; margin-top: 10px; }
    .live-job-panel { margin-top: 18px; border: 1px solid rgba(34,211,238,.24); border-radius: 20px; background: rgba(2,6,23,.44); padding: 18px; }
    .live-job-panel[hidden] { display: none; }
    .live-job-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(165px, 1fr)); gap: 10px; margin: 14px 0; }
    .live-job-streams { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 12px; }
    .live-job-stream h3 { margin: 0 0 8px; color: #e2e8f0; font-size: 14px; }
    .live-job-stream pre { min-height: 160px; max-height: 360px; margin: 0; }
    .live-job-meta { color: #94a3b8; font-size: 12px; margin: 0 0 8px; }
    .live-job-cancel-form { display: flex; flex-wrap: wrap; gap: 10px; align-items: end; margin: 14px 0; }
    .live-job-cancel-form[hidden] { display: none; }
    .live-job-cancel-form label { color: #94a3b8; display: grid; gap: 6px; flex: 1 1 360px; font-size: 11px; font-weight: 900; letter-spacing: .08em; text-transform: uppercase; }
    .live-job-cancel-form input { border: 1px solid rgba(248,113,113,.32); border-radius: 12px; background: rgba(2,6,23,.48); color: #e2e8f0; padding: 10px 12px; min-width: 280px; font-weight: 800; }
    .danger { border-color: rgba(248,113,113,.42); background: rgba(185,28,28,.18); color: #fecaca; }
    .danger:hover { background: rgba(185,28,28,.32); }
    table { width: 100%; border-collapse: collapse; min-width: 980px; }
    th, td { border-bottom: 1px solid rgba(148,163,184,.14); padding: 10px 12px; text-align: left; vertical-align: top; }
    th { color: #94a3b8; font-size: 11px; text-transform: uppercase; letter-spacing: .08em; }
    td { color: #e2e8f0; font-size: 13px; font-weight: 700; }
    pre { border: 1px solid rgba(148,163,184,.18); border-radius: 16px; background: rgba(2,6,23,.55); color: #cbd5e1; padding: 14px; overflow: auto; white-space: pre-wrap; word-break: break-word; }
  </style>
</head>
<body>
  <main>
    <section class="panel">
      <div class="eyebrow">DeltaAegis Telemetry Source</div>
      <h1>NetSniper</h1>
      <p>DeltaAegis treats NetSniper as a lightweight CLI/headless scan engine. This page detects the local NetSniper checkout and its completed telemetry runs before dashboard scan execution is added.</p>

      <div class="actions">
        <a href="/">Back to dashboard</a>
        <a href="/operator">Operator session</a>
        <a href="/api/netsniper/status">View raw status JSON</a>
        <button type="button" id="netsniper-refresh">Refresh status</button>
        <button type="button" id="netsniper-import-latest">Import latest completed run</button>
      </div>

      <div class="status" id="netsniper-status">Loading NetSniper status…</div>

      <div class="grid">
        <div class="card"><div class="card-label">Installed</div><div class="card-value" id="netsniper-installed">—</div></div>
        <div class="card"><div class="card-label">Runs directory</div><div class="card-value" id="netsniper-runs-dir-exists">—</div></div>
        <div class="card"><div class="card-label">Latest run</div><div class="card-value" id="netsniper-latest-run">—</div></div>
        <div class="card"><div class="card-label">Import ready</div><div class="card-value" id="netsniper-import-ready">—</div></div>
      </div>

      <details class="technical-details">
        <summary>Detected NetSniper paths</summary>
        <pre id="netsniper-paths">Loading…</pre>
      </details>

      <details class="technical-details">
        <summary>Latest run metadata</summary>
        <pre id="netsniper-latest-json">Loading…</pre>
      </details>

      <h2>Import result</h2>
      <div class="status" id="netsniper-import-result">No import has been run from this page yet.</div>

      <h2>Guarded scan launch</h2>
      <p>ADMIN-only launch control for a single private IPv4 CIDR target. DeltaAegis uses a fixed NetSniper headless command shape and does not expose arbitrary shell input.</p>
      <form id="netsniper-scan-start-form" class="scan-form">
        <label>Private CIDR target
          <input id="netsniper-scan-target" name="target" autocomplete="off" placeholder="192.168.5.0/24" required>
        </label>
          <label>Scan profile
            <select id="netsniper-scan-profile" name="scan_profile">
              <option value="balanced" selected>Balanced — routine telemetry</option>
              <option value="accurate">Accurate — deeper evidence</option>
              <option value="quick">Quick — lighter check</option>
            </select>
          </label>
        <button type="submit" id="netsniper-scan-start">Start guarded scan</button>
      </form>
      <div class="status" id="netsniper-scan-start-result">No scan has been started from this page yet.</div>

      <h2>Scheduled scans</h2>
      <p>Saved profile-aware NetSniper scan schedules. These use the same guarded scan-job path as manual dashboard launches.</p>

      <div class="actions" id="netsniper-hourly-monitoring-controls">
        <label>Hourly monitoring target
          <input id="netsniper-hourly-monitoring-target" name="hourly_target" autocomplete="off" placeholder="192.168.5.0/24">
        </label>
        <button type="button" id="netsniper-hourly-monitoring-enable">Enable hourly balanced monitoring</button>
        <button type="button" id="netsniper-hourly-monitoring-disable">Disable hourly monitoring</button>
      </div>
      <p class="muted">Hourly monitoring creates or refreshes one saved schedule named <code>Hourly Balanced Monitoring</code> using the balanced profile, a 60-minute cadence, and auto-ingest enabled.</p>

      <form id="netsniper-schedule-create-form" class="scan-form">
        <label>Schedule name
          <input id="netsniper-schedule-name" name="name" autocomplete="off" placeholder="Hourly Balanced Monitoring" required>
        </label>
        <label>Private CIDR target
          <input id="netsniper-schedule-target" name="target" autocomplete="off" placeholder="192.168.5.0/24" required>
        </label>
        <label>Scan profile
          <select id="netsniper-schedule-profile" name="scan_profile">
            <option value="balanced" selected>Balanced — routine telemetry</option>
            <option value="accurate">Accurate — deeper evidence</option>
            <option value="quick">Quick — lighter check</option>
          </select>
        </label>
        <label>Cadence
          <select id="netsniper-schedule-cadence" name="cadence_minutes">
            <option value="60" selected>Every 1 hour</option>
            <option value="120">Every 2 hours</option>
            <option value="360">Every 6 hours</option>
            <option value="720">Every 12 hours</option>
            <option value="1440">Daily</option>
          </select>
        </label>
        <label>Enabled
          <select id="netsniper-schedule-enabled" name="enabled">
            <option value="true" selected>Enabled</option>
            <option value="false">Disabled</option>
          </select>
        </label>
        <label>Auto-ingest
          <select id="netsniper-schedule-auto-ingest" name="auto_ingest">
            <option value="true" selected>Enabled</option>
            <option value="false">Disabled</option>
          </select>
          <label for="netsniper-schedule-trueaegis-after-ingest">TrueAegis after ingest</label>
          <select id="netsniper-schedule-trueaegis-after-ingest" name="run_trueaegis_after_ingest">
            <option value="false" selected>no</option>
            <option value="true">yes - record follow-up intent</option>
          </select>
        </label>
        <button type="submit" id="netsniper-schedule-create">Create schedule</button>
      </form>

      <div class="actions">
        <button type="button" id="netsniper-schedules-refresh">Refresh schedules</button>
        <button type="button" id="netsniper-schedules-run-due">Run due schedules</button>
        <button type="button" id="netsniper-stale-scan-fail">Mark stale active scans failed</button>
        <a href="/api/netsniper/schedules">View raw schedules JSON</a>
      </div>

      <p class="muted"><strong>TrueAegis note:</strong> Scheduled scans run NetSniper and optional auto-ingest only. TrueAegis validation is configured and launched separately from the TrueAegis controls; NetSniper schedules do not automatically run TrueAegis.</p>
      <p class="muted"><strong>Stale scan recovery:</strong> If an old <code>QUEUED</code> or <code>RUNNING</code> scan job blocks schedules and no NetSniper process is active, an ADMIN can mark stale active scan jobs failed after confirmation.</p>
      <div class="status" id="netsniper-schedule-result">No scheduled scan action has run from this page yet.</div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Status</th>
              <th>Target</th>
              <th>Profile</th>
              <th>Cadence</th>
              <th>Next run</th>
              <th>Last run</th>
              <th>Last status</th>
              <th>Last job</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="netsniper-schedules-body">
            <tr><td colspan="10">Loading schedules…</td></tr>
          </tbody>
        </table>
      </div>

      <h2>Schedule run history</h2>
      <p>Read-only evidence view linking saved schedules to the guarded scan jobs they triggered.</p>
      <div class="actions">
        <button type="button" id="netsniper-schedule-history-refresh">Refresh schedule history</button>
        <a href="/api/netsniper/schedule-history">View raw schedule history JSON</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Schedule</th>
              <th>Schedule status</th>
              <th>Target</th>
              <th>Profile</th>
              <th>Last run</th>
              <th>Next run</th>
              <th>Job</th>
              <th>Job status</th>
              <th>Finished</th>
              <th>Message</th>
            </tr>
          </thead>
          <tbody id="netsniper-schedule-history-body">
            <tr><td colspan="10">Loading schedule history…</td></tr>
          </tbody>
        </table>
      </div>

      <h2>Recent scan jobs</h2>
      <p>Recent guarded NetSniper scan jobs from the DeltaAegis scan job ledger.</p>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Job</th>
              <th>Status</th>
              <th>Target</th>
              <th>Profile</th>
              <th>Created</th>
              <th>Updated</th>
              <th>Exit</th>
              <th>Bundle</th>
              <th>Message</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody id="netsniper-scan-jobs-body">
            <tr><td colspan="10">Loading scan jobs…</td></tr>
          </tbody>
        </table>
      </div>

      <section id="netsniper-live-job-panel" class="live-job-panel" hidden>
        <div class="actions">
          <strong id="netsniper-live-job-heading">Live scan details</strong>
          <a id="netsniper-live-job-raw" href="/api/netsniper/job-detail" target="_blank" rel="noopener">View raw job detail JSON</a>
          <button type="button" id="netsniper-live-job-refresh">Refresh details</button>
          <button type="button" id="netsniper-live-job-close">Close details</button>
        </div>

        <div class="status" id="netsniper-live-job-status">Select a scan job to view its lifecycle evidence and bounded log tails.</div>

        <form id="netsniper-live-job-cancel-form" class="live-job-cancel-form" hidden>
          <label>Cancellation reason
            <input id="netsniper-live-job-cancel-reason" name="reason" autocomplete="off" maxlength="500" placeholder="Reason for stopping this active scan" required>
          </label>
          <button type="submit" id="netsniper-live-job-cancel" class="danger">Cancel active scan</button>
        </form>
        <div class="status" id="netsniper-live-job-cancel-result" hidden>No cancellation request has been submitted.</div>

        <div class="live-job-grid">
          <div class="card"><div class="card-label">Status</div><div class="card-value" id="netsniper-live-job-state">—</div></div>
          <div class="card"><div class="card-label">Process PID</div><div class="card-value" id="netsniper-live-job-pid">—</div></div>
          <div class="card"><div class="card-label">Heartbeat</div><div class="card-value" id="netsniper-live-job-heartbeat">—</div></div>
          <div class="card"><div class="card-label">Updated</div><div class="card-value" id="netsniper-live-job-updated">—</div></div>
          <div class="card"><div class="card-label">Cancel requested</div><div class="card-value" id="netsniper-live-job-cancel-requested-at">—</div></div>
          <div class="card"><div class="card-label">Requested by</div><div class="card-value" id="netsniper-live-job-cancel-requested-by">—</div></div>
          <div class="card"><div class="card-label">Cancelled</div><div class="card-value" id="netsniper-live-job-cancelled-at">—</div></div>
        </div>

        <details class="technical-details">
          <summary>Cancellation evidence</summary>
          <pre id="netsniper-live-job-cancel-reason-display">—</pre>
        </details>

        <div class="live-job-streams">
          <details class="live-job-stream technical-details">
            <summary>Stdout tail</summary>
            <p class="live-job-meta" id="netsniper-live-job-stdout-meta">No stdout detail loaded.</p>
            <pre id="netsniper-live-job-stdout">—</pre>
          </details>
          <details class="live-job-stream technical-details">
            <summary>Stderr tail</summary>
            <p class="live-job-meta" id="netsniper-live-job-stderr-meta">No stderr detail loaded.</p>
            <pre id="netsniper-live-job-stderr">—</pre>
          </details>
        </div>
      </section>

      <h2>Design boundary</h2>
      <p>This tab does not run arbitrary shell commands. Scan execution and cancellation use guarded, ADMIN-only APIs with validated job identifiers; the browser never supplies or signals a process PID.</p>
    </section>
  </main>

  <script>
    function text(value) {
      if (value === null || value === undefined || value === "") { return "—"; }
      return String(value);
    }

    function escapeHtml(value) {
      return text(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }

    function pill(value, goodLabel) {
      const isGood = Boolean(value);
      const label = isGood ? goodLabel : "No";
      const cls = isGood ? "ok" : "warn";
      return `<span class="pill ${cls}">${escapeHtml(label)}</span>`;
    }

    function setHtml(id, value) {
      const element = document.getElementById(id);
      if (element) { element.innerHTML = value; }
    }

    function setText(id, value) {
      const element = document.getElementById(id);
      if (element) { element.textContent = text(value); }
    }

    async function loadNetSniperStatus() {
      const status = document.getElementById("netsniper-status");

      try {
        const response = await fetch("/api/netsniper/status", {
          credentials: "same-origin",
          cache: "no-store"
        });

        if (response.status === 401 || response.status === 403) {
          window.location.href = "/login";
          return;
        }

        if (!response.ok) {
          status.textContent = "NetSniper status lookup failed.";
          return;
        }

        const payload = await response.json();
        const latest = payload.latest_run || {};

        setHtml("netsniper-installed", pill(payload.netsniper_installed, "Yes"));
        setHtml("netsniper-runs-dir-exists", pill(payload.runs_dir_exists, "Found"));
        setText("netsniper-latest-run", latest.run_id || "No runs detected");
        setHtml("netsniper-import-ready", pill(payload.import_ready, "Ready"));

        setText("netsniper-paths", JSON.stringify({
          netsniper_root: payload.netsniper_root,
          netsniper_script: payload.netsniper_script,
          runs_dir: payload.runs_dir
        }, null, 2));

        setText("netsniper-latest-json", JSON.stringify(latest || {}, null, 2));

        status.textContent = payload.import_ready
          ? "Latest NetSniper run is ready for dashboard import."
          : "No completed import-ready NetSniper run was found yet.";
      } catch (error) {
        status.textContent = `NetSniper status lookup failed: ${error.message || error}`;
      }
    }

    function dashboardActionReceiptLabel(value) {
      return String(value || "")
        .replaceAll("_", " ")
        .replace(/\\b\\w/g, function (character) {
          return character.toUpperCase();
        });
    }

    function dashboardActionReceiptValue(value) {
      if (value === true) {
        return "Yes";
      }

      if (value === false) {
        return "No";
      }

      if (value === null || value === undefined || value === "") {
        return "—";
      }

      if (Array.isArray(value)) {
        return value.length ? value.join(", ") : "None";
      }

      if (typeof value === "object") {
        return Object.entries(value)
          .map(function (entry) {
            return `${dashboardActionReceiptLabel(entry[0])}: ${dashboardActionReceiptValue(entry[1])}`;
          })
          .join("; ");
      }

      return String(value);
    }

    function renderDashboardActionReceipt(target, receipt, fallbackPayload) {
      if (!target) {
        return;
      }

      const safeReceipt = receipt && typeof receipt === "object"
        ? receipt
        : {};
      const safePayload = fallbackPayload && typeof fallbackPayload === "object"
        ? fallbackPayload
        : {};
      const message = String(
        safeReceipt.message
        || safePayload.message
        || safePayload.error
        || "Action completed."
      ).trim();
      const severity = String(
        safeReceipt.severity
        || (safePayload.ok === false ? "error" : "info")
      ).toLowerCase();
      const summary = safeReceipt.summary && typeof safeReceipt.summary === "object"
        ? safeReceipt.summary
        : {};
      const identifiers = safeReceipt.identifiers && typeof safeReceipt.identifiers === "object"
        ? safeReceipt.identifiers
        : {};
      const lines = [message];

      Object.entries(summary).forEach(function (entry) {
        lines.push(
          `${dashboardActionReceiptLabel(entry[0])}: ${dashboardActionReceiptValue(entry[1])}`
        );
      });

      Object.entries(identifiers).forEach(function (entry) {
        lines.push(
          `${dashboardActionReceiptLabel(entry[0])}: ${dashboardActionReceiptValue(entry[1])}`
        );
      });

      target.textContent = lines.join("\\n");
      target.dataset.receiptSeverity = severity;
      target.dataset.receiptAction = String(safeReceipt.action || "");
    }

    async function importLatestNetSniperRun() {
      const status = document.getElementById("netsniper-status");
      const output = document.getElementById("netsniper-import-result");
      const button = document.getElementById("netsniper-import-latest");

      button.disabled = true;
      status.textContent = "Importing latest completed NetSniper run…";

      try {
        const response = await fetch("/api/netsniper/import-latest", {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
          headers: {"Content-Type": "application/json"},
          body: "{}"
        });

        let payload = {};
        try {
          payload = await response.json();
        } catch (error) {
          payload = {};
        }

        if (response.status === 401 || response.status === 403) {
          window.location.href = "/login";
          return;
        }

        if (!response.ok || !payload.ok) {
          throw new Error(payload.message || payload.error || `Import failed with HTTP ${response.status}`);
        }

        renderDashboardActionReceipt(output, payload.receipt, payload);
        status.textContent = (payload.receipt || {}).message
          || `Import complete: ${payload.run_id || "latest run"}`;
        await loadNetSniperStatus();
      } catch (error) {
        status.textContent = `Import failed: ${error.message || error}`;
        output.textContent = String(error.message || error);
      } finally {
        button.disabled = false;
      }
    }

    let selectedNetSniperJobId = "";
    let selectedNetSniperJob = null;
    let netSniperJobDetailTimer = null;

    function stopNetSniperJobDetailPolling() {
      if (netSniperJobDetailTimer !== null) {
        window.clearTimeout(netSniperJobDetailTimer);
        netSniperJobDetailTimer = null;
      }
    }

    function netSniperJobIsActive(job) {
      const status = String((job || {}).status || "").toUpperCase();
      return status === "QUEUED" || status === "RUNNING";
    }

    function scanJobStreamMeta(stream) {
      if (!stream || !stream.available) {
        return `Unavailable: ${(stream || {}).reason || "log not available"}`;
      }

      const parts = [
        `${stream.bytes_read || 0} byte(s) returned`,
        `${stream.file_size || 0} byte file`
      ];

      if (stream.truncated) { parts.push("tail truncated"); }
      if (stream.updated_at) { parts.push(`updated ${stream.updated_at}`); }
      return parts.join(" · ");
    }

    function renderNetSniperJobDetail(payload) {
      const panel = document.getElementById("netsniper-live-job-panel");
      const job = payload.job || {};
      const stdout = payload.stdout || {};
      const stderr = payload.stderr || {};
      const jobId = job.job_id || payload.job_id || selectedNetSniperJobId;

      if (!panel) { return; }

      panel.hidden = false;
      selectedNetSniperJob = job;
      setText("netsniper-live-job-heading", `Scan job ${jobId || "detail"}`);
      setText("netsniper-live-job-status", `${job.status || "UNKNOWN"} · ${job.message || "No job message"}`);
      setText("netsniper-live-job-state", job.status || "—");
      setText("netsniper-live-job-pid", job.process_pid || "—");
      setText("netsniper-live-job-heartbeat", job.heartbeat_at || "—");
      setText("netsniper-live-job-updated", job.updated_at || "—");
      setText("netsniper-live-job-cancel-requested-at", job.cancel_requested_at || "—");
      setText("netsniper-live-job-cancel-requested-by", job.cancel_requested_by || "—");
      setText("netsniper-live-job-cancelled-at", job.cancelled_at || "—");
      setText("netsniper-live-job-cancel-reason-display", job.cancel_reason || "—");
      setText("netsniper-live-job-stdout-meta", scanJobStreamMeta(stdout));
      setText("netsniper-live-job-stderr-meta", scanJobStreamMeta(stderr));
      setText("netsniper-live-job-stdout", stdout.available ? stdout.text : "—");
      setText("netsniper-live-job-stderr", stderr.available ? stderr.text : "—");

      const cancelForm = document.getElementById("netsniper-live-job-cancel-form");
      const cancelButton = document.getElementById("netsniper-live-job-cancel");
      const cancelResult = document.getElementById("netsniper-live-job-cancel-result");
      const canCancel = netSniperJobIsActive(job) && !job.cancel_requested_at;

      if (cancelForm) { cancelForm.hidden = !canCancel; }
      if (cancelButton) { cancelButton.disabled = !canCancel; }

      if (cancelResult && job.cancel_requested_at) {
        cancelResult.hidden = false;
        cancelResult.textContent = job.status === "CANCELLED"
          ? `Scan cancelled at ${job.cancelled_at || job.finished_at || "unknown time"}.`
          : `Cancellation requested by ${job.cancel_requested_by || "operator"} at ${job.cancel_requested_at}.`;
      }

      const rawLink = document.getElementById("netsniper-live-job-raw");
      if (rawLink && jobId) {
        rawLink.href = `/api/netsniper/job-detail?job_id=${encodeURIComponent(jobId)}&tail_bytes=16384`;
      }
    }

    async function loadNetSniperJobDetail(jobId) {
      const requestedJobId = String(jobId || selectedNetSniperJobId || "").trim();
      if (!requestedJobId) { return; }

      selectedNetSniperJobId = requestedJobId;
      stopNetSniperJobDetailPolling();

      const panel = document.getElementById("netsniper-live-job-panel");
      if (panel) { panel.hidden = false; }
      setText("netsniper-live-job-status", `Loading scan job ${requestedJobId}…`);

      try {
        const response = await fetch(
          `/api/netsniper/job-detail?job_id=${encodeURIComponent(requestedJobId)}&tail_bytes=16384`,
          { credentials: "same-origin", cache: "no-store" }
        );

        if (response.status === 401 || response.status === 403) {
          window.location.href = "/login";
          return;
        }

        let payload = {};
        try { payload = await response.json(); } catch (error) { payload = {}; }

        if (selectedNetSniperJobId !== requestedJobId) { return; }
        if (!response.ok || !payload.ok) {
          throw new Error(payload.error || `Job detail request failed with HTTP ${response.status}`);
        }

        renderNetSniperJobDetail(payload);

        if (netSniperJobIsActive(payload.job) && selectedNetSniperJobId === requestedJobId) {
          netSniperJobDetailTimer = window.setTimeout(function () {
            loadNetSniperJobDetail(requestedJobId);
          }, 3000);
        }
      } catch (error) {
        if (selectedNetSniperJobId === requestedJobId) {
          setText("netsniper-live-job-status", `Job detail lookup failed: ${error.message || error}`);
        }
      }
    }

    function closeNetSniperJobDetail() {
      stopNetSniperJobDetailPolling();
      selectedNetSniperJobId = "";
      selectedNetSniperJob = null;
      const panel = document.getElementById("netsniper-live-job-panel");
      const cancelForm = document.getElementById("netsniper-live-job-cancel-form");
      const cancelResult = document.getElementById("netsniper-live-job-cancel-result");
      const cancelReason = document.getElementById("netsniper-live-job-cancel-reason");

      if (panel) { panel.hidden = true; }
      if (cancelForm) { cancelForm.hidden = true; }
      if (cancelResult) { cancelResult.hidden = true; }
      if (cancelReason) { cancelReason.value = ""; }
    }

    async function cancelSelectedNetSniperJob(event) {
      event.preventDefault();

      const job = selectedNetSniperJob || {};
      const jobId = String(job.job_id || selectedNetSniperJobId || "").trim();
      const reasonInput = document.getElementById("netsniper-live-job-cancel-reason");
      const button = document.getElementById("netsniper-live-job-cancel");
      const result = document.getElementById("netsniper-live-job-cancel-result");
      const reason = String((reasonInput || {}).value || "").trim();

      if (!jobId || !netSniperJobIsActive(job)) {
        if (result) {
          result.hidden = false;
          result.textContent = "Only an active queued or running scan can be cancelled.";
        }
        return;
      }

      if (!reason) {
        if (result) {
          result.hidden = false;
          result.textContent = "A cancellation reason is required.";
        }
        if (reasonInput) { reasonInput.focus(); }
        return;
      }

      if (!window.confirm(`Cancel active scan ${jobId}?\n\nReason: ${reason}`)) {
        return;
      }

      if (button) { button.disabled = true; }
      if (reasonInput) { reasonInput.disabled = true; }
      if (result) {
        result.hidden = false;
        result.textContent = `Submitting cancellation request for ${jobId}…`;
      }

      try {
        const response = await fetch("/api/netsniper/scan-cancel", {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({job_id: jobId, reason: reason})
        });

        if (response.status === 401 || response.status === 403) {
          window.location.href = "/login";
          return;
        }

        let payload = {};
        try { payload = await response.json(); } catch (error) { payload = {}; }

        if (!response.ok || !payload.ok) {
          throw new Error(
            payload.error
            || payload.message
            || `Cancellation failed with HTTP ${response.status}`
          );
        }

        if (result) {
          result.hidden = false;
          renderDashboardActionReceipt(
          result,
          payload.receipt || {
            action: "netsniper.scan_cancel",
            severity: "info",
            message: payload.message || "Scan cancellation request accepted.",
            summary: {
              cancellation_action: payload.cancellation_action || "requested"
            },
            identifiers: {
              job_id: payload.job_id || ""
            }
          },
          payload
        );
        }

        await loadNetSniperScanJobs();
        await loadNetSniperJobDetail(jobId);
      } catch (error) {
        if (result) {
          result.hidden = false;
          result.textContent = `Cancellation failed: ${error.message || error}`;
        }
      } finally {
        if (reasonInput) { reasonInput.disabled = false; }
        if (button && netSniperJobIsActive(selectedNetSniperJob || {})) {
          button.disabled = Boolean(
            (selectedNetSniperJob || {}).cancel_requested_at
          );
        }
      }
    }

    function renderNetSniperScanJobs(payload) {
      const tbody = document.getElementById("netsniper-scan-jobs-body");
      if (!tbody) { return; }

      const jobs = Array.isArray(payload)
        ? payload
        : (payload.jobs || payload.scan_jobs || payload.items || []);

      if (!jobs.length) {
        tbody.innerHTML = '<tr><td colspan="10">No scan jobs found.</td></tr>';
        return;
      }

      tbody.innerHTML = jobs.slice(0, 10).map(function (job) {
        const jobId = job.job_id || "";
        return `
          <tr>
            <td><code>${escapeHtml(jobId || "-")}</code></td>
            <td><span class="pill">${escapeHtml(job.status || "-")}</span></td>
            <td>${escapeHtml(job.target || job.network_scope || "-")}</td>
            <td>${escapeHtml(job.scan_profile || "balanced")}</td>
            <td>${escapeHtml(job.created_at || "-")}</td>
            <td>${escapeHtml(job.updated_at || "-")}</td>
            <td>${escapeHtml(job.exit_code === null || job.exit_code === undefined ? "-" : job.exit_code)}</td>
            <td>${escapeHtml(job.bundle_path || "-")}</td>
            <td>${escapeHtml(job.message || "-")}</td>
            <td><button type="button" data-scan-job-detail="${escapeHtml(jobId)}">View details</button></td>
          </tr>
        `;
      }).join("");
    }

    async function loadNetSniperScanJobs() {
      try {
        const response = await fetch("/api/scan-jobs?limit=10", {
          credentials: "same-origin",
          cache: "no-store"
        });

        if (response.status === 401 || response.status === 403) {
          return;
        }

        if (!response.ok) {
          return;
        }

        const payload = await response.json();
        renderNetSniperScanJobs(payload);
      } catch (error) {
        const tbody = document.getElementById("netsniper-scan-jobs-body");
        if (tbody) {
          tbody.innerHTML = `<tr><td colspan="10">Scan job lookup failed: ${escapeHtml(error.message || error)}</td></tr>`;
        }
      }
    }


    function scheduleCadenceLabel(minutes) {
      const value = Number.parseInt(minutes || 60, 10);
      const labels = {
        60: "Every 1 hour",
        120: "Every 2 hours",
        360: "Every 6 hours",
        720: "Every 12 hours",
        1440: "Daily"
      };
      return labels[value] || `${value} minutes`;
    }

    function scheduleEnabledPill(schedule) {
      const enabled = Boolean(schedule && schedule.enabled);
      const cls = enabled ? "ok" : "warn";
      const label = enabled ? "Enabled" : "Disabled";
      return `<span class="pill ${cls}">${label}</span>`;
    }

    async function postNetSniperSchedule(path, payload) {
      const response = await fetch(path, {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payload || {})
      });

      let data = {};
      try {
        data = await response.json();
      } catch (error) {
        data = {};
      }

      if (response.status === 401) {
        window.location.href = "/login";
        return null;
      }

      if (response.status === 403) {
        throw new Error("ADMIN role required to manage NetSniper scan schedules.");
      }

      if (!response.ok || !data.ok) {
        throw new Error(data.message || data.error || `Schedule request failed with HTTP ${response.status}`);
      }

      return data;
    }

    function renderNetSniperSchedules(payload) {
      const tbody = document.getElementById("netsniper-schedules-body");
      if (!tbody) { return; }

      const schedules = Array.isArray(payload)
        ? payload
        : (payload.schedules || payload.items || []);

      if (!schedules.length) {
        tbody.innerHTML = '<tr><td colspan="10">No scan schedules found.</td></tr>';
        return;
      }

      tbody.innerHTML = schedules.slice(0, 20).map(function (schedule) {
        const scheduleId = schedule.schedule_id || "";
        const toggleAction = schedule.enabled ? "disable" : "enable";
        const toggleLabel = schedule.enabled ? "Disable" : "Enable";

        return `
          <tr>
            <td>${escapeHtml(schedule.name || "-")}<br><code>${escapeHtml(scheduleId || "-")}</code></td>
            <td>${scheduleEnabledPill(schedule)}</td>
            <td>${escapeHtml(schedule.target || schedule.network_scope || "-")}</td>
            <td>${escapeHtml(schedule.scan_profile || "balanced")}</td>
            <td>${escapeHtml(scheduleCadenceLabel(schedule.cadence_minutes))}</td>
            <td>${escapeHtml(schedule.next_run_at || "-")}</td>
            <td>${escapeHtml(schedule.last_run_at || "-")}</td>
            <td>${escapeHtml(schedule.last_status || "-")}</td>
            <td>${escapeHtml(schedule.last_job_id || "-")}</td>
            <td>
              <button type="button" data-schedule-action="${toggleAction}" data-schedule-id="${escapeHtml(scheduleId)}">${toggleLabel}</button>
              <button type="button" data-schedule-action="delete" data-schedule-id="${escapeHtml(scheduleId)}">Delete</button>
            </td>
          </tr>
        `;
      }).join("");
    }


    function renderNetSniperScheduleHistory(payload) {
      const tbody = document.getElementById("netsniper-schedule-history-body");
      if (!tbody) { return; }

      const rows = Array.isArray(payload) ? payload : (payload.history || []);

      if (!rows.length) {
        tbody.innerHTML = `<tr><td colspan="10">No schedule history found.</td></tr>`;
        return;
      }

      tbody.innerHTML = rows.map(function (item) {
        const job = item.job || {};
        const scheduleStatus = item.deleted
          ? "DELETED"
          : (item.last_status || (item.enabled ? "ENABLED" : "DISABLED"));
        const jobId = job.job_id || item.last_job_id || "-";
        const jobStatus = job.status || "-";
        const finishedAt = job.finished_at || "-";
        const message = job.message || item.message || "-";

        return `
          <tr>
            <td><code>${escapeHtml(item.schedule_id || "-")}</code><br>${escapeHtml(item.name || "-")}</td>
            <td>${escapeHtml(scheduleStatus)}</td>
            <td>${escapeHtml(item.target || "-")}</td>
            <td>${escapeHtml(item.scan_profile || "balanced")}</td>
            <td>${escapeHtml(item.last_run_at || "-")}</td>
            <td>${escapeHtml(item.next_run_at || "-")}</td>
            <td><code>${escapeHtml(jobId)}</code></td>
            <td>${escapeHtml(jobStatus)}</td>
            <td>${escapeHtml(finishedAt)}</td>
            <td>${escapeHtml(message)}</td>
          </tr>
        `;
      }).join("");
    }

    async function loadNetSniperScheduleHistory() {
      const tbody = document.getElementById("netsniper-schedule-history-body");

      try {
        const response = await fetch("/api/netsniper/schedule-history?limit=50", {
          credentials: "same-origin",
          cache: "no-store"
        });

        if (response.status === 401 || response.status === 403) {
          return;
        }

        if (!response.ok) {
          if (tbody) {
            tbody.innerHTML = `<tr><td colspan="10">Schedule history lookup failed with HTTP ${escapeHtml(response.status)}</td></tr>`;
          }
          return;
        }

        const payload = await response.json();
        renderNetSniperScheduleHistory(payload);
      } catch (error) {
        if (tbody) {
          tbody.innerHTML = `<tr><td colspan="10">Schedule history lookup failed: ${escapeHtml(error.message || error)}</td></tr>`;
        }
      }
    }


    async function loadNetSniperSchedules() {
      try {
        const response = await fetch("/api/netsniper/schedules", {
          credentials: "same-origin",
          cache: "no-store"
        });

        if (response.status === 401 || response.status === 403) {
          return;
        }

        if (!response.ok) {
          return;
        }

        const payload = await response.json();
        renderNetSniperSchedules(payload);
      } catch (error) {
        const tbody = document.getElementById("netsniper-schedules-body");
        if (tbody) {
          tbody.innerHTML = `<tr><td colspan="10">Schedule lookup failed: ${escapeHtml(error.message || error)}</td></tr>`;
        }
      }
    }


    function hourlyMonitoringTargetValue() {
      const hourlyTarget = document.getElementById("netsniper-hourly-monitoring-target");
      const scheduleTarget = document.getElementById("netsniper-schedule-target");
      const scanTarget = document.getElementById("netsniper-scan-target");

      const candidates = [
        hourlyTarget ? hourlyTarget.value.trim() : "",
        scheduleTarget ? scheduleTarget.value.trim() : "",
        scanTarget ? scanTarget.value.trim() : ""
      ];

      return candidates.find(function (value) { return Boolean(value); }) || "";
    }

    async function setHourlyNetSniperMonitoring(enabled) {
      const status = document.getElementById("netsniper-status");
      const output = document.getElementById("netsniper-schedule-result");
      const enableButton = document.getElementById("netsniper-hourly-monitoring-enable");
      const disableButton = document.getElementById("netsniper-hourly-monitoring-disable");
      const target = hourlyMonitoringTargetValue();

      if (enabled && !target) {
        output.textContent = "Target CIDR is required to enable hourly monitoring.";
        return;
      }

      enableButton.disabled = true;
      disableButton.disabled = true;
      status.textContent = enabled
        ? "Enabling hourly balanced monitoring…"
        : "Disabling hourly balanced monitoring…";

      try {
        const payload = await postNetSniperSchedule("/api/netsniper/hourly-monitoring", {
          target: target,
          enabled: Boolean(enabled)
        });

        if (!payload) { return; }

        renderDashboardActionReceipt(output, payload.receipt, payload);
        status.textContent = (payload.receipt || {}).message
          || (
            enabled
              ? "Hourly balanced monitoring enabled."
              : "Hourly balanced monitoring disabled."
          );

        await loadNetSniperSchedules();
      } catch (error) {
        status.textContent = `Hourly monitoring action failed: ${error.message || error}`;
        output.textContent = String(error.message || error);
      } finally {
        enableButton.disabled = false;
        disableButton.disabled = false;
      }
    }


    async function createNetSniperSchedule(event) {
      event.preventDefault();

      const status = document.getElementById("netsniper-status");
      const output = document.getElementById("netsniper-schedule-result");
      const button = document.getElementById("netsniper-schedule-create");

      const nameInput = document.getElementById("netsniper-schedule-name");
      const targetInput = document.getElementById("netsniper-schedule-target");
      const profileInput = document.getElementById("netsniper-schedule-profile");
      const cadenceInput = document.getElementById("netsniper-schedule-cadence");
      const enabledInput = document.getElementById("netsniper-schedule-enabled");
      const autoIngestInput = document.getElementById("netsniper-schedule-auto-ingest");
        const trueAegisAfterIngestInput = document.getElementById("netsniper-schedule-trueaegis-after-ingest");

      const name = nameInput ? nameInput.value.trim() : "";
      const target = targetInput ? targetInput.value.trim() : "";

      if (!name || !target) {
        output.textContent = "Schedule name and target CIDR are required.";
        return;
      }

      button.disabled = true;
      status.textContent = "Creating NetSniper scan schedule…";

      try {
        const payload = await postNetSniperSchedule("/api/netsniper/schedule-create", {
          name: name,
          target: target,
          scan_profile: profileInput ? profileInput.value : "balanced",
          cadence_minutes: cadenceInput ? Number.parseInt(cadenceInput.value, 10) : 60,
          enabled: enabledInput ? enabledInput.value === "true" : true,
          auto_ingest: autoIngestInput ? autoIngestInput.value === "true" : true,
          run_trueaegis_after_ingest: trueAegisAfterIngestInput ? trueAegisAfterIngestInput.value === "true" : false
        });

        if (!payload) { return; }

        renderDashboardActionReceipt(output, payload.receipt, payload);
        status.textContent = (payload.receipt || {}).message
          || `Created scan schedule: ${(payload.schedule || {}).schedule_id || name}`;
        await loadNetSniperSchedules();
      } catch (error) {
        status.textContent = `Schedule create failed: ${error.message || error}`;
        output.textContent = String(error.message || error);
      } finally {
        button.disabled = false;
      }
    }

    async function runDueNetSniperSchedules() {
      const status = document.getElementById("netsniper-status");
      const output = document.getElementById("netsniper-schedule-result");
      const button = document.getElementById("netsniper-schedules-run-due");

      button.disabled = true;
      status.textContent = "Running due NetSniper schedules…";

      try {
        const payload = await postNetSniperSchedule("/api/netsniper/schedule-run-due", {max_runs: 1});

        if (!payload) { return; }

        renderDashboardActionReceipt(output, payload.receipt, payload);
        status.textContent = (payload.receipt || {}).message
          || `Schedule runner complete: ${(payload.results || []).length} result(s)`;

        await loadNetSniperSchedules();
        await loadNetSniperScanJobs();
        await loadNetSniperScheduleHistory();
      } catch (error) {
        status.textContent = `Schedule runner failed: ${error.message || error}`;
        output.textContent = String(error.message || error);
      } finally {
        button.disabled = false;
      }
    }

    async function recoverStaleNetSniperScans() {
      const status = document.getElementById("netsniper-status");
      const output = document.getElementById("netsniper-schedule-result");
      const button = document.getElementById("netsniper-stale-scan-fail");
      const confirmationText = "MARK STALE SCANS FAILED";
      const confirmation = window.prompt(
        "ADMIN recovery action. Confirm no NetSniper process is active, then type: " + confirmationText
      );

      if (confirmation !== confirmationText) {
        output.textContent = "Stale scan recovery cancelled.";
        return;
      }

      button.disabled = true;
      status.textContent = "Marking stale active NetSniper scan jobs failed…";

      try {
        const payload = await postNetSniperSchedule("/api/netsniper/stale-scan-fail", {
          confirmation: confirmationText,
          stale_minutes: 360
        });

        if (!payload) { return; }

        renderDashboardActionReceipt(output, payload.receipt, payload);
        status.textContent = (payload.receipt || {}).message
          || `Stale scan recovery complete: ${payload.recovered_count || 0} job(s) marked failed`;

        await loadNetSniperSchedules();
        await loadNetSniperScanJobs();
        await loadNetSniperScheduleHistory();
      } catch (error) {
        status.textContent = `Stale scan recovery failed: ${error.message || error}`;
        output.textContent = String(error.message || error);
      } finally {
        button.disabled = false;
      }
    }


    async function handleNetSniperScheduleAction(event) {
      const button = event.target.closest("button[data-schedule-action]");
      if (!button) { return; }

      const action = button.dataset.scheduleAction;
      const scheduleId = button.dataset.scheduleId;
      const status = document.getElementById("netsniper-status");
      const output = document.getElementById("netsniper-schedule-result");

      if (!scheduleId) {
        output.textContent = "Schedule ID is missing.";
        return;
      }

      const deleteConfirmation = `DELETE SCHEDULE ${scheduleId}`;

      if (
        action === "delete"
        && !window.confirm(
          `Delete scan schedule ${scheduleId}?

`
          + "This removes only the saved schedule definition. "
          + "Existing queued or running scan jobs are not cancelled, "
          + "and completed job history is preserved. Use the dedicated "
          + "Cancel active scan control to stop an active job."
        )
      ) {
        return;
      }

      button.disabled = true;
      status.textContent = `Applying schedule action: ${action}`;

      try {
        const requestPayload = {schedule_id: scheduleId};

        if (action === "delete") {
          requestPayload.confirmation = deleteConfirmation;
        }

        const payload = await postNetSniperSchedule(
          `/api/netsniper/schedule-${action}`,
          requestPayload
        );

        if (!payload) { return; }

        renderDashboardActionReceipt(output, payload.receipt, payload);
        status.textContent = (payload.receipt || {}).message
          || (
            action === "delete"
              ? `Schedule deleted; ${payload.linked_job_count || 0} linked job(s) preserved and no active jobs cancelled.`
              : `Schedule action complete: ${action}`
          );

        await loadNetSniperSchedules();

        if (action === "delete") {
          await loadNetSniperScheduleHistory();
          await loadNetSniperScanJobs();
        }
      } catch (error) {
        status.textContent = `Schedule action failed: ${error.message || error}`;
        output.textContent = String(error.message || error);
      } finally {
        button.disabled = false;
      }
    }


    async function startNetSniperScan(event) {
      event.preventDefault();

      const status = document.getElementById("netsniper-status");
      const output = document.getElementById("netsniper-scan-start-result");
      const button = document.getElementById("netsniper-scan-start");
      const targetInput = document.getElementById("netsniper-scan-target");
      const profileInput = document.getElementById("netsniper-scan-profile");
      const target = targetInput ? targetInput.value.trim() : "";
      const scanProfile = profileInput ? profileInput.value.trim() : "balanced";

      if (!target) {
        output.textContent = "Target CIDR is required.";
        return;
      }

      button.disabled = true;
      status.textContent = "Starting guarded NetSniper scan job…";

      try {
        const response = await fetch("/api/netsniper/scan-start", {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({target: target, scan_profile: scanProfile})
        });

        let payload = {};
        try {
          payload = await response.json();
        } catch (error) {
          payload = {};
        }

        if (response.status === 401) {
          window.location.href = "/login";
          return;
        }

        if (response.status === 403) {
          throw new Error("ADMIN role required to start NetSniper scans.");
        }

        if (!response.ok || !payload.ok) {
          throw new Error(payload.message || payload.error || `Scan start failed with HTTP ${response.status}`);
        }

        renderDashboardActionReceipt(output, payload.receipt, payload);
        status.textContent = (payload.receipt || {}).message
          || `Scan job started: ${payload.job_id || "queued"}`;
        await loadNetSniperScanJobs();

        if (payload.job_id) {
          loadNetSniperJobDetail(payload.job_id);
        }
      } catch (error) {
        status.textContent = `Scan start failed: ${error.message || error}`;
        output.textContent = String(error.message || error);
      } finally {
        button.disabled = false;
      }
    }

    document.getElementById("netsniper-refresh").addEventListener("click", function () {
      loadNetSniperStatus();
      loadNetSniperScanJobs();
      loadNetSniperSchedules();
      loadNetSniperScheduleHistory();
    });
    document.getElementById("netsniper-import-latest").addEventListener("click", importLatestNetSniperRun);
    document.getElementById("netsniper-scan-start-form").addEventListener("submit", startNetSniperScan);
    document.getElementById("netsniper-schedule-create-form").addEventListener("submit", createNetSniperSchedule);
    document.getElementById("netsniper-schedules-refresh").addEventListener("click", function () {
      loadNetSniperSchedules();
      loadNetSniperScheduleHistory();
    });
    document.getElementById("netsniper-schedule-history-refresh").addEventListener("click", loadNetSniperScheduleHistory);
    document.getElementById("netsniper-schedules-run-due").addEventListener("click", runDueNetSniperSchedules);
    document.getElementById("netsniper-stale-scan-fail").addEventListener("click", recoverStaleNetSniperScans);
    document.getElementById("netsniper-hourly-monitoring-enable").addEventListener("click", function () { setHourlyNetSniperMonitoring(true); });
    document.getElementById("netsniper-hourly-monitoring-disable").addEventListener("click", function () { setHourlyNetSniperMonitoring(false); });
    document.getElementById("netsniper-schedules-body").addEventListener("click", handleNetSniperScheduleAction);
    document.getElementById("netsniper-scan-jobs-body").addEventListener("click", function (event) {
      const button = event.target.closest("button[data-scan-job-detail]");
      if (!button) { return; }
      loadNetSniperJobDetail(button.dataset.scanJobDetail || "");
    });
    document.getElementById("netsniper-live-job-refresh").addEventListener("click", function () {
      loadNetSniperJobDetail(selectedNetSniperJobId);
    });
    document.getElementById("netsniper-live-job-close").addEventListener("click", closeNetSniperJobDetail);
    document.getElementById("netsniper-live-job-cancel-form").addEventListener("submit", cancelSelectedNetSniperJob);
    window.addEventListener("beforeunload", stopNetSniperJobDetailPolling);
    loadNetSniperStatus();
    loadNetSniperScanJobs();
    loadNetSniperSchedules();
    loadNetSniperScheduleHistory();
    window.setInterval(loadNetSniperScanJobs, 5000);
    window.setInterval(loadNetSniperSchedules, 15000);
    window.setInterval(loadNetSniperScheduleHistory, 15000);
  </script>
<footer data-deltaaegis-license="AGPL-3.0-only" style="margin:2rem 0 0;padding:1rem;border-top:1px solid currentColor;opacity:.78;text-align:center;font-size:.85rem">
  DeltaAegis is licensed under AGPL-3.0-only.
  <a href="https://github.com/ParkerLee07/DeltaAegis" target="_blank" rel="noopener noreferrer">View Corresponding Source</a>.
</footer>
</body>
</html>"""


def dashboard_bind_host_is_loopback(host: str | None) -> bool:
    value = str(host or "").strip().lower()

    if value == "localhost":
        return True

    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]

    value = value.split("%", 1)[0]

    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _command_dashboard_impl(args):
    from http.cookies import SimpleCookie
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs, unquote, urlparse

    global _DASHBOARD_FORCE_SECURE_COOKIES

    # v0.42 dashboard LAN binding
    lan_mode = bool(getattr(args, "lan", False))
    bind_host = "0.0.0.0" if lan_mode else args.host
    non_loopback_bind = not dashboard_bind_host_is_loopback(bind_host)
    _DASHBOARD_FORCE_SECURE_COOKIES = bool(
        getattr(args, "secure_cookies", False)
    )
    try:
        public_origin_identity = _dashboard_public_origin_identity(
            getattr(args, "public_origin", None),
            secure_cookies=_DASHBOARD_FORCE_SECURE_COOKIES,
        )
    except ValueError as exc:
        raise DeltaAegisError(str(exc)) from exc

    db_path = args.db
    token = args.token
    setup_nonce = secrets.token_urlsafe(32)
    has_active_password_users = False
    login_required = bool(token or getattr(args, "require_login", False))

    try:
        with connect(db_path) as dashboard_auth_connection:
            has_active_password_users = dashboard_has_active_password_users(
                dashboard_auth_connection
            )
            login_required = login_required or has_active_password_users
    except Exception:
        has_active_password_users = False
        login_required = bool(token or getattr(args, "require_login", False))

    if non_loopback_bind and not (token or has_active_password_users):
        raise DeltaAegisError(
            "a non-loopback dashboard bind requires an active password user "
            "or an explicit --token; refusing unauthenticated network exposure"
        )


    class DeltaAegisDashboardHandler(BaseHTTPRequestHandler):
        server_version = "DeltaAegisDashboard/1.0-stage2"

        def log_message(self, fmt, *handler_args):
            if not args.quiet:
                sanitized_args = tuple(
                    re.sub(
                        r"([?&](?:token|access_token)=)[^&\s]*",
                        r"\1[REDACTED]",
                        str(value),
                        flags=re.IGNORECASE,
                    )
                    for value in handler_args
                )
                super().log_message(fmt, *sanitized_args)

        def send_error(self, code, message=None, explain=None):
            # BaseHTTPRequestHandler's stock HTML error omits the dashboard's
            # security boundary. Keep parser/method errors bounded and apply
            # the same headers as every other response type.
            detail = str(message or self.responses.get(code, ("Error",))[0])
            dashboard_text_response(self, detail, status=int(code))

        def dashboard_request_token(self):
            # Secrets in query strings leak into browser history and standard
            # HTTP access logs. Dashboard/API tokens are header-only.
            legacy = self.headers.get("X-DeltaAegis-Token", "").strip()
            authorization = self.headers.get("Authorization", "").strip()
            bearer = ""
            if authorization:
                scheme, separator, value = authorization.partition(" ")
                if separator and scheme.casefold() == "bearer":
                    bearer = value.strip()
            if legacy and bearer and not secrets.compare_digest(legacy, bearer):
                return ""
            return bearer or legacy

        def api_v1_bearer_token(self):
            """Return only the documented stable-API credential transport."""

            authorizations = self.headers.get_all("Authorization") or []
            if len(authorizations) > 1:
                raise _api_v1.ApiV1Error(
                    "ambiguous_credentials",
                    "Stable API requests must use exactly one Authorization Bearer credential.",
                    status=400,
                )
            if not authorizations:
                return ""
            authorization = str(authorizations[0] or "").strip()
            scheme, separator, value = authorization.partition(" ")
            if not separator or scheme.casefold() != "bearer":
                return ""
            token_value = value.strip()
            if not token_value or any(character.isspace() for character in token_value):
                return ""
            if self.headers.get("X-DeltaAegis-Token"):
                raise _api_v1.ApiV1Error(
                    "ambiguous_credentials",
                    "Stable API requests must use one Authorization Bearer credential.",
                    status=400,
                )
            return token_value

        def dashboard_setup_request_is_local(self):
            try:
                address = str(self.client_address[0] if self.client_address else "")
                address = address.split("%", 1)[0]
                return ipaddress.ip_address(address).is_loopback
            except ValueError:
                return False


        def dashboard_session_cookie_token(self):
            raw_cookie = self.headers.get("Cookie", "")

            if not raw_cookie:
                return ""

            cookie = SimpleCookie()

            try:
                cookie.load(raw_cookie)
            except Exception:
                return ""

            morsel = cookie.get(ACCESS_SESSION_COOKIE_NAME)

            if not morsel:
                return ""

            return str(morsel.value or "").strip()

        def dashboard_csrf_cookie_token(self):
            raw_cookie = self.headers.get("Cookie", "")
            if not raw_cookie:
                return ""
            cookie = SimpleCookie()
            try:
                cookie.load(raw_cookie)
            except Exception:
                return ""
            morsel = cookie.get(ACCESS_CSRF_COOKIE_NAME)
            return str(morsel.value or "").strip() if morsel else ""

        def dashboard_login_redirect(self):
            dashboard_redirect_response(self, "/login")

        def dashboard_logout_redirect(self):
            dashboard_redirect_response(
                self,
                "/login",
                cookie_header=(
                    dashboard_clear_session_cookie_header(),
                    dashboard_clear_csrf_cookie_header(),
                ),
            )

        def dashboard_legacy_actor(self, auth_type="dashboard_unauthenticated"):
            role = "ADMIN" if auth_type in {"legacy_dashboard_token", "dashboard_unauthenticated"} else "VIEWER"

            return {
                "auth_type": auth_type,
                "user_id": None,
                "username": "dashboard",
                "display_name": "DeltaAegis Dashboard",
                "role": role,
            }

        def authenticate_dashboard_request(self, required_role="VIEWER"):
            required_role = normalize_access_role(required_role)
            supplied = self.dashboard_request_token()
            self.current_actor = None

            session_token = self.dashboard_session_cookie_token()

            if session_token:
                connection = self.open_connection()

                try:
                    actor = authenticate_dashboard_session(
                        connection,
                        session_token,
                        required_role=required_role,
                    )
                finally:
                    connection.close()

                if actor:
                    self.current_actor = actor
                    return True

            if token and supplied == token:
                self.current_actor = self.dashboard_legacy_actor("legacy_dashboard_token")
                return True

            if supplied:
                connection = self.open_connection()

                try:
                    actor = authenticate_access_api_token(
                        connection,
                        supplied,
                        required_role=required_role,
                    )
                finally:
                    connection.close()

                if actor:
                    self.current_actor = actor
                    return True

            if not token and not supplied and not login_required:
                self.current_actor = self.dashboard_legacy_actor("dashboard_unauthenticated")
                return True

            return False

        def authorized(self):
            return self.authenticate_dashboard_request(required_role="VIEWER")

        def require_auth(self, required_role="VIEWER"):
            if self.authenticate_dashboard_request(required_role=required_role):
                return True

            dashboard_json_response(
                self,
                {
                    "error": "unauthorized",
                    "message": "Provide a valid X-DeltaAegis-Token header. Database-backed API tokens are supported.",
                    "required_role": normalize_access_role(required_role),
                },
                status=401,
            )

            return False

        def open_connection(self):
            return connect(db_path)

        def api_v1_send(self, payload, status=200, headers=None):
            _api_v1.validate_envelope(payload)
            response_id = str(
                (payload.get("meta") or {}).get("request_id")
                or self.api_v1_request_id()
            )
            response_headers = {"X-Request-ID": response_id}
            response_headers.update(dict(headers or {}))
            dashboard_json_response(
                self,
                payload,
                status=status,
                headers=response_headers,
            )

        def api_v1_request_id(self):
            current = getattr(self, "_api_v1_request_id", None)
            if current:
                return current
            current = _api_v1.request_id(self.headers.get("X-Request-ID"))
            self._api_v1_request_id = current
            return current

        def api_v1_error(self, code, message, status=400, details=None, headers=None):
            self.api_v1_send(
                _api_v1.error_envelope(
                    code,
                    message,
                    request_id_value=self.api_v1_request_id(),
                    details=details,
                ),
                status=status,
                headers=headers,
            )

        def api_v1_route_matches(self, route):
            value = str(route or "")
            return value == "/api/v1" or value.startswith("/api/v1/")

        def api_v1_read_json_body(self):
            if self.headers.get("Transfer-Encoding"):
                raise _api_v1.ApiV1Error(
                    "unsupported_transfer_encoding",
                    "Stable API mutations do not accept Transfer-Encoding.",
                    status=400,
                )
            lengths = self.headers.get_all("Content-Length") or []
            if len(lengths) != 1:
                raise _api_v1.ApiV1Error(
                    "length_required",
                    "Stable API mutations require one Content-Length header.",
                    status=411,
                )
            length_text = str(lengths[0]).strip()
            if re.fullmatch(r"[0-9]+", length_text) is None:
                raise _api_v1.ApiV1Error(
                    "invalid_content_length",
                    "Content-Length must be a non-negative integer.",
                    status=400,
                )
            length = int(length_text)
            if length > DASHBOARD_MAX_REQUEST_BODY_BYTES:
                self.close_connection = True
                raise _api_v1.ApiV1Error(
                    "request_too_large",
                    f"Request bodies are limited to {DASHBOARD_MAX_REQUEST_BODY_BYTES} bytes.",
                    status=413,
                )
            raw = self.rfile.read(length)
            try:
                decoded = raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise _api_v1.ApiV1Error(
                    "invalid_json_encoding",
                    "Stable API JSON bodies must use UTF-8.",
                    status=400,
                ) from exc
            try:
                payload = json.loads(decoded)
            except json.JSONDecodeError as exc:
                raise _api_v1.ApiV1Error(
                    "invalid_json",
                    "The request body is not valid JSON.",
                    status=400,
                    details={"line": exc.lineno, "column": exc.colno},
                ) from exc
            if not isinstance(payload, dict):
                raise _api_v1.ApiV1Error(
                    "invalid_json_type",
                    "Stable API JSON bodies must contain an object.",
                    status=400,
                )
            return payload

        def dashboard_host_identity(self):
            host_values = self.headers.get_all("Host") or []
            if len(host_values) != 1:
                return None
            raw = str(host_values[0] or "").strip()
            if (
                not raw
                or len(raw) > 255
                or any(character.isspace() for character in raw)
                or any(character in raw for character in "/?#@")
            ):
                return None
            try:
                parsed_host = urlsplit("//" + raw)
                hostname = str(parsed_host.hostname or "").rstrip(".").casefold()
                port = parsed_host.port
            except ValueError:
                return None
            if not hostname:
                return None
            return raw, hostname, port

        def dashboard_host_allowed(self):
            identity = self.dashboard_host_identity()
            if identity is None:
                return False
            _raw, hostname, port = identity
            if public_origin_identity is not None:
                scheme, expected_hostname, expected_port = public_origin_identity
                actual_port = port or (443 if scheme == "https" else 80)
                return (
                    hostname == expected_hostname
                    and int(actual_port) == int(expected_port)
                )
            if port is not None and int(port) != int(self.server.server_port):
                return False
            try:
                local_value = str(self.connection.getsockname()[0]).split("%", 1)[0]
                local_address = ipaddress.ip_address(local_value)
            except (AttributeError, IndexError, OSError, ValueError):
                return False
            if hostname == "localhost":
                return bool(local_address.is_loopback)
            try:
                address = ipaddress.ip_address(hostname.split("%", 1)[0])
            except ValueError:
                expected = str(bind_host or "").rstrip(".").casefold()
                return expected not in {"", "0.0.0.0", "::"} and hostname == expected
            return address == local_address

        def dashboard_origin_allowed(self):
            identity = self.dashboard_host_identity()
            origin_values = self.headers.get_all("Origin") or []
            if len(origin_values) != 1:
                return False
            origin = str(origin_values[0] or "").strip()
            if identity is None or not origin or len(origin) > 512:
                return False
            raw_host, hostname, host_port = identity
            try:
                parsed = urlsplit(origin)
                origin_port = parsed.port
            except ValueError:
                return False
            if public_origin_identity is not None:
                expected_scheme, expected_hostname, expected_port = (
                    public_origin_identity
                )
                actual_hostname = (
                    str(parsed.hostname or "").rstrip(".").casefold()
                )
                actual_port = origin_port or (
                    443 if parsed.scheme == "https" else 80
                )
                return bool(
                    self.dashboard_host_allowed()
                    and parsed.scheme == expected_scheme
                    and actual_hostname == expected_hostname
                    and int(actual_port) == int(expected_port)
                    and parsed.username is None
                    and parsed.password is None
                    and parsed.path in {"", "/"}
                    and not parsed.query
                    and not parsed.fragment
                )
            if (
                parsed.scheme
                != ("https" if _DASHBOARD_FORCE_SECURE_COOKIES else "http")
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
                or str(parsed.hostname or "").rstrip(".").casefold() != hostname
            ):
                return False
            expected_port = host_port or int(self.server.server_port)
            actual_port = origin_port or (443 if parsed.scheme == "https" else 80)
            if actual_port != expected_port:
                return False
            # raw_host is read to keep the comparison anchored to the actual
            # request header rather than any forwarded proxy value.
            return bool(raw_host)

        def enforce_host_boundary(self, route):
            if self.dashboard_host_allowed():
                return True
            if self.api_v1_route_matches(route):
                self.api_v1_error(
                    "invalid_host",
                    "The HTTP Host header is not allowed for this dashboard binding.",
                    status=400,
                )
            else:
                dashboard_json_response(
                    self,
                    {
                        "error": "invalid_host",
                        "message": "The HTTP Host header is not allowed for this dashboard binding.",
                    },
                    status=400,
                )
            return False

        def enforce_cookie_mutation_boundary(self, route):
            session_token = self.dashboard_session_cookie_token()
            if not session_token:
                return True
            connection = self.open_connection()
            try:
                actor = _auth.authenticate_dashboard_session(
                    connection,
                    session_token,
                    required_role="VIEWER",
                    update_last_seen=False,
                )
            finally:
                connection.close()
            if not actor:
                headers = {
                    "Set-Cookie": [
                        dashboard_clear_session_cookie_header(),
                        dashboard_clear_csrf_cookie_header(),
                    ]
                }
                if self.api_v1_route_matches(route):
                    self.api_v1_error(
                        "unauthorized",
                        "The dashboard session is invalid or expired.",
                        status=401,
                        headers=headers,
                    )
                else:
                    dashboard_json_response(
                        self,
                        {"error": "unauthorized", "message": "The dashboard session is invalid or expired."},
                        status=401,
                        headers=headers,
                    )
                return False
            csrf_values = self.headers.get_all("X-DeltaAegis-CSRF") or []
            csrf_header = (
                str(csrf_values[0] or "").strip()
                if len(csrf_values) == 1
                else ""
            )
            csrf_cookie = self.dashboard_csrf_cookie_token()
            valid_double_submit = bool(
                csrf_header
                and csrf_cookie
                and secrets.compare_digest(csrf_header, csrf_cookie)
            )
            if (
                not self.dashboard_origin_allowed()
                or not valid_double_submit
                or not _auth.verify_dashboard_csrf_token(actor, csrf_header)
            ):
                if self.api_v1_route_matches(route):
                    self.api_v1_error(
                        "csrf_validation_failed",
                        "Cookie-authenticated mutations require a same-origin request and valid CSRF token.",
                        status=403,
                    )
                else:
                    dashboard_json_response(
                        self,
                        {
                            "error": "csrf_validation_failed",
                            "message": "Cookie-authenticated mutations require a same-origin request and valid CSRF token.",
                        },
                        status=403,
                    )
                return False
            self.current_actor = actor
            return True

        def authenticate_api_v1(self, permission):
            self.current_actor = None
            session_token = self.dashboard_session_cookie_token()
            if session_token:
                if (
                    self.headers.get_all("Authorization")
                    or self.headers.get("X-DeltaAegis-Token")
                ):
                    self.api_v1_error(
                        "ambiguous_credentials",
                        "Stable API requests must use one credential transport.",
                        status=400,
                    )
                    return False
                connection = self.open_connection()
                try:
                    actor = _auth.authenticate_dashboard_session(
                        connection,
                        session_token,
                        required_role="VIEWER",
                    )
                finally:
                    connection.close()
                if not actor:
                    self.api_v1_error(
                        "unauthorized",
                        "The dashboard session is invalid or expired.",
                        status=401,
                        headers={
                            "Set-Cookie": [
                                dashboard_clear_session_cookie_header(),
                                dashboard_clear_csrf_cookie_header(),
                            ]
                        },
                    )
                    return False
                if not _auth.access_actor_allows_scope(actor, permission):
                    self.api_v1_error(
                        "forbidden",
                        "The authenticated role is not allowed to access this resource.",
                        status=403,
                        details={"required_scope": permission, "actor_role": actor.get("role")},
                    )
                    return False
                self.current_actor = actor
                return True

            supplied = self.api_v1_bearer_token()
            if not supplied:
                self.api_v1_error(
                    "unauthorized",
                    "Provide a scoped DeltaAegis API token using Authorization: Bearer.",
                    status=401,
                )
                return False
            connection = self.open_connection()
            try:
                actor = _auth.authenticate_scoped_access_api_token(
                    connection,
                    supplied,
                    required_scope=permission,
                )
                if actor is None:
                    known = _auth.authenticate_access_api_token(
                        connection,
                        supplied,
                        required_role="VIEWER",
                        update_last_used=False,
                    )
                else:
                    known = actor
            finally:
                connection.close()
            if actor is None:
                self.api_v1_error(
                    "forbidden" if known else "unauthorized",
                    (
                        "The API token is not bounded or does not include the required scope."
                        if known
                        else "The API token is invalid, expired, or revoked."
                    ),
                    status=403 if known else 401,
                    details={"required_scope": permission},
                )
                return False
            self.current_actor = actor
            return True

        def api_v1_scope(self, query):
            raw_scope = (query.get("scope") or [""])[0].strip()
            if not raw_scope:
                return None
            try:
                return optional_network_scope(raw_scope)
            except ValueError as exc:
                raise _api_v1.ApiV1Error(
                    "invalid_scope",
                    "scope must be a valid CIDR network",
                    status=400,
                    details={"scope": raw_scope},
                ) from exc

        def api_v1_paginate(self, items, query):
            limit, offset = _api_v1.parse_pagination(query)
            return _api_v1.paginated_envelope(
                list(items)[offset : offset + limit + 1],
                limit=limit,
                offset=offset,
                request_id_value=self.api_v1_request_id(),
            )

        def handle_api_v1_get(self, route, query):
            if route == "/api/v1":
                self.api_v1_send(
                    _api_v1.success_envelope(
                        _api_v1.api_index(),
                        request_id_value=self.api_v1_request_id(),
                    )
                )
                return
            if route == "/api/v1/openapi.json":
                document = _api_v1.openapi_document()
                _api_v1.validate_openapi_document(document)
                dashboard_json_response(
                    self,
                    document,
                    headers={"X-Request-ID": self.api_v1_request_id()},
                )
                return
            if route == "/api/v1/health":
                self.api_v1_send(
                    _api_v1.success_envelope(
                        _operations.liveness_report(),
                        request_id_value=self.api_v1_request_id(),
                    )
                )
                return

            asset_match = re.fullmatch(r"/api/v1/assets/([^/]+)", route)
            quality_match = re.fullmatch(
                r"/api/v1/telemetry-quality/decisions/([^/]+)", route
            )
            detection_match = re.fullmatch(r"/api/v1/detections/([^/]+)", route)
            permissions = {
                "/api/v1/readiness": "operations.read",
                "/api/v1/diagnostics": "operations.read",
                "/api/v1/session": "session.read",
                "/api/v1/summary": "dashboard.read",
                "/api/v1/scopes": "dashboard.read",
                "/api/v1/sensors": "dashboard.read",
                "/api/v1/sites": "dashboard.read",
                "/api/v1/assets": "dashboard.read",
                "/api/v1/events": "dashboard.read",
                "/api/v1/alerts": "dashboard.read",
                "/api/v1/scan-jobs": "dashboard.read",
                "/api/v1/validations": "dashboard.read",
                "/api/v1/telemetry-quality/decisions": "dashboard.read",
                "/api/v1/detections": "dashboard.read",
            }
            permission = permissions.get(route)
            if asset_match or quality_match or detection_match:
                permission = "dashboard.read"
            if permission is None:
                self.api_v1_error("not_found", "Stable API route not found.", status=404, details={"path": route})
                return
            if not self.authenticate_api_v1(permission):
                return

            connection = self.open_connection()
            try:
                scope = self.api_v1_scope(query)
                sensor_filter = (query.get("sensor_id") or [""])[0].strip()
                scope_id_filter = (query.get("scope_id") or [""])[0].strip()
                if route == "/api/v1/readiness":
                    payload = _api_v1.success_envelope(
                        _operations.readiness_report(
                            connection,
                            database_path=db_path,
                        ),
                        request_id_value=self.api_v1_request_id(),
                    )
                elif route == "/api/v1/diagnostics":
                    payload = _api_v1.success_envelope(
                        _operations.diagnostics_report(
                            connection,
                            database_path=db_path,
                        ),
                        request_id_value=self.api_v1_request_id(),
                    )
                elif route == "/api/v1/session":
                    actor = {
                        key: value
                        for key, value in dict(self.current_actor or {}).items()
                        if not str(key).startswith("_")
                    }
                    payload = _api_v1.success_envelope(
                        actor,
                        request_id_value=self.api_v1_request_id(),
                    )
                elif route == "/api/v1/summary":
                    payload = _api_v1.success_envelope(
                        dashboard_summary_payload(connection, scope=scope),
                        request_id_value=self.api_v1_request_id(),
                    )
                elif route == "/api/v1/scopes":
                    payload = self.api_v1_paginate(
                        _identity.list_scopes(
                            connection,
                            sensor_id=sensor_filter or None,
                        ),
                        query,
                    )
                elif route == "/api/v1/sensors":
                    payload = self.api_v1_paginate(
                        _identity.list_sensors(connection), query
                    )
                elif route == "/api/v1/sites":
                    sites = dashboard_sites_payload(connection).get("sites", [])
                    payload = self.api_v1_paginate(sites, query)
                elif route == "/api/v1/assets":
                    limit, offset = _api_v1.parse_pagination(query)
                    if sensor_filter or scope_id_filter:
                        items = _identity.list_assets(
                            connection,
                            sensor_id=sensor_filter or None,
                            scope_id=scope_id_filter or None,
                            limit=limit + 1,
                            offset=offset,
                        )
                        page_items = items
                    else:
                        items = dashboard_assets_payload(
                            connection,
                            limit + offset + 1,
                            scope=scope,
                            state=(query.get("state") or [""])[0].strip().upper() or None,
                            identity=(query.get("identity") or [""])[0].strip().upper() or None,
                        )
                        page_items = items[offset : offset + limit + 1]
                    payload = _api_v1.paginated_envelope(
                        page_items,
                        limit=limit,
                        offset=offset,
                        request_id_value=self.api_v1_request_id(),
                    )
                elif asset_match:
                    asset_key = unquote(asset_match.group(1))
                    detail = (
                        _identity.asset_detail(
                            connection,
                            asset_key=asset_key,
                            scope_id=scope_id_filter,
                        )
                        if scope_id_filter
                        else dashboard_asset_detail_payload(
                            connection,
                            asset_key,
                            scope=scope,
                            limit=50,
                        )
                    )
                    payload = _api_v1.success_envelope(
                        detail,
                        request_id_value=self.api_v1_request_id(),
                    )
                elif route == "/api/v1/events":
                    limit, offset = _api_v1.parse_pagination(query)
                    items = dashboard_events_payload(connection, limit + offset + 1, scope=scope)
                    payload = _api_v1.paginated_envelope(items[offset:], limit=limit, offset=offset, request_id_value=self.api_v1_request_id())
                elif route == "/api/v1/alerts":
                    limit, offset = _api_v1.parse_pagination(query)
                    items = dashboard_alerts_payload(connection, limit + offset + 1, scope=scope)
                    payload = _api_v1.paginated_envelope(items[offset:], limit=limit, offset=offset, request_id_value=self.api_v1_request_id())
                elif route == "/api/v1/scan-jobs":
                    limit, offset = _api_v1.parse_pagination(query)
                    items = dashboard_scan_jobs_payload(connection, limit + offset + 1)
                    payload = _api_v1.paginated_envelope(items[offset:], limit=limit, offset=offset, request_id_value=self.api_v1_request_id())
                elif route == "/api/v1/validations":
                    limit, offset = _api_v1.parse_pagination(query)
                    data = dashboard_validations_payload(connection, limit=limit + offset + 1)
                    payload = _api_v1.paginated_envelope(data.get("observations", [])[offset:], limit=limit, offset=offset, request_id_value=self.api_v1_request_id())
                elif route == "/api/v1/telemetry-quality/decisions":
                    limit, offset = _api_v1.parse_pagination(query)
                    data = dashboard_telemetry_quality_payload(
                        connection,
                        limit=limit + offset + 1,
                        scope=scope,
                        state=(query.get("state") or [""])[0].strip().upper() or None,
                    )
                    payload = _api_v1.paginated_envelope(data.get("decisions", [])[offset:], limit=limit, offset=offset, request_id_value=self.api_v1_request_id())
                elif quality_match:
                    payload = _api_v1.success_envelope(
                        dashboard_telemetry_quality_detail_payload(
                            connection, unquote(quality_match.group(1))
                        ).get("decision"),
                        request_id_value=self.api_v1_request_id(),
                    )
                elif route == "/api/v1/detections":
                    limit, offset = _api_v1.parse_pagination(query)
                    items = _detection.list_results(
                        connection,
                        sensor_id=sensor_filter or None,
                        scope_id=scope_id_filter or None,
                        disposition=(query.get("disposition") or [""])[0].strip().upper() or None,
                        limit=limit + 1,
                        offset=offset,
                    )
                    payload = _api_v1.paginated_envelope(
                        items,
                        limit=limit,
                        offset=offset,
                        request_id_value=self.api_v1_request_id(),
                    )
                elif detection_match:
                    payload = _api_v1.success_envelope(
                        _detection.result_by_id(
                            connection,
                            unquote(detection_match.group(1)),
                        ),
                        request_id_value=self.api_v1_request_id(),
                    )
                else:
                    raise _api_v1.ApiV1Error("not_found", "Stable API route not found.", status=404)
            except _api_v1.ApiV1Error:
                raise
            except (DeltaAegisError, ValueError) as exc:
                raise _api_v1.ApiV1Error(
                    "invalid_request",
                    str(exc),
                    status=getattr(exc, "status_code", 400),
                ) from exc
            finally:
                connection.close()
            self.api_v1_send(payload)

        def handle_api_v1_post(self, route):
            detection_review_match = re.fullmatch(
                r"/api/v1/detections/([^/]+)/reviews", route
            )
            permissions = {
                "/api/v1/sites": "sites.write",
                "/api/v1/sensors": "identity.sensors.write",
            }
            permission = permissions.get(route)
            if detection_review_match:
                permission = "detection.review"
            if permission is None:
                self.api_v1_error("not_found", "Stable API route not found.", status=404, details={"path": route})
                return
            if not self.authenticate_api_v1(permission):
                return
            content_types = self.headers.get_all("Content-Type") or []
            media_type = (
                str(content_types[0] if len(content_types) == 1 else "")
                .split(";", 1)[0]
                .strip()
                .casefold()
            )
            if media_type != "application/json":
                self.api_v1_error("unsupported_media_type", "Stable API mutations require application/json.", status=415)
                return
            payload = self.api_v1_read_json_body()

            connection = self.open_connection()
            reservation = None
            try:
                idempotency_values = self.headers.get_all("Idempotency-Key") or []
                if len(idempotency_values) != 1:
                    raise _api_v1.ApiV1Error(
                        "invalid_idempotency_key",
                        "Stable API mutations require exactly one Idempotency-Key header.",
                        status=400,
                    )
                reservation = _api_v1.reserve_idempotency_key(
                    connection,
                    actor=self.current_actor or {},
                    method="POST",
                    route=route,
                    key=str(idempotency_values[0]),
                    payload=payload,
                )
                if reservation["replay"]:
                    self.api_v1_send(
                        reservation["payload"],
                        status=reservation["status"],
                        headers={"Idempotency-Replayed": "true"},
                    )
                    return

                connection.execute("BEGIN IMMEDIATE")
                if route == "/api/v1/sites":
                    result = dashboard_site_action_payload(
                        connection,
                        "/api/site-create",
                        payload,
                        actor=self.current_actor,
                        source_ip=self.client_address[0] if self.client_address else None,
                        user_agent=self.headers.get("User-Agent", ""),
                    )
                    audit_action = "API_V1_SITE_CREATE"
                    target_type = "logical_site"
                    target_key = str(
                        ((result.get("site") or {}).get("site_id") or "")
                    )
                elif route == "/api/v1/sensors":
                    allowed = {
                        "sensor_id",
                        "display_name",
                        "trust_domain",
                        "network_scopes",
                        "metadata",
                    }
                    unexpected = sorted(set(payload) - allowed)
                    if unexpected:
                        raise _api_v1.ApiV1Error(
                            "invalid_sensor",
                            "sensor enrollment contains unsupported fields",
                            status=400,
                            details={"fields": unexpected},
                        )
                    result = _identity.register_sensor(
                        connection,
                        sensor_id=payload.get("sensor_id"),
                        display_name=payload.get("display_name"),
                        trust_domain=payload.get("trust_domain") or _identity.DEFAULT_TRUST_DOMAIN,
                        network_scopes=payload.get("network_scopes") or (),
                        metadata=payload.get("metadata") or {},
                        actor=self.current_actor,
                    )
                    audit_action = "API_V1_SENSOR_ENROLL"
                    target_type = "sensor"
                    target_key = str(result.get("sensor_id") or "")
                elif detection_review_match:
                    allowed = {"action", "reason"}
                    unexpected = sorted(set(payload) - allowed)
                    if unexpected:
                        raise _api_v1.ApiV1Error(
                            "invalid_detection_review",
                            "detection review contains unsupported fields",
                            status=400,
                            details={"fields": unexpected},
                        )
                    result = _detection.review_result(
                        connection,
                        result_id=unquote(detection_review_match.group(1)),
                        action=payload.get("action"),
                        reason=payload.get("reason"),
                        actor=self.current_actor,
                    )
                    audit_action = "API_V1_DETECTION_REVIEW"
                    target_type = "detection_result"
                    target_key = str(result.get("result_id") or "")
                else:
                    raise _api_v1.ApiV1Error(
                        "not_found", "Stable API route not found.", status=404
                    )
                _auth.record_access_audit_event(
                    connection,
                    audit_action,
                    actor=self.current_actor,
                    target_type=target_type,
                    target_key=target_key,
                    source_ip=(
                        self.client_address[0] if self.client_address else None
                    ),
                    user_agent=self.headers.get("User-Agent", ""),
                    details={"stable_api_route": route},
                )
                response = _api_v1.success_envelope(
                    result,
                    request_id_value=self.api_v1_request_id(),
                )
                _api_v1.complete_idempotency_key(
                    connection,
                    idempotency_id=reservation["idempotency_id"],
                    status=201,
                    payload=response,
                )
                connection.commit()
                self.api_v1_send(response, status=201)
            except _api_v1.ApiV1Error:
                if connection.in_transaction:
                    connection.rollback()
                raise
            except (DashboardAdminUserActionError, DeltaAegisError, ValueError) as exc:
                if connection.in_transaction:
                    connection.rollback()
                response = _api_v1.error_envelope(
                    "mutation_failed",
                    str(exc),
                    request_id_value=self.api_v1_request_id(),
                )
                if reservation and not reservation.get("replay"):
                    _api_v1.complete_idempotency_key(
                        connection,
                        idempotency_id=reservation["idempotency_id"],
                        status=getattr(exc, "status_code", 400),
                        payload=response,
                    )
                self.api_v1_send(
                    response,
                    status=getattr(exc, "status_code", 400),
                )
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                response = _api_v1.error_envelope(
                    "internal_error",
                    "The stable API mutation could not be completed.",
                    request_id_value=self.api_v1_request_id(),
                )
                if reservation and not reservation.get("replay"):
                    _api_v1.complete_idempotency_key(
                        connection,
                        idempotency_id=reservation["idempotency_id"],
                        status=500,
                        payload=response,
                    )
                self.api_v1_send(response, status=500)
            finally:
                connection.close()


        def require_permission(self, permission: str):
            required_role = access_rbac_required_role(permission)

            # v0.27 RBAC semantics:
            # - Missing/invalid browser login on HTML pages redirects to /login.
            # - Missing/invalid API/token authentication returns 401.
            # - Valid authentication with a role below the permission returns 403.
            session_token = self.dashboard_session_cookie_token()

            if session_token:
                if self.authenticate_dashboard_request(required_role="VIEWER"):
                    actor = getattr(self, "current_actor", None)

                    if actor and access_role_allows(actor.get("role"), required_role):
                        return True

                    dashboard_json_response(
                        self,
                        {
                            "error": "forbidden",
                            "message": "The authenticated role is not allowed to access this DeltaAegis resource.",
                            "required_role": normalize_access_role(required_role),
                            "actor_role": normalize_access_role(actor.get("role") if actor else None),
                        },
                        status=403,
                    )
                    return False

                route = self.path.split("?", 1)[0]
                if route in {"/", "/operator", "/operator/users", "/operator/reset", "/operator/telemetry-quality", "/netsniper"}:
                    self.dashboard_logout_redirect()
                else:
                    dashboard_json_response(
                        self,
                        {
                            "error": "unauthorized",
                            "message": "The dashboard session is invalid or expired.",
                            "required_role": normalize_access_role(required_role),
                        },
                        status=401,
                        headers={
                            "Set-Cookie": dashboard_clear_session_cookie_header(),
                        },
                    )
                return False

            # Preserve browser UX compatibility for protected HTML pages.
            route = self.path.split("?", 1)[0]
            request_token = self.dashboard_request_token()

            if not request_token and route in {"/", "/operator", "/operator/users", "/operator/telemetry-quality"}:
                self.dashboard_login_redirect()
                return False

            # Non-browser access and token/API requests continue to use the
            # existing auth path.
            return self.require_auth(required_role=required_role)




        def do_GET(self):
            parsed = urlparse(self.path)
            route = parsed.path
            query = parse_qs(parsed.query)

            if not self.enforce_host_boundary(route):
                return

            if self.api_v1_route_matches(route):
                try:
                    self.handle_api_v1_get(route, query)
                except _api_v1.ApiV1Error as exc:
                    self.api_v1_error(
                        exc.code,
                        str(exc),
                        status=exc.status,
                        details=exc.details,
                    )
                except Exception:
                    self.api_v1_error(
                        "internal_error",
                        "The stable API request could not be completed.",
                        status=500,
                    )
                return

            if route == "/healthz":
                dashboard_text_response(self, "ok")
                return

            if route == "/setup":
                if not self.dashboard_setup_request_is_local():
                    dashboard_json_response(
                        self,
                        {
                            "error": "setup_local_only",
                            "message": "First-admin setup is available only from a loopback client.",
                        },
                        status=403,
                    )
                    return
                connection = self.open_connection()

                try:
                    setup_required = dashboard_first_admin_setup_required(connection)
                finally:
                    connection.close()

                if not setup_required:
                    dashboard_redirect_response(self, "/login")
                    return

                dashboard_html_response(
                    self,
                    dashboard_first_admin_setup_html(setup_nonce=setup_nonce),
                )
                return

            if route == "/login":
                connection = self.open_connection()

                try:
                    setup_required = dashboard_first_admin_setup_required(connection)
                finally:
                    connection.close()

                if setup_required:
                    dashboard_redirect_response(self, "/setup")
                    return

                # Login must remain a public browser page. Use silent auth here;
                # do not call require_auth() or require_permission(), because
                # those helpers emit JSON 401/403 responses for protected routes.
                if self.authenticate_dashboard_request(required_role="VIEWER"):
                    dashboard_redirect_response(self, "/")
                    return

                dashboard_html_response(self, dashboard_login_html())
                return

            if route == "/logout":
                dashboard_json_response(
                    self,
                    {
                        "error": "method_not_allowed",
                        "message": "Logout is a state-changing action and requires POST.",
                    },
                    status=405,
                    headers={"Allow": "POST"},
                )
                return

            if route == "/":
                if not self.authenticate_dashboard_request(required_role="VIEWER"):
                    self.dashboard_login_redirect()
                    return

                dashboard_html_response(self, dashboard_index_html())
                return

            if route == "/operator":
                if not self.require_permission("operator.session.read"):
                    return
                dashboard_html_response(self, dashboard_operator_session_shell_html())
                return

            if route == "/operator/telemetry-quality":
                if not self.require_permission("operator.session.read"):
                    return
                dashboard_html_response(
                    self,
                    dashboard_telemetry_quality_shell_html(),
                )
                return

            if not self.require_permission("dashboard.read"):
                return

            if route == "/operator/users":
                if not self.require_permission("admin.users.read"):
                    return
                dashboard_html_response(self, dashboard_operator_users_shell_html())
                return

            if route == "/operator/reset":
                if not self.require_permission("admin.telemetry.cleanup"):
                    return
                dashboard_html_response(self, dashboard_operator_reset_shell_html())
                return

            if route == "/netsniper":
                dashboard_html_response(self, render_netsniper_page())
                return

            if route == "/api/netsniper/schedules":
                connection = self.open_connection()

                try:
                    dashboard_json_response(
                        self,
                        {
                            "ok": True,
                            "schedules": dashboard_scan_schedules_payload(connection),
                        },
                    )
                finally:
                    connection.close()

                return

            if route == "/api/netsniper/schedule-history":
                query = urllib.parse.parse_qs(parsed.query or "")
                limit = max(
                    1,
                    min(
                        safe_int(query.get("limit", ["50"])[0]) or 50,
                        200,
                    ),
                )
                scope = query.get("scope", [""])[0].strip() or None
                connection = self.open_connection()

                try:
                    dashboard_json_response(
                        self,
                        dashboard_netsniper_schedule_history_payload(
                            connection,
                            limit=limit,
                            scope=scope,
                        ),
                    )
                finally:
                    connection.close()

                return

            if route == "/api/netsniper/job-detail":
                query = urllib.parse.parse_qs(parsed.query or "")
                job_id = query.get("job_id", [""])[0]
                tail_bytes = query.get(
                    "tail_bytes",
                    [str(SCAN_JOB_LOG_TAIL_DEFAULT_BYTES)],
                )[0]
                connection = self.open_connection()

                try:
                    payload = dashboard_scan_job_detail_payload(
                        connection,
                        job_id=job_id,
                        tail_bytes=tail_bytes,
                        logs_root=DEFAULT_SCAN_LOGS,
                    )

                    if payload.get("ok"):
                        response_status = 200
                    elif payload.get("error") == "scan job not found":
                        response_status = 404
                    else:
                        response_status = 400

                    dashboard_json_response(
                        self,
                        payload,
                        status=response_status,
                    )
                finally:
                    connection.close()

                return

            if route == "/api/netsniper/status":
                dashboard_json_response(self, dashboard_netsniper_status_payload())
                return

            if route == "/api/session":
                dashboard_json_response(
                    self,
                    dashboard_session_payload(getattr(self, "current_actor", None)),
                )
                return

            if route == "/api/telemetry-cleanup/audit-events":
                if not self.require_permission("admin.telemetry.cleanup"):
                    return

                query = urllib.parse.parse_qs(parsed.query or "")
                limit = max(
                    1,
                    min(
                        safe_int(query.get("limit", ["20"])[0]) or 20,
                        200,
                    ),
                )
                connection = self.open_connection()

                try:
                    dashboard_json_response(
                        self,
                        dashboard_telemetry_cleanup_audit_events_payload(
                            connection,
                            limit=limit,
                        ),
                    )
                finally:
                    connection.close()

                return

            if route == "/api/telemetry-cleanup/preview":
                if not self.require_permission("admin.telemetry.cleanup"):
                    return

                connection = self.open_connection()

                try:
                    dashboard_json_response(
                        self,
                        dashboard_telemetry_cleanup_preview_payload(connection),
                    )
                finally:
                    connection.close()

                return

            try:
                limit = int(query.get("limit", ["20"])[0])
            except ValueError:
                limit = 20

            limit = max(1, min(limit, 200))

            raw_scope = query.get("scope", [args.scope or ""])[0]
            scope = None

            if raw_scope:
                try:
                    scope = optional_network_scope(raw_scope)
                except ValueError:
                    dashboard_json_response(
                        self,
                        {
                            "error": "invalid_scope",
                            "scope": raw_scope,
                            "message": "Scope must be a valid CIDR network, such as 192.168.4.0/24.",
                        },
                        status=400,
                    )
                    return

            site_id = query.get("site_id", [""])[0].strip()

            if scope and site_id:
                dashboard_json_response(
                    self,
                    {
                        "ok": False,
                        "error": "ambiguous_scope_selection",
                        "message": (
                            "Use either scope or site_id, not both."
                        ),
                        "scope": scope,
                        "site_id": site_id,
                    },
                    status=400,
                )
                return

            state = query.get("state", [""])[0].strip().upper() or None
            identity = query.get("identity", [""])[0].strip().upper() or None

            allowed_states = {"ACTIVE", "MISSING", "REMOVED", "EPHEMERAL_MISSING"}
            allowed_identities = {"GLOBAL_MAC", "LOCAL_MAC", "IP_ONLY"}

            if state and state not in allowed_states:
                dashboard_json_response(
                    self,
                    {
                        "error": "invalid_state",
                        "state": state,
                        "allowed": sorted(allowed_states),
                    },
                    status=400,
                )
                return

            if identity and identity not in allowed_identities:
                dashboard_json_response(
                    self,
                    {
                        "error": "invalid_identity",
                        "identity": identity,
                        "allowed": sorted(allowed_identities),
                    },
                    status=400,
                )
                return

            connection = self.open_connection()

            try:
                if (
                    site_id
                    and route
                    not in {"/api/sites", "/api/site-detail"}
                ):
                    try:
                        site_payload = dashboard_site_route_payload(
                            connection,
                            route,
                            query,
                            site_id,
                            limit=limit,
                            state=state,
                            identity=identity,
                        )
                    except DeltaAegisError as exc:
                        dashboard_json_response(
                            self,
                            {
                                "ok": False,
                                "error": "logical_site_not_found",
                                "site_id": site_id,
                                "message": str(exc),
                            },
                            status=404,
                        )
                        return

                    if site_payload is None:
                        dashboard_json_response(
                            self,
                            {
                                "ok": False,
                                "error": (
                                    "site_aggregation_not_supported"
                                ),
                                "site_id": site_id,
                                "path": route,
                                "message": (
                                    "This endpoint remains "
                                    "subnet-scoped. Select one member "
                                    "subnet before using it."
                                ),
                            },
                            status=400,
                        )
                        return

                    dashboard_json_response(
                        self,
                        site_payload,
                    )
                    return

                if route == "/api/sites":
                    dashboard_json_response(
                        self,
                        dashboard_sites_payload(connection),
                    )
                elif route == "/api/site-management":
                    dashboard_json_response(
                        self,
                        dashboard_site_management_payload(connection),
                    )
                elif route == "/api/site-detail":
                    site_id = query.get("site_id", [""])[0].strip()

                    if not site_id:
                        dashboard_json_response(
                            self,
                            {
                                "ok": False,
                                "error": "site_id_required",
                                "message": (
                                    "site_id query parameter is required"
                                ),
                            },
                            status=400,
                        )
                    else:
                        try:
                            site_payload = (
                                dashboard_site_detail_payload(
                                    connection,
                                    site_id,
                                )
                            )
                        except DeltaAegisError as exc:
                            dashboard_json_response(
                                self,
                                {
                                    "ok": False,
                                    "error": "logical_site_not_found",
                                    "site_id": site_id,
                                    "message": str(exc),
                                },
                                status=404,
                            )
                        else:
                            dashboard_json_response(
                                self,
                                site_payload,
                            )
                elif route == "/api/scopes":
                    dashboard_json_response(self, dashboard_scopes_payload(connection))
                elif route == "/api/summary":
                    dashboard_json_response(self, dashboard_summary_payload(connection, scope=scope))
                elif route == "/api/scan-context":
                    dashboard_json_response(self, dashboard_scan_context_payload(connection, scope=scope))
                elif route == "/api/trueaegis/context":
                    dashboard_json_response(
                        self,
                        dashboard_trueaegis_orchestration_context_payload(
                            connection,
                            scope=scope,
                        ),
                    )
                elif route == "/api/validation-summary":
                    dashboard_json_response(self, dashboard_validation_summary_payload(connection))
                elif route == "/api/validations":
                    dashboard_json_response(self, dashboard_validations_payload(connection, limit=25))

                elif route == "/api/validation-correlations":
                    query = parse_qs(parsed.query)
                    try:
                        limit = int(query.get("limit", ["50"])[0] or "50")
                    except (TypeError, ValueError):
                        limit = 50
                    scope = query.get("scope", [""])[0].strip() or None
                    status = query.get("status", [""])[0].strip() or None
                    dashboard_json_response(
                        self,
                        dashboard_validation_correlations_payload(
                            connection,
                            limit=limit,
                            scope=scope,
                            status=status,
                        ),
                    )
                elif route == "/api/telemetry-quality":
                    state_filter = query.get("state", [""])[0].strip() or None
                    try:
                        quality_payload = dashboard_telemetry_quality_payload(
                            connection,
                            limit=limit,
                            scope=scope,
                            state=state_filter,
                        )
                    except (DeltaAegisError, ValueError) as exc:
                        dashboard_json_response(
                            self,
                            {
                                "ok": False,
                                "error": "telemetry_quality_query_failed",
                                "message": str(exc),
                            },
                            status=400,
                        )
                    else:
                        dashboard_json_response(self, quality_payload)
                elif route == "/api/telemetry-quality/detail":
                    decision_id = query.get(
                        "decision_id",
                        [""],
                    )[0].strip()
                    if not decision_id:
                        dashboard_json_response(
                            self,
                            {
                                "ok": False,
                                "error": "decision_id_required",
                                "message": (
                                    "decision_id query parameter is required"
                                ),
                            },
                            status=400,
                        )
                    else:
                        try:
                            detail = (
                                dashboard_telemetry_quality_detail_payload(
                                    connection,
                                    decision_id,
                                )
                            )
                        except DeltaAegisError as exc:
                            dashboard_json_response(
                                self,
                                {
                                    "ok": False,
                                    "error": "quality_decision_not_found",
                                    "message": str(exc),
                                },
                                status=404,
                            )
                        else:
                            dashboard_json_response(self, detail)
                elif route == "/api/current-state":
                    dashboard_json_response(self, dashboard_current_state_payload(connection, scope=scope))
                elif route == "/api/latest-network-changes":
                    dashboard_json_response(
                        self,
                        dashboard_latest_network_changes_payload(
                            connection,
                            limit=limit,
                            scope=scope,
                        ),
                    )
                elif route == "/api/scan-freshness":
                    dashboard_json_response(
                        self,
                        dashboard_scan_freshness_payload(
                            connection,
                            scope=scope,
                        ),
                    )
                elif route == "/api/scan-jobs":
                    status_filter = query.get("status", [""])[0].strip() or None
                    dashboard_json_response(
                        self,
                        dashboard_scan_jobs_payload(
                            connection,
                            limit=limit,
                            scope=scope,
                            status=status_filter,
                        ),
                    )
                elif route == "/api/trueaegis-jobs":
                    status_filter = query.get("status", [""])[0].strip() or None
                    dashboard_json_response(
                        self,
                        dashboard_trueaegis_jobs_payload(
                            connection,
                            limit=limit,
                            scope=scope,
                            status=status_filter,
                        ),
                    )
                elif route == "/api/assets":
                    dashboard_json_response(
                        self,
                        dashboard_assets_payload(
                            connection,
                            limit,
                            scope=scope,
                            state=state,
                            identity=identity,
                        ),
                    )
                elif route == "/api/asset":
                    identifier = query.get("identifier", query.get("asset_key", [""]))[0].strip()

                    dashboard_json_response(
                        self,
                        dashboard_asset_detail_payload(
                            connection,
                            identifier,
                            scope=scope,
                            limit=limit,
                        ),
                    )
                elif route == "/api/intelligence-host":
                    identifier = query.get("identity", query.get("host", [""]))[0].strip()

                    dashboard_json_response(
                        self,
                        dashboard_netsniper_intelligence_host_payload(
                            connection,
                            identifier,
                        ),
                    )
                elif route == "/api/ticket-evidence":
                    subject_key = query.get("subject_key", [""])[0]
                    evidence_limit = query.get("limit", ["10"])[0]
                    payload = dashboard_ticket_evidence_payload(
                        connection,
                        subject_key=subject_key,
                        scope=scope,
                        limit=evidence_limit,
                    )
                    dashboard_json_response(self, payload)
                elif route == "/api/investigation-center":
                    ticket_status = query.get("ticket_status", ["ALL"])[0]
                    ticket_signal = query.get("ticket_signal", ["ALL"])[0]
                    triage_bucket = query.get("triage_bucket", ["ALL"])[0]
                    triage_urgency = query.get("triage_urgency", ["ALL"])[0]

                    dashboard_json_response(
                        self,
                        dashboard_investigation_center_payload(
                            connection,
                            limit=limit,
                            scope=scope,
                            ticket_status=ticket_status,
                            ticket_signal=ticket_signal,
                            triage_bucket=triage_bucket,
                            triage_urgency=triage_urgency,
                        ),
                    )
                elif route == "/api/events":
                    dashboard_json_response(self, dashboard_events_payload(connection, limit, scope=scope))
                elif route == "/api/alerts":
                    dashboard_json_response(self, dashboard_alerts_payload(connection, limit, scope=scope))
                elif route == "/api/port-behavior":
                    lookback_value = query.get("lookback", ["5"])[0]

                    try:
                        lookback_limit = max(1, min(25, int(lookback_value)))
                    except ValueError:
                        lookback_limit = 5

                    dashboard_json_response(
                        self,
                        dashboard_port_behavior_payload(
                            connection,
                            limit=limit,
                            scope=scope,
                            lookback=lookback_limit,
                        ),
                    )
                elif route == "/api/current-risk":
                    dashboard_json_response(self, dashboard_current_risk_payload(connection, limit, scope=scope))
                elif route == "/api/risk":
                    dashboard_json_response(self, dashboard_risk_payload(connection, limit, scope=scope))
                elif route == "/api/annotations":
                    dashboard_json_response(self, dashboard_annotations_payload(connection, limit, scope=scope))
                elif route == "/api/admin/users":
                    if not self.require_permission("admin.users.read"):
                        return
                    dashboard_json_response(
                        self,
                        dashboard_admin_users_payload(connection),
                    )
                elif route == "/api/access-audit":
                    if not self.require_permission("admin.audit.read"):
                        return
                    action_filter = query.get("action", [""])[0].strip() or None
                    actor_filter = query.get("actor", [""])[0].strip() or None
                    target_type_filter = query.get("target_type", [""])[0].strip() or None

                    dashboard_json_response(
                        self,
                        dashboard_access_audit_payload(
                            connection,
                            limit=limit,
                            action=action_filter,
                            actor=actor_filter,
                            target_type=target_type_filter,
                        ),
                    )
                else:
                    dashboard_json_response(
                        self,
                        {
                            "error": "not_found",
                            "path": route,
                        },
                        status=404,
                    )
            finally:
                connection.close()

        def do_POST(self):
            parsed = urlparse(self.path)
            route = parsed.path

            if not self.enforce_host_boundary(route):
                return

            if (
                self.api_v1_route_matches(route)
                and self.dashboard_session_cookie_token()
                and (
                    self.headers.get_all("Authorization")
                    or self.headers.get("X-DeltaAegis-Token")
                )
            ):
                self.api_v1_error(
                    "ambiguous_credentials",
                    "Stable API requests must use one credential transport.",
                    status=400,
                )
                return

            if route not in {"/setup", "/login"}:
                if not self.enforce_cookie_mutation_boundary(route):
                    return

            if self.api_v1_route_matches(route):
                try:
                    self.handle_api_v1_post(route)
                except _api_v1.ApiV1Error as exc:
                    self.api_v1_error(
                        exc.code,
                        str(exc),
                        status=exc.status,
                        details=exc.details,
                    )
                except Exception:
                    self.api_v1_error(
                        "internal_error",
                        "The stable API mutation could not be completed.",
                        status=500,
                    )
                return

            if route == "/setup":
                if not self.dashboard_setup_request_is_local():
                    dashboard_json_response(
                        self,
                        {
                            "error": "setup_local_only",
                            "message": "First-admin setup is available only from a loopback client.",
                        },
                        status=403,
                    )
                    return
                connection = self.open_connection()

                try:
                    setup_required = dashboard_first_admin_setup_required(connection)
                finally:
                    connection.close()

                if not setup_required:
                    dashboard_json_response(
                        self,
                        {
                            "error": "setup_disabled",
                            "message": "First-admin setup is disabled because a dashboard account already exists.",
                        },
                        status=403,
                    )
                    return

                try:
                    content_length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    content_length = 0

                content_length = max(0, min(content_length, 16384))
                raw_body = self.rfile.read(content_length).decode("utf-8", errors="replace")
                form = parse_qs(raw_body)

                username = form.get("username", [""])[0].strip()
                display_name = form.get("display_name", [""])[0].strip()
                password = form.get("password", [""])[0]
                password_confirm = form.get("password_confirm", [""])[0]
                supplied_setup_nonce = form.get("setup_nonce", [""])[0]

                if non_loopback_bind and not secrets.compare_digest(
                    str(supplied_setup_nonce),
                    setup_nonce,
                ):
                    dashboard_html_response(
                        self,
                        dashboard_first_admin_setup_html(
                            "Setup form expired or could not be verified. Reload and try again.",
                            setup_nonce=setup_nonce,
                        ),
                        status=403,
                    )
                    return

                if not username:
                    dashboard_html_response(
                        self,
                        dashboard_first_admin_setup_html(
                            "Username is required.",
                            setup_nonce=setup_nonce,
                        ),
                    )
                    return

                try:
                    username = normalize_access_username(username)
                except DeltaAegisError as exc:
                    dashboard_html_response(
                        self,
                        dashboard_first_admin_setup_html(
                            str(exc),
                            setup_nonce=setup_nonce,
                        ),
                        status=400,
                    )
                    return

                try:
                    validate_access_password(password)
                except DeltaAegisError as exc:
                    dashboard_html_response(
                        self,
                        dashboard_first_admin_setup_html(
                            str(exc),
                            setup_nonce=setup_nonce,
                        ),
                        status=400,
                    )
                    return

                if password != password_confirm:
                    dashboard_html_response(
                        self,
                        dashboard_first_admin_setup_html(
                            "Passwords do not match.",
                            setup_nonce=setup_nonce,
                        ),
                    )
                    return

                connection = self.open_connection()

                try:
                    # Serialize the check and first-user insert. Without this
                    # lock, simultaneous setup requests can both become ADMIN.
                    connection.execute("BEGIN IMMEDIATE")
                    if not dashboard_first_admin_setup_required(connection):
                        connection.rollback()
                        dashboard_json_response(
                            self,
                            {
                                "error": "setup_disabled",
                                "message": "First-admin setup is disabled because a dashboard account already exists.",
                            },
                            status=403,
                        )
                        return

                    create_access_user(
                        connection,
                        username,
                        display_name=display_name or username,
                        role="ADMIN",
                        password=password,
                    )
                    connection.commit()

                    session = dashboard_user_login(
                        connection,
                        username,
                        password,
                        source_ip=self.client_address[0] if self.client_address else None,
                        user_agent=self.headers.get("User-Agent", ""),
                    )
                    connection.commit()
                except Exception:
                    if connection.in_transaction:
                        connection.rollback()
                    raise
                finally:
                    connection.close()

                if not session:
                    dashboard_redirect_response(self, "/login")
                    return

                dashboard_redirect_response(
                    self,
                    "/",
                    cookie_header=(
                        dashboard_session_cookie_header(session["session_token"]),
                        dashboard_csrf_cookie_header(session["csrf_token"]),
                    ),
                )
                return

            if route == "/login":
                try:
                    content_length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    content_length = 0

                content_length = max(0, min(content_length, 16384))
                raw_body = self.rfile.read(content_length).decode("utf-8", errors="replace")
                form = parse_qs(raw_body)
                username = form.get("username", [""])[0].strip()
                password = form.get("password", [""])[0]

                connection = self.open_connection()

                try:
                    try:
                        session = dashboard_user_login(
                            connection,
                            username,
                            password,
                            source_ip=self.client_address[0] if self.client_address else None,
                            user_agent=self.headers.get("User-Agent", ""),
                        )
                    except DashboardLoginRateLimitedError as exc:
                        connection.rollback()
                        dashboard_html_response(
                            self,
                            dashboard_login_html(
                                message="Too many login attempts. Try again later.",
                                username=username,
                            ),
                            status=429,
                            headers={"Retry-After": str(exc.retry_after)},
                        )
                        return
                    except DeltaAegisError:
                        # Invalid username syntax is an authentication failure,
                        # not an uncaught request-handler exception.
                        connection.rollback()
                        session = None
                finally:
                    connection.close()

                if not session:
                    dashboard_html_response(
                        self,
                        dashboard_login_html(
                            message="Invalid username or password.",
                            username=username,
                        ),
                    )
                    return

                dashboard_redirect_response(
                    self,
                    "/",
                    cookie_header=(
                        dashboard_session_cookie_header(session["session_token"]),
                        dashboard_csrf_cookie_header(session["csrf_token"]),
                    ),
                )
                return

            if route == "/logout":
                session_token = self.dashboard_session_cookie_token()

                if session_token:
                    connection = self.open_connection()

                    try:
                        actor = authenticate_dashboard_session(
                            connection,
                            session_token,
                            required_role="VIEWER",
                            update_last_seen=False,
                        )
                        expire_dashboard_session(
                            connection,
                            session_token,
                            actor=actor,
                            reason="logout",
                        )
                    finally:
                        connection.close()

                self.dashboard_logout_redirect()
                return

            if route in DASHBOARD_SITE_ACTION_ROUTES:
                if not self.require_permission("sites.write"):
                    return

                connection = self.open_connection()
                payload: dict[str, Any] = {}

                try:
                    payload = dashboard_read_request_payload(
                        self
                    )
                    result = dashboard_site_action_payload(
                        connection,
                        route,
                        payload,
                        actor=getattr(
                            self,
                            "current_actor",
                            None,
                        ),
                        source_ip=(
                            self.client_address[0]
                            if self.client_address
                            else None
                        ),
                        user_agent=self.headers.get(
                            "User-Agent",
                            "",
                        ),
                    )
                    connection.commit()
                except (
                    DashboardAdminUserActionError,
                    DeltaAegisError,
                    ValueError,
                ) as exc:
                    connection.rollback()

                    try:
                        record_access_audit_event(
                            connection,
                            action="LOGICAL_SITE_DASHBOARD_ACTION_FAILED",
                            actor=getattr(
                                self,
                                "current_actor",
                                None,
                            ),
                            target_type="logical_site",
                            target_key=str(
                                payload.get("site_id")
                                or route
                            ),
                            source_ip=(
                                self.client_address[0]
                                if self.client_address
                                else None
                            ),
                            user_agent=self.headers.get(
                                "User-Agent",
                                "",
                            ),
                            details={
                                "route": route,
                                "error": str(exc),
                                "payload_fields": sorted(
                                    str(key)
                                    for key in payload
                                ),
                            },
                        )
                        connection.commit()
                    except Exception:
                        connection.rollback()

                    dashboard_admin_json_error_response(
                        self,
                        str(exc),
                        status_code=getattr(
                            exc,
                            "status_code",
                            400,
                        ),
                    )
                    return
                finally:
                    connection.close()

                dashboard_json_response(self, result)
                return

            if route in {
                "/api/telemetry-quality/review",
                "/api/telemetry-quality/override",
            }:
                permission = (
                    "telemetry.quality.override"
                    if route.endswith("/override")
                    else "telemetry.quality.review"
                )
                if not self.require_permission(permission):
                    return

                actor = getattr(self, "current_actor", None)
                if not actor or actor.get("auth_type") != "dashboard_session":
                    dashboard_json_response(
                        self,
                        {
                            "ok": False,
                            "error": "dashboard_session_required",
                            "message": (
                                "Telemetry-quality review and override require "
                                "an authenticated dashboard session."
                            ),
                        },
                        status=403,
                    )
                    return

                try:
                    quality_payload = dashboard_read_request_payload(self)
                except DashboardAdminUserActionError as exc:
                    dashboard_admin_json_error_response(
                        self,
                        str(exc),
                        status_code=exc.status_code,
                    )
                    return

                connection = self.open_connection()
                try:
                    if route.endswith("/override"):
                        result = (
                            dashboard_telemetry_quality_override_payload(
                                connection,
                                quality_payload,
                                actor=actor,
                                source_ip=(
                                    self.client_address[0]
                                    if self.client_address
                                    else None
                                ),
                                user_agent=self.headers.get(
                                    "User-Agent",
                                    "",
                                ),
                            )
                        )
                    else:
                        result = (
                            dashboard_telemetry_quality_review_payload(
                                connection,
                                quality_payload,
                                actor=actor,
                                source_ip=(
                                    self.client_address[0]
                                    if self.client_address
                                    else None
                                ),
                                user_agent=self.headers.get(
                                    "User-Agent",
                                    "",
                                ),
                            )
                        )
                    connection.commit()
                except (DeltaAegisError, ValueError) as exc:
                    connection.rollback()
                    dashboard_json_response(
                        self,
                        {
                            "ok": False,
                            "error": "telemetry_quality_action_failed",
                            "message": str(exc),
                        },
                        status=400,
                    )
                    return
                finally:
                    connection.close()

                dashboard_json_response(self, result)
                return

            if route == "/api/admin/users" or route.startswith("/api/admin/users/"):
                if not self.require_permission("admin.users.write"):
                    return

                connection = self.open_connection()

                try:
                    payload = dashboard_read_request_payload(self)
                    result = dashboard_admin_handle_user_action(
                        connection,
                        route,
                        payload,
                        getattr(self, "current_actor", None),
                    )
                    connection.commit()
                except DashboardAdminUserActionError as exc:
                    connection.rollback()
                    dashboard_admin_json_error_response(
                        self,
                        str(exc),
                        status_code=getattr(exc, "status_code", 400),
                    )
                    return
                except DeltaAegisError as exc:
                    connection.rollback()
                    dashboard_admin_json_error_response(
                        self,
                        str(exc),
                        status_code=400,
                    )
                    return
                finally:
                    connection.close()

                dashboard_json_response(self, result)
                return

            if route == "/api/telemetry-cleanup/clear-all":
                if not self.require_permission("admin.telemetry.cleanup"):
                    return

                try:
                    payload = dashboard_read_request_payload(self)
                    connection = self.open_connection()

                    try:
                        result = dashboard_telemetry_cleanup_clear_all_payload(
                            connection,
                            payload,
                            actor=getattr(self, "current_actor", None),
                            source_ip=self.client_address[0] if self.client_address else None,
                            user_agent=self.headers.get("User-Agent", ""),
                        )
                        connection.commit()
                    finally:
                        connection.close()

                    dashboard_json_response(self, result)
                except DeltaAegisError as exc:
                    dashboard_json_response(
                        self,
                        {
                            "ok": False,
                            "error": "telemetry_cleanup_failed",
                            "message": str(exc),
                            "confirmation_required": TELEMETRY_CLEANUP_CONFIRMATION,
                        },
                        status=400,
                    )

                return

            if route in {
                "/api/netsniper/schedule-create",
                "/api/netsniper/schedule-enable",
                "/api/netsniper/schedule-disable",
                "/api/netsniper/schedule-delete",
                "/api/netsniper/schedule-run-due",
                "/api/netsniper/stale-scan-fail",
                "/api/netsniper/hourly-monitoring",
            }:
                required_permission = (
                    "admin.telemetry.cleanup"
                    if route == "/api/netsniper/stale-scan-fail"
                    else "scan.start"
                )

                if not self.require_permission(required_permission):
                    return

                try:
                    payload = dashboard_read_request_payload(self)
                except DashboardAdminUserActionError as exc:
                    dashboard_admin_json_error_response(
                        self,
                        str(exc),
                        status_code=exc.status_code,
                    )
                    return

                connection = self.open_connection()

                try:
                    result = dashboard_netsniper_schedule_action_payload(
                        connection,
                        route,
                        payload,
                        args.events,
                    )
                    connection.commit()
                except DashboardAdminUserActionError as exc:
                    connection.rollback()
                    dashboard_admin_json_error_response(
                        self,
                        str(exc),
                        status_code=exc.status_code,
                    )
                    return
                except DeltaAegisError as exc:
                    connection.rollback()
                    dashboard_admin_json_error_response(
                        self,
                        str(exc),
                        status_code=400,
                    )
                    return
                finally:
                    connection.close()

                dashboard_json_response(self, result)
                return

            if route == "/api/trueaegis/run":
                if not self.require_permission("scan.start"):
                    return

                try:
                    content_length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    content_length = 0

                if content_length > 65536:
                    dashboard_json_response(
                        self,
                        {
                            "ok": False,
                            "error": "body_too_large",
                            "message": "POST body is too large.",
                        },
                        status=413,
                    )
                    return

                payload = {}

                if content_length > 0:
                    try:
                        raw_body = self.rfile.read(content_length).decode("utf-8")
                        payload = json.loads(raw_body)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        dashboard_json_response(
                            self,
                            {
                                "ok": False,
                                "error": "invalid_json",
                                "message": "POST body must be valid JSON.",
                            },
                            status=400,
                        )
                        return

                    if not isinstance(payload, dict):
                        dashboard_json_response(
                            self,
                            {
                                "ok": False,
                                "error": "invalid_json",
                                "message": "POST body must be a JSON object.",
                            },
                            status=400,
                        )
                        return

                connection = self.open_connection()

                try:
                    try:
                        result = dashboard_trueaegis_validation_start_payload(
                            connection,
                            payload,
                            args.db,
                        )
                    except DeltaAegisError as exc:
                        connection.rollback()
                        dashboard_json_response(
                            self,
                            {
                                "ok": False,
                                "error": "trueaegis_run_failed",
                                "message": str(exc),
                            },
                            status=400,
                        )
                        return

                    dashboard_json_response(self, result, status=202)
                    return
                finally:
                    connection.close()

            if route == "/api/netsniper/scan-cancel":
                if not self.require_permission("scan.start"):
                    return

                try:
                    content_length = int(
                        self.headers.get("Content-Length", "0")
                    )
                except ValueError:
                    content_length = 0

                if content_length <= 0:
                    dashboard_json_response(
                        self,
                        {
                            "ok": False,
                            "error": "missing_body",
                            "message": "POST body must be JSON.",
                        },
                        status=400,
                    )
                    return

                if content_length > 65536:
                    dashboard_json_response(
                        self,
                        {
                            "ok": False,
                            "error": "body_too_large",
                            "message": "POST body is too large.",
                        },
                        status=413,
                    )
                    return

                try:
                    payload = dashboard_read_request_payload(self)
                except DashboardAdminUserActionError as exc:
                    dashboard_admin_json_error_response(
                        self,
                        str(exc),
                        status_code=exc.status_code,
                    )
                    return

                connection = self.open_connection()

                try:
                    try:
                        result = dashboard_netsniper_scan_cancel_payload(
                            connection,
                            payload,
                            actor=getattr(
                                self,
                                "current_actor",
                                None,
                            ),
                            source_ip=(
                                self.client_address[0]
                                if self.client_address
                                else None
                            ),
                            user_agent=self.headers.get(
                                "User-Agent",
                                "",
                            ),
                        )
                        connection.commit()
                    except DashboardAdminUserActionError as exc:
                        connection.rollback()
                        dashboard_admin_json_error_response(
                            self,
                            str(exc),
                            status_code=exc.status_code,
                        )
                        return
                    except DeltaAegisError as exc:
                        connection.rollback()
                        dashboard_admin_json_error_response(
                            self,
                            str(exc),
                            status_code=400,
                        )
                        return

                    dashboard_json_response(self, result)
                    return
                finally:
                    connection.close()

            if route == "/api/netsniper/scan-start":
                if not self.require_permission("scan.start"):
                    return

                try:
                    content_length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    content_length = 0

                if content_length <= 0:
                    dashboard_json_response(
                        self,
                        {
                            "ok": False,
                            "error": "missing_body",
                            "message": "POST body must be JSON.",
                        },
                        status=400,
                    )
                    return

                if content_length > 65536:
                    dashboard_json_response(
                        self,
                        {
                            "ok": False,
                            "error": "body_too_large",
                            "message": "POST body is too large.",
                        },
                        status=413,
                    )
                    return

                try:
                    raw_body = self.rfile.read(content_length).decode("utf-8")
                    payload = json.loads(raw_body)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    dashboard_json_response(
                        self,
                        {
                            "ok": False,
                            "error": "invalid_json",
                            "message": "POST body must be valid JSON.",
                        },
                        status=400,
                    )
                    return

                connection = self.open_connection()

                try:
                    try:
                        result = dashboard_netsniper_scan_start_payload(
                            connection,
                            payload,
                            args.db,
                            args.events,
                        )
                    except DeltaAegisError as exc:
                        connection.rollback()
                        dashboard_json_response(
                            self,
                            {
                                "ok": False,
                                "error": "netsniper_scan_start_failed",
                                "message": str(exc),
                            },
                            status=400,
                        )
                        return

                    dashboard_json_response(self, result)
                    return
                finally:
                    connection.close()

            if not self.require_permission("workflow.write"):
                return

            if route not in {"/api/investigate-asset", "/api/ticket-status", "/api/netsniper/import-latest", "/api/validation-ingest"}:
                dashboard_json_response(
                    self,
                    {
                        "error": "not_found",
                        "path": route,
                    },
                    status=404,
                )
                return

            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                content_length = 0

            if content_length <= 0:
                dashboard_json_response(
                    self,
                    {
                        "error": "missing_body",
                        "message": "POST body must be JSON.",
                    },
                    status=400,
                )
                return

            if content_length > 65536:
                dashboard_json_response(
                    self,
                    {
                        "error": "body_too_large",
                        "message": "POST body is too large.",
                    },
                    status=413,
                )
                return

            try:
                raw_body = self.rfile.read(content_length).decode("utf-8")
                payload = json.loads(raw_body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                dashboard_json_response(
                    self,
                    {
                        "error": "invalid_json",
                        "message": "POST body must be valid JSON.",
                    },
                    status=400,
                )
                return


            if route == "/api/validation-ingest":
                connection = self.open_connection()

                try:
                    try:
                        result = dashboard_trueaegis_validation_ingest_payload(
                            connection,
                            payload,
                        )
                    except DeltaAegisError as exc:
                        connection.rollback()
                        dashboard_json_response(
                            self,
                            {
                                "ok": False,
                                "error": "validation_ingest_failed",
                                "message": str(exc),
                            },
                            status=400,
                        )
                        return

                    dashboard_json_response(self, result)
                    return
                finally:
                    connection.close()

            if route == "/api/netsniper/import-latest":
                connection = self.open_connection()

                try:
                    try:
                        payload = dashboard_netsniper_import_latest_payload(
                            connection,
                            args.events,
                        )
                    except DeltaAegisError as exc:
                        dashboard_json_response(
                            self,
                            {
                                "ok": False,
                                "error": "netsniper_import_failed",
                                "message": str(exc),
                            },
                            status=400,
                        )
                        return

                    dashboard_json_response(self, payload)
                    return
                finally:
                    connection.close()

            if route == "/api/ticket-status":
                subject_key = str(
                    payload.get("subject_key")
                    or payload.get("identifier")
                    or ""
                ).strip()
                raw_scope = str(payload.get("scope") or "").strip()
                status = str(payload.get("status") or "").strip()
                note = str(payload.get("note") or payload.get("reason") or "").strip()
                analyst = str(payload.get("analyst") or "dashboard").strip()

                try:
                    scope = optional_network_scope(raw_scope) if raw_scope else None
                    connection = self.open_connection()

                    try:
                        state = set_ticket_state(
                            connection,
                            subject_key,
                            status,
                            analyst=analyst,
                            note=note,
                        )
                        record_access_audit_event(
                            connection,
                            action="DASHBOARD_TICKET_STATUS_UPDATE",
                            actor=getattr(self, "current_actor", None),
                            target_type="investigation_ticket",
                            target_key=state.get("ticket_key") or subject_key,
                            source_ip=self.client_address[0] if self.client_address else None,
                            user_agent=self.headers.get("User-Agent", ""),
                            details={
                                "subject_key": subject_key,
                                "scope": raw_scope,
                                "status": status,
                                "analyst": analyst,
                                "note_present": bool(note),
                            },
                        )
                        connection.commit()
                        investigation_center = dashboard_investigation_center_payload(
                            connection,
                            limit=25,
                            scope=scope,
                        )

                        dashboard_json_response(
                            self,
                            {
                                "ok": True,
                                "ticket_state": state,
                                "investigation_center": investigation_center,
                                "receipt": dashboard_ticket_status_action_receipt(
                                    state,
                                    subject_key,
                                    raw_scope,
                                ),
                            },
                        )
                    finally:
                        connection.close()
                except (DeltaAegisError, ValueError) as exc:
                    dashboard_json_response(
                        self,
                        {
                            "ok": False,
                            "error": "ticket_status_failed",
                            "message": str(exc),
                        },
                        status=400,
                    )

                return

            identifier = str(payload.get("identifier") or "").strip()
            raw_scope = str(payload.get("scope") or "").strip()
            status = str(payload.get("status") or "").strip()
            reason = str(payload.get("reason") or "").strip()

            try:
                scope = optional_network_scope(raw_scope) if raw_scope else None
                connection = self.open_connection()

                try:
                    asset_key, resolved_scope = resolve_asset_for_investigation(
                        connection,
                        identifier,
                        scope=scope,
                    )
                    record = set_asset_investigation_status(
                        connection,
                        asset_key,
                        resolved_scope,
                        status,
                        reason,
                    )

                    record_access_audit_event(
                        connection,
                        action="DASHBOARD_ASSET_INVESTIGATION_UPDATE",
                        actor=getattr(self, "current_actor", None),
                        target_type="asset_investigation",
                        target_key=asset_key,
                        source_ip=self.client_address[0] if self.client_address else None,
                        user_agent=self.headers.get("User-Agent", ""),
                        details={
                            "identifier": identifier,
                            "asset_key": asset_key,
                            "scope": resolved_scope,
                            "status": status,
                            "reason_present": bool(reason),
                        },
                    )
                    connection.commit()

                    ticket_state = None
                    workflow_status = (
                        str(status or "")
                        .strip()
                        .upper()
                        .replace("-", "_")
                        .replace(" ", "_")
                    )

                    if workflow_status in TICKET_WORKFLOW_STATUSES:
                        ticket_state = set_ticket_state(
                            connection,
                            asset_key,
                            workflow_status,
                            analyst="dashboard",
                            note=reason,
                        )

                    connection.commit()

                    detail = dashboard_asset_detail_payload(
                        connection,
                        asset_key,
                        scope=resolved_scope,
                    )

                    dashboard_json_response(
                        self,
                        {
                            "ok": True,
                            "asset_key": asset_key,
                            "scope": resolved_scope,
                            "investigation": record,
                            "ticket_state": ticket_state,
                            "asset_detail": detail,
                                "receipt": dashboard_asset_investigation_action_receipt(
                                    record,
                                    asset_key,
                                    resolved_scope,
                                    ticket_state,
                                ),
                        },
                    )
                finally:
                    connection.close()
            except (DeltaAegisError, ValueError) as exc:
                dashboard_json_response(
                    self,
                    {
                        "ok": False,
                        "error": "investigation_status_failed",
                        "message": str(exc),
                    },
                    status=400,
                )

        def handle_unsupported_http_method(self):
            parsed = urlparse(self.path)
            route = parsed.path
            if not self.enforce_host_boundary(route):
                return
            if self.api_v1_route_matches(route):
                self.api_v1_error(
                    "method_not_allowed",
                    "The HTTP method is not allowed for this stable API route.",
                    status=405,
                    details={"method": self.command, "path": route},
                    headers={"Allow": "GET, POST"},
                )
                return
            self.send_error(501, "Unsupported method")

        def do_PUT(self):
            self.handle_unsupported_http_method()

        def do_PATCH(self):
            self.handle_unsupported_http_method()

        def do_DELETE(self):
            self.handle_unsupported_http_method()

        def do_OPTIONS(self):
            self.handle_unsupported_http_method()

    # Reconcile dead rows at every dashboard start, even when the recurring
    # schedule worker is disabled.
    startup_watchdog_connection = connect(db_path)

    try:
        startup_watchdog = scan_job_watchdog_recover_dead_jobs(
            startup_watchdog_connection,
            actor="dashboard_startup",
            events_path=args.events,
            trueaegis_execution_mode="asynchronous",
        )
    finally:
        startup_watchdog_connection.close()

    if startup_watchdog.get("recovered_count") and not args.quiet:
        print(
            "[DeltaAegis] scan watchdog recovered "
            f"{startup_watchdog['recovered_count']} dead scan job(s)",
            flush=True,
        )

    server_address = (bind_host, args.port)
    server = ThreadingHTTPServer(
        server_address,
        DeltaAegisDashboardHandler,
    )

    dashboard_schedule_worker_thread = None
    dashboard_schedule_worker_stop = None
    schedule_worker_interval = max(
        1,
        int(
            getattr(
                args,
                "schedule_worker_interval_seconds",
                DASHBOARD_SCHEDULE_WORKER_INTERVAL_SECONDS,
            )
            or DASHBOARD_SCHEDULE_WORKER_INTERVAL_SECONDS
        ),
    )

    if getattr(args, "enable_scheduled_scans", True):
        dashboard_schedule_worker_thread, dashboard_schedule_worker_stop = dashboard_start_schedule_worker_thread(
            db_path=db_path,
            events_path=args.events,
            interval_seconds=schedule_worker_interval,
            quiet=args.quiet,
        )

    print("DeltaAegis dashboard starting")
    print("============================")
    configured_public_origin = str(
        getattr(args, "public_origin", None) or ""
    ).strip()
    print(
        "URL:      "
        + (
            configured_public_origin.rstrip("/")
            if configured_public_origin
            else f"http://{bind_host}:{args.port}"
        )
    )
    if configured_public_origin:
        print(f"Backend:  http://{bind_host}:{args.port}")
    print(f"Database: {db_path}")
    print("Mode:     dashboard + investigation status updates")
    if getattr(args, "enable_scheduled_scans", True):
        print(f"Scheduler: enabled, checks due NetSniper schedules every {schedule_worker_interval}s")
    else:
        print("Scheduler: disabled")

    if token:
        print("Auth:     token required")
        print("Header:   X-DeltaAegis-Token")
        print("DB Tokens: accepted via X-DeltaAegis-Token")
    elif login_required:
        print("Auth:     username/password login required")
        print("Login:    http://{host}:{port}/login".format(host=bind_host, port=args.port))
        print("Sessions: HttpOnly SameSite=Strict cookie")
        print("DB Tokens: still accepted for automation via X-DeltaAegis-Token")
    else:
        print("Auth:     disabled")
        print("Warning:  bind to 127.0.0.1 unless you are using a trusted network")
        print("DB Tokens: accepted when supplied in X-DeltaAegis-Token")
        print("Tip:      set a password on an active user to enable browser login")

    print()
    print("Press Ctrl+C to stop.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard.")
    finally:
        if dashboard_schedule_worker_stop is not None:
            dashboard_schedule_worker_stop.set()
        if dashboard_schedule_worker_thread is not None:
            dashboard_schedule_worker_thread.join(timeout=2.0)
            if dashboard_schedule_worker_thread.is_alive():
                print(
                    "[DeltaAegis] waiting for the active scheduled "
                    "scan to finalize before dashboard shutdown",
                    flush=True,
                )
                dashboard_schedule_worker_thread.join()
        server.server_close()

    return 0

def command_dashboard(args, *, namespace: dict[str, Any]):
    install_namespace(namespace)
    return _command_dashboard_impl(args)
