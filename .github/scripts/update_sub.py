#!/usr/bin/env python3
"""Fetch public proxy feeds and write a deterministic Base64 subscription."""

import base64
import binascii
import ipaddress
import json
import os
import re
import socket
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_FEED_BYTES = 5 * 1024 * 1024
MAX_SOURCES = 100
FETCH_TIMEOUT_SECONDS = 20
SUPPORTED_SCHEMES = {
    "http",
    "https",
    "hysteria2",
    "hy2",
    "shadowsocks",
    "socks",
    "socks4",
    "socks5",
    "socks5h",
    "ss",
    "trojan",
    "tuic",
    "vless",
    "vmess",
}


class SubscriptionError(Exception):
    """An input, feed, or output error safe to show in workflow logs."""


def _decode_base64(value):
    compact = re.sub(r"\s+", "", value)
    if not compact or len(compact) % 4 == 1:
        return None
    compact += "=" * (-len(compact) % 4)
    try:
        return base64.b64decode(compact, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return None


def _valid_host_port(parsed):
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    return bool(
        hostname
        and not re.search(r"[\s\x00-\x1f]", hostname)
        and port is not None
        and 1 <= port <= 65535
    )


def _valid_vmess(uri):
    encoded = uri[len("vmess://"):].split("#", 1)[0]
    raw = _decode_base64(encoded)
    if raw is None:
        return False
    try:
        data = json.loads(raw.decode("utf-8"))
        port = int(data.get("port", 0))
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError, TypeError, ValueError):
        return False
    address = data.get("add") if isinstance(data, dict) else None
    identity = data.get("id") if isinstance(data, dict) else None
    return bool(
        isinstance(address, str)
        and address
        and not re.search(r"[\s\x00-\x1f]", address)
        and 1 <= port <= 65535
        and isinstance(identity, str)
        and identity
    )


def _valid_shadowsocks(uri):
    parsed = urlsplit(uri)
    if _valid_host_port(parsed):
        if parsed.username and parsed.password:
            return True
        if parsed.username and not parsed.password:
            decoded_userinfo = _decode_base64(parsed.username)
            if decoded_userinfo is not None:
                try:
                    method, password = decoded_userinfo.decode("utf-8").split(":", 1)
                    if method and password:
                        return True
                except (UnicodeDecodeError, ValueError):
                    pass

    # Legacy SIP002 links encode method:password@host:port as one Base64 token.
    token = parsed.netloc.split("@", 1)[0]
    decoded = _decode_base64(token)
    if decoded is None:
        return False
    try:
        credentials = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return bool(re.match(r"^[^:@/\s]+:.+@[^:@/\s]+:\d{1,5}$", credentials))


def is_valid_node(uri):
    if not uri or uri != uri.strip() or re.search(r"[\x00-\x20\x7f]", uri):
        return False
    scheme, separator, _ = uri.partition("://")
    scheme = scheme.lower()
    if not separator or scheme not in SUPPORTED_SCHEMES:
        return False
    if scheme == "vmess":
        return _valid_vmess(uri)
    try:
        parsed = urlsplit(uri)
        if scheme in {"ss", "shadowsocks"}:
            return _valid_shadowsocks(uri)
        if not _valid_host_port(parsed):
            return False
        if scheme in {"vless", "trojan", "hysteria2", "hy2", "tuic"}:
            return bool(parsed.username)
        return True
    except ValueError:
        return False


def _extract_nodes(content):
    text = content.decode("utf-8-sig").strip()
    if not text:
        raise SubscriptionError("feed contains no nodes")

    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not any("://" in line for line in lines):
        decoded = _decode_base64(text)
        if decoded is not None:
            try:
                decoded_text = decoded.decode("utf-8-sig").strip()
                decoded_lines = [
                    line.strip()
                    for line in decoded_text.splitlines()
                    if line.strip() and not line.lstrip().startswith("#")
                ]
                if decoded_lines:
                    lines = decoded_lines
            except UnicodeDecodeError:
                pass

    if not lines or any(not is_valid_node(line) for line in lines):
        raise SubscriptionError("feed contains invalid nodes")
    return lines


def _validate_public_https_url(url):
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or re.search(r"[\s\x00-\x20\x7f]", url)
        ):
            raise ValueError
        host = parsed.hostname.rstrip(".").lower()
        if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
            raise ValueError

        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            addresses = [
                ipaddress.ip_address(result[4][0].split("%", 1)[0])
                for result in socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
            ]
        if not addresses or any(not address.is_global for address in addresses):
            raise ValueError
        return parsed
    except (OSError, UnicodeError, ValueError):
        raise SubscriptionError("source URL must resolve only to public HTTPS addresses") from None


class _HTTPSOnlyRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        _validate_public_https_url(new_url)
        return super().redirect_request(request, response, code, message, headers, new_url)


def _fetch_feed(url, source_number):
    try:
        _validate_public_https_url(url)
        request = Request(url, headers={"User-Agent": "VPN-Subscription-Sync/1.0"})
        with build_opener(_HTTPSOnlyRedirectHandler()).open(
            request, timeout=FETCH_TIMEOUT_SECONDS
        ) as response:
            _validate_public_https_url(response.geturl())
            content = response.read(MAX_FEED_BYTES + 1)
    except (HTTPError, OSError, URLError, SubscriptionError, ValueError):
        raise SubscriptionError(f"source {source_number} could not be fetched safely") from None
    if len(content) > MAX_FEED_BYTES:
        raise SubscriptionError(f"source {source_number} exceeds the size limit")
    try:
        return _extract_nodes(content)
    except (UnicodeDecodeError, SubscriptionError):
        raise SubscriptionError(f"source {source_number} is empty or invalid") from None


def source_urls(value):
    if not value or not value.strip():
        raise SubscriptionError("VPN_SOURCE_URLS is unset or empty")
    urls = [
        line.strip()
        for line in value.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not urls:
        raise SubscriptionError("VPN_SOURCE_URLS contains no source URLs")
    if len(urls) > MAX_SOURCES:
        raise SubscriptionError("VPN_SOURCE_URLS contains too many sources")
    for index, url in enumerate(urls, start=1):
        try:
            parsed = urlsplit(url)
            if (
                parsed.scheme.lower() != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or re.search(r"[\s\x00-\x20\x7f]", url)
            ):
                raise ValueError
        except ValueError:
            raise SubscriptionError(f"source {index} must be a public HTTPS URL") from None
    return urls


def build_subscription(urls):
    nodes = set()
    for index, url in enumerate(urls, start=1):
        nodes.update(_fetch_feed(url, index))
    if not nodes:
        raise SubscriptionError("sources contain no valid nodes")
    node_data = ("\n".join(sorted(nodes)) + "\n").encode("utf-8")
    return base64.b64encode(node_data).decode("ascii") + "\n"


def main():
    try:
        urls = source_urls(os.environ.get("VPN_SOURCE_URLS", ""))
        subscription = build_subscription(urls)
        output_path = sys.argv[1] if len(sys.argv) > 1 else "sub.txt"
        with open(output_path, "w", encoding="ascii", newline="\n") as output:
            output.write(subscription)
    except SubscriptionError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except OSError:
        print("Error: could not write subscription output", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
