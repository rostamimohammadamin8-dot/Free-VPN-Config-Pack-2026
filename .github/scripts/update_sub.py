#!/usr/bin/env python3
"""Fetch public proxy feeds and write a deterministic Base64 subscription."""

import base64
import binascii
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
from urllib.parse import quote, urljoin, urlsplit

MAX_FEED_BYTES = 5 * 1024 * 1024
MAX_SOURCES = 100
FETCH_TIMEOUT_SECONDS = 20
MAX_REDIRECTS = 5
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


def _resolve_public_https_url(url):
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
            addresses = []
            for result in socket.getaddrinfo(
                host, parsed.port or 443, type=socket.SOCK_STREAM
            ):
                address = ipaddress.ip_address(result[4][0].split("%", 1)[0])
                if address not in addresses:
                    addresses.append(address)
        if not addresses or any(not address.is_global for address in addresses):
            raise ValueError
        return parsed, [str(address) for address in addresses]
    except (OSError, UnicodeError, ValueError):
        raise SubscriptionError("source URL must resolve only to public HTTPS addresses") from None


def _validate_public_https_url(url):
    return _resolve_public_https_url(url)[0]


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, address, port, timeout):
        super().__init__(
            hostname,
            port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self._connect_address = address

    def connect(self):
        raw_socket = socket.create_connection(
            (self._connect_address, self.port),
            self.timeout,
            self.source_address,
        )
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


def _fetch_url(url):
    current_url = url
    for redirect_count in range(MAX_REDIRECTS + 1):
        parsed, addresses = _resolve_public_https_url(current_url)
        hostname = parsed.hostname.encode("idna").decode("ascii")
        port = parsed.port or 443
        target = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
        if parsed.query:
            target += "?" + quote(parsed.query, safe="/?@!$&'()*+,;=:-._~")
        host_header = f"[{hostname}]" if ":" in hostname else hostname
        if port != 443:
            host_header += f":{port}"

        last_error = None
        response = None
        connection = None
        for address in addresses:
            connection = _PinnedHTTPSConnection(
                hostname, address, port, FETCH_TIMEOUT_SECONDS
            )
            try:
                connection.request(
                    "GET",
                    target,
                    headers={
                        "Host": host_header,
                        "User-Agent": "VPN-Subscription-Sync/1.0",
                        "Connection": "close",
                    },
                )
                response = connection.getresponse()
                break
            except (OSError, ssl.SSLError, http.client.HTTPException) as error:
                last_error = error
                connection.close()
                connection = None
        if response is None:
            if last_error is not None:
                raise last_error
            raise SubscriptionError("feed connection failed")

        try:
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                if not location or redirect_count == MAX_REDIRECTS:
                    raise SubscriptionError("feed redirect limit exceeded")
                current_url = urljoin(current_url, location)
                continue
            if response.status != 200:
                raise SubscriptionError("feed returned an unsuccessful status")
            return response.read(MAX_FEED_BYTES + 1)
        finally:
            connection.close()
    raise SubscriptionError("feed redirect limit exceeded")


def _fetch_feed(url, source_number):
    try:
        content = _fetch_url(url)
    except (
        OSError,
        UnicodeError,
        ssl.SSLError,
        http.client.HTTPException,
        SubscriptionError,
        ValueError,
    ):
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
