import base64
import json
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

from update_sub import (
    SubscriptionError,
    _PinnedHTTPSConnection,
    _extract_nodes,
    _fetch_url,
    _resolve_public_https_url,
    _validate_public_https_url,
    build_subscription,
    is_valid_node,
    source_urls,
)


class SubscriptionParserTests(unittest.TestCase):
    def test_validates_supported_proxy_uris(self):
        self.assertTrue(is_valid_node("vless://uuid@example.com:443#edge"))
        self.assertTrue(is_valid_node("trojan://secret@example.com:443"))
        self.assertTrue(is_valid_node("ss://method:secret@example.com:8388"))
        encoded_auth = base64.urlsafe_b64encode(b"method:password").decode().rstrip("=")
        self.assertTrue(is_valid_node(f"ss://{encoded_auth}@example.com:8388"))
        self.assertTrue(is_valid_node("socks5://example.com:1080"))
        self.assertFalse(is_valid_node("ss://method@example.com:8388"))
        self.assertFalse(is_valid_node("vless://uuid@example.com"))
        self.assertFalse(is_valid_node("file://example.com:443"))

    def test_validates_vmess_payload(self):
        payload = base64.urlsafe_b64encode(
            json.dumps({"add": "example.com", "port": "443", "id": "uuid"}).encode()
        ).decode().rstrip("=")
        self.assertTrue(is_valid_node(f"vmess://{payload}"))
        self.assertFalse(is_valid_node("vmess://not-a-node"))

    def test_reads_plain_and_base64_subscription_feeds(self):
        lines = b"vless://uuid@example.com:443\n trojan://secret@example.net:443 \n"
        expected = [
            "vless://uuid@example.com:443",
            "trojan://secret@example.net:443",
        ]
        self.assertEqual(_extract_nodes(lines), expected)
        self.assertEqual(
            _extract_nodes(base64.b64encode(lines)),
            expected,
        )

    def test_rejects_empty_or_invalid_feeds_and_sources(self):
        for content in (b"", b"not a proxy node\n"):
            with self.subTest(content=content), self.assertRaises(SubscriptionError):
                _extract_nodes(content)
        for value in ("", "http://example.com/feed", "https://user:pass@example.com/feed"):
            with self.subTest(value=value), self.assertRaises(SubscriptionError):
                source_urls(value)

    def test_blocks_non_public_feed_addresses(self):
        with self.assertRaises(SubscriptionError):
            _validate_public_https_url("https://127.0.0.1/feed")
        parsed = _validate_public_https_url("https://8.8.8.8/feed")
        self.assertEqual(parsed.scheme, "https")

    def test_rejects_dns_results_that_include_private_addresses(self):
        public_result = (None, None, None, None, ("8.8.8.8", 443))
        private_result = (None, None, None, None, ("10.0.0.1", 443))
        with patch(
            "update_sub.socket.getaddrinfo",
            return_value=[public_result, private_result],
        ):
            with self.assertRaises(SubscriptionError):
                _resolve_public_https_url("https://feed.example/sub")

    def test_https_connection_uses_the_validated_ip(self):
        raw_socket = MagicMock()

        class FakeContext:
            def wrap_socket(self, connection_socket, server_hostname):
                self.server_hostname = server_hostname
                return connection_socket

        connection = _PinnedHTTPSConnection("feed.example", "8.8.8.8", 443, 5)
        context = FakeContext()
        connection._context = context
        with patch(
            "update_sub.socket.create_connection",
            return_value=raw_socket,
        ) as create_connection:
            connection.connect()
        create_connection.assert_called_once_with(("8.8.8.8", 443), 5, None)
        self.assertEqual(context.server_hostname, "feed.example")
        connection.close()

    def test_redirects_are_resolved_and_revalidated(self):
        class FakeResponse:
            def __init__(self, status, location=None, body=b""):
                self.status = status
                self.location = location
                self.body = body

            def getheader(self, name):
                return self.location if name == "Location" else None

            def read(self, limit):
                return self.body

        class FakeConnection:
            def __init__(self, hostname, address, port, timeout):
                self.hostname = hostname
                self.requested_target = None

            def request(self, method, target, headers):
                self.requested_target = target

            def getresponse(self):
                return responses.pop(0)

            def close(self):
                pass

        responses = [
            FakeResponse(302, "https://cdn.example/subscription"),
            FakeResponse(200, body=b"subscription"),
        ]
        with (
            patch(
                "update_sub._resolve_public_https_url",
                side_effect=[
                    (urlsplit("https://feed.example/start"), ["8.8.8.8"]),
                    (urlsplit("https://cdn.example/subscription"), ["1.1.1.1"]),
                ],
            ) as resolve_url,
            patch("update_sub._PinnedHTTPSConnection", FakeConnection),
        ):
            self.assertEqual(_fetch_url("https://feed.example/start"), b"subscription")
        self.assertEqual(resolve_url.call_count, 2)

    def test_deduplicates_and_sorts_before_encoding(self):
        node_a = "vless://uuid-a@example.com:443"
        node_b = "vless://uuid-b@example.net:443"
        expected = base64.b64encode(f"{node_a}\n{node_b}\n".encode()).decode() + "\n"
        with patch(
            "update_sub._fetch_feed",
            side_effect=[[node_b, node_a], [node_a]],
        ):
            actual = build_subscription(
                ["https://one.example/feed", "https://two.example/feed"]
            )
        self.assertEqual(actual, expected)

    def test_requires_a_nonempty_valid_node_set(self):
        with patch("update_sub._fetch_feed", return_value=[]):
            with self.assertRaisesRegex(SubscriptionError, "no valid nodes"):
                build_subscription(["https://one.example/feed"])


if __name__ == "__main__":
    unittest.main()
