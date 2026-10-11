import base64
import json
import unittest
from unittest.mock import patch

from update_sub import (
    SubscriptionError,
    _extract_nodes,
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
