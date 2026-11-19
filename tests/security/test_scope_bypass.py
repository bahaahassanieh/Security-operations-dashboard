"""Adversarial tests: unauthorized targets must never pass scope evaluation."""
from __future__ import annotations

import socket

import pytest

from app.services.scope import (
    ScopeError,
    ScopeEvaluator,
    normalize_rule,
    parse_target,
)


def evaluator(allow, deny=(), resolver=None):
    rules = [normalize_rule(value) for value in allow]
    rules += [normalize_rule(value, is_exclusion=True) for value in deny]
    return ScopeEvaluator(rules, resolver=resolver)


SCOPE = evaluator(
    ["app.example.com", "*.dev.example.com", "203.0.113.0/24", "https://portal.example.org/app"],
    ["secret.dev.example.com", "203.0.113.9", "https://app.example.com/admin"],
)


@pytest.mark.parametrize(
    "target",
    [
        "app.example.com",
        "APP.EXAMPLE.COM",
        "app.example.com.",
        "https://app.example.com/login?x=1",
        "http://app.example.com:8080/",
        "a.dev.example.com",
        "a.b.dev.example.com",
        "203.0.113.10",
        "http://203.0.113.10:8080/x",
        "https://portal.example.org/app",
        "https://portal.example.org/app/settings",
    ],
)
def test_authorized_targets_are_allowed(target):
    assert SCOPE.evaluate(target).allowed, target


@pytest.mark.parametrize(
    "target",
    [
        # Plainly out of scope
        "evil.com",
        "example.com",
        "other.example.com",
        "dev.example.com",
        "198.51.100.1",
        # Suffix and prefix confusion
        "app.example.com.evil.com",
        "notapp.example.com",
        "xdev.example.com",
        "a.dev.example.com.evil.com",
        "https://evil.com/app.example.com",
        "https://evil.com?x=app.example.com",
        "https://evil.com#app.example.com",
        # Userinfo tricks
        "https://app.example.com@evil.com/",
        "https://app.example.com:pw@evil.com/",
        "https://evil.com@app.example.com/",
        # Parser differentials
        "https://evil.com\\@app.example.com/",
        "https://app.example.com\\.evil.com/",
        "https://evil.com/\t.app.example.com",
        "https://evil.com\r\nHost: app.example.com",
        "https://app.example.com evil.com",
        "https://app%2eexample%2ecom/",
        "https://evil.com%2f@app.example.com/",
        "https://app.example.com%00.evil.com/",
        # Unsupported schemes
        "file:///etc/passwd",
        "ftp://app.example.com/",
        "gopher://app.example.com/",
        "javascript:alert(1)",
        "data:text/html,app.example.com",
        # Exclusions must win over inclusions
        "secret.dev.example.com",
        "SECRET.DEV.EXAMPLE.COM",
        "secret.dev.example.com.",
        "deep.secret.dev.example.com",
        "203.0.113.9",
        "http://203.0.113.9:8443/",
        "::ffff:203.0.113.9",
        "http://[::ffff:203.0.113.9]/",
        "3405803785",
        "0xCB.0.113.9",
        "https://app.example.com/admin",
        "https://app.example.com/admin/users",
        "https://app.example.com/ADMIN",
        "http://app.example.com/admin",
        "https://app.example.com:8443/admin",
        "https://app.example.com/x/../admin",
        "https://app.example.com/%61dmin",
        "https://app.example.com/%2561dmin",
        "https://app.example.com/./admin",
        "https://app.example.com//admin",
        "https://app.example.com/admin;v=1",
        "https://app.example.com/foo/..%2fadmin",
        "https://app.example.com/%2525252525252561dmin",
        # URL-prefix boundaries
        "https://portal.example.org/",
        "https://portal.example.org/application",
        "https://portal.example.org/app/../admin",
        "https://portal.example.org/app/..%2fadmin",
        "https://portal.example.org/app/%2e%2e/admin",
        "http://portal.example.org/app",
        "https://portal.example.org:8443/app",
        "portal.example.org",
        # Empty and malformed
        "",
        "   ",
        "https://",
        "https://:443/",
        "http://app.example.com:99999/",
        "http://app.example.com:0/",
        "x" * 3000,
    ],
)
def test_unauthorized_targets_are_denied(target):
    assert not SCOPE.evaluate(target).allowed, target


@pytest.mark.parametrize(
    "literal",
    [
        "127.0.0.1",
        "2130706433",
        "0x7f000001",
        "0x7f.0.0.1",
        "0177.0.0.1",
        "127.1",
        "127.0.1",
        "::1",
        "[::1]",
        "::ffff:127.0.0.1",
        "::ffff:7f00:1",
        "64:ff9b::7f00:1",
        "2002:7f00:1::",
        "１２７.０.０.１",
        "localhost",
    ],
)
def test_loopback_encodings_are_denied(literal):
    assert not SCOPE.evaluate(literal).allowed, literal
    assert not SCOPE.evaluate(f"http://{literal}/").allowed or literal == "::1"


@pytest.mark.parametrize(
    "literal",
    ["2130706433", "0x7f.0.0.1", "0177.0.0.1", "127.1", "::ffff:127.0.0.1", "64:ff9b::7f00:1"],
)
def test_encoded_ips_canonicalize_to_loopback(literal):
    assert parse_target(literal).host == "127.0.0.1"


@pytest.mark.parametrize(
    "address",
    [
        "169.254.169.254",
        "2852039166",
        "0xA9FEA9FE",
        "::ffff:169.254.169.254",
        "100.100.100.200",
        "168.63.129.16",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "fe80::1",
        "ff02::1",
        "fd00:ec2::254",
    ],
)
def test_prohibited_addresses_are_denied_even_when_scoped(address):
    broad = ScopeEvaluator(
        [
            normalize_rule(value, min_ipv4_prefix=0, min_ipv6_prefix=0)
            for value in ("0.0.0.0/0", "::/0")
        ]
    )
    assert not broad.evaluate(address).allowed, address


@pytest.mark.parametrize(
    "rule",
    [
        "*",
        "*.*",
        "*.com",
        "*.co.uk",
        "*.github.io",
        "com",
        "co.uk",
        "0.0.0.0/0",
        "::/0",
        "10.0.0.0/8",
        "2001:db8::/32",
        "10.0.0.1/24",
        "::ffff:10.0.0.0/104",
        "exa mple.com",
        "example.com/path",
        "example.com:8080",
        "",
    ],
)
def test_overbroad_or_malformed_rules_are_rejected(rule):
    with pytest.raises(ScopeError):
        normalize_rule(rule)


class TestDnsRebinding:
    """Execution-time checks on the addresses a hostname actually resolves to."""

    @staticmethod
    def scope(addresses, allow=("app.example.com",), deny=()):
        return evaluator(allow, deny, resolver=lambda _host: list(addresses))

    def test_public_address_is_allowed(self):
        assert self.scope(["93.184.216.34"]).evaluate("app.example.com", resolve=True).allowed

    @pytest.mark.parametrize(
        "address",
        ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "::1", "::ffff:127.0.0.1",
         "fc00::1", "100.64.0.1"],
    )
    def test_private_address_is_denied_unless_authorized(self, address):
        assert not self.scope([address]).evaluate("app.example.com", resolve=True).allowed

    def test_private_address_is_allowed_when_explicitly_authorized(self):
        scope = self.scope(["10.0.0.5"], allow=("app.example.com", "10.0.0.5"))
        assert scope.evaluate("app.example.com", resolve=True).allowed

    def test_metadata_address_is_denied_even_when_authorized(self):
        scope = self.scope(["169.254.169.254"], allow=("app.example.com", "169.254.169.254"))
        assert not scope.evaluate("app.example.com", resolve=True).allowed

    def test_one_bad_address_among_many_denies(self):
        scope = self.scope(["93.184.216.34", "127.0.0.1"])
        assert not scope.evaluate("app.example.com", resolve=True).allowed

    def test_excluded_address_is_denied(self):
        scope = self.scope(["93.184.216.34"], deny=("93.184.216.0/24",))
        assert not scope.evaluate("app.example.com", resolve=True).allowed

    def test_resolution_failure_fails_closed(self):
        def failing(_host):
            raise socket.gaierror("no such host")

        assert not evaluator(["app.example.com"], resolver=failing).evaluate(
            "app.example.com", resolve=True
        ).allowed

    def test_empty_resolution_fails_closed(self):
        assert not self.scope([]).evaluate("app.example.com", resolve=True).allowed

    def test_garbage_resolution_fails_closed(self):
        assert not self.scope(["not-an-ip"]).evaluate("app.example.com", resolve=True).allowed
