import ipaddress
import re
import logging

from app.db.models import Target, TargetType, ScopeDirection

logger = logging.getLogger(__name__)


class ScopeEnforcer:
    def __init__(self, targets: list[Target]):
        self.in_scope_matchers: list[callable] = []
        self.out_of_scope_matchers: list[callable] = []

        for t in targets:
            matcher = self._build_matcher(t)
            if t.direction == ScopeDirection.in_scope:
                self.in_scope_matchers.append(matcher)
            else:
                self.out_of_scope_matchers.append(matcher)

    def _build_matcher(self, target: Target) -> callable:
        if target.target_type == TargetType.ip:
            addr = ipaddress.ip_address(target.value)
            return lambda v, a=addr: self._match_ip(v, a)

        if target.target_type == TargetType.ip_range:
            network = ipaddress.ip_network(target.value, strict=False)
            return lambda v, n=network: self._match_ip_range(v, n)

        if target.target_type == TargetType.wildcard_domain:
            pattern = self._wildcard_to_regex(target.value)
            return lambda v, p=pattern: self._match_domain(v, p)

        if target.target_type == TargetType.url:
            prefix = target.value.rstrip("/")
            return lambda v, pf=prefix: self._match_url(v, pf)

        return lambda v: False

    @staticmethod
    def _wildcard_to_regex(wildcard: str) -> re.Pattern:
        wildcard = wildcard.lstrip("*.")
        escaped = re.escape(wildcard)
        return re.compile(rf"^(.*\.)?{escaped}$", re.IGNORECASE)

    @staticmethod
    def _match_ip(value: str, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        try:
            return ipaddress.ip_address(value) == addr
        except ValueError:
            return False

    @staticmethod
    def _match_ip_range(value: str, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
        try:
            return ipaddress.ip_address(value) in network
        except ValueError:
            return False

    @staticmethod
    def _match_domain(value: str, pattern: re.Pattern) -> bool:
        host = value.split("://")[-1].split("/")[0].split(":")[0]
        return bool(pattern.match(host))

    @staticmethod
    def _match_url(value: str, prefix: str) -> bool:
        return value.rstrip("/").startswith(prefix)

    def is_in_scope(self, value: str) -> bool:
        for matcher in self.out_of_scope_matchers:
            if matcher(value):
                logger.info("OUT OF SCOPE (exclusion): %s", value)
                return False

        for matcher in self.in_scope_matchers:
            if matcher(value):
                return True

        logger.info("OUT OF SCOPE (no match): %s", value)
        return False

    def filter_targets(self, values: list[str]) -> list[str]:
        return [v for v in values if self.is_in_scope(v)]
