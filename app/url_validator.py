"""
SSRF 防护模块 — URL 校验、协议限制、IP 检查、重定向控制
"""
import socket
import ipaddress
import logging
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# 允许的主机白名单（默认空，拒绝所有外部请求）
# 可配置：FETCH_ALLOWED_HOSTS=example.com,api.example.org
ALLOWED_HOSTS = set(
    h.strip().lower()
    for h in "".split(",")
    if h.strip()
)

# 允许的端口（可配置：FETCH_ALLOWED_PORTS=80,443,8080）
_ALLOWED_PORTS = {80, 443}
_BLOCKED_NETWORKS = frozenset([
    ipaddress.IPv4Network("0.0.0.0/8"),        # Current network
    ipaddress.IPv4Network("10.0.0.0/8"),       # Private
    ipaddress.IPv4Network("127.0.0.0/8"),      # Loopback
    ipaddress.IPv4Network("169.254.0.0/16"),   # Link-local
    ipaddress.IPv4Network("172.16.0.0/12"),    # Private
    ipaddress.IPv4Network("192.0.0.0/29"),     # IPv4 Service Continuity
    ipaddress.IPv4Network("192.0.0.170/31"),   # NAT64
    ipaddress.IPv4Network("192.0.2.0/24"),     # Documentation
    ipaddress.IPv4Network("192.168.0.0/16"),   # Private
    ipaddress.IPv4Network("198.18.0.0/15"),    # Benchmarking
    ipaddress.IPv4Network("198.51.100.0/24"),  # Documentation
    ipaddress.IPv4Network("203.0.113.0/24"),   # Documentation
    ipaddress.IPv4Network("224.0.0.0/4"),      # Multicast
    ipaddress.IPv4Network("240.0.0.0/4"),      # Reserved
    ipaddress.IPv6Network("::1/128"),           # Loopback
    ipaddress.IPv6Network("64:ff9b::/96"),     # IPv4/IPv6 translation
    ipaddress.IPv6Network("100::/64"),          # Discard prefix
    ipaddress.IPv6Network("2001::/32"),         # Teredo
    ipaddress.IPv6Network("2001:2::/48"),       # Benchmarking
    ipaddress.IPv6Network("2001:db8::/32"),     # Documentation
    ipaddress.IPv6Network("fe80::/10"),         # Link-local
    ipaddress.IPv6Network("fc00::/7"),          # Unique local
    ipaddress.IPv6Network("ff00::/8"),          # Multicast
])

MAX_REDIRECTS = 3
MAX_RESPONSE_BYTES = 1 * 1024 * 1024  # 1 MiB
FETCH_TIMEOUT = 5
ALLOWED_CONTENT_TYPES = {"text/plain", "application/json"}


class SSRFError(Exception):
    """SSRF 校验失败"""


def validate_url(raw_url):
    """
    校验 URL 并返回 (parsed_result, hostname, port)
    不满足安全要求时抛出 SSRFError
    """
    raw_url = raw_url.strip()
    if not raw_url:
        raise SSRFError("URL 为空")

    # 拒绝控制字符
    if any(ord(c) < 32 for c in raw_url):
        raise SSRFError("URL 包含控制字符")

    # 解析
    parts = urlsplit(raw_url)

    # 协议限制
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise SSRFError(f"不允许的协议: {scheme}")

    # 拒绝 userinfo
    if parts.username or parts.password or "@" in parts.netloc.split("@")[-1:]:
        raise SSRFError("URL 不允许包含用户信息")

    hostname = parts.hostname
    if not hostname:
        raise SSRFError("URL 缺少主机名")

    hostname = hostname.lower().lstrip(".").rstrip(".")
    if not hostname or hostname == "localhost":
        raise SSRFError("无效主机名")

    # 端口
    port = parts.port
    if port is None:
        port = 443 if scheme == "https" else 80
    if port not in _ALLOWED_PORTS:
        raise SSRFError(f"不允许的端口: {port}")

    # 主机白名单
    if ALLOWED_HOSTS and hostname not in ALLOWED_HOSTS:
        raise SSRFError(f"主机不在白名单中: {hostname}")

    return parts, hostname, port


def _is_private_ip(addr_str):
    """检查单个 IP 是否为私有/保留地址"""
    try:
        ip = ipaddress.ip_address(addr_str)
    except ValueError:
        return True  # 无法解析则拒绝

    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return True

    # 检查 IPv4-mapped IPv6（如 ::ffff:127.0.0.1）
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        v4 = ip.ipv4_mapped
        if v4.is_loopback or v4.is_private or v4.is_link_local or v4.is_reserved:
            return True

    # 网络级别检查
    for net in _BLOCKED_NETWORKS:
        if ip in net:
            return True

    return False


def validate_host(hostname, port):
    """
    DNS 解析主机，验证所有解析 IP 均为公网地址。
    任一地址为私有地址则拒绝。
    """
    hostname_lower = hostname.lower().rstrip(".")
    if hostname_lower in ("localhost", "0.0.0.0"):
        raise SSRFError("禁止访问本地地址")

    # 短路径：如果是纯 IP，直接校验
    try:
        ip = ipaddress.ip_address(hostname_lower)
        if _is_private_ip(str(ip)):
            raise SSRFError(f"目标 {hostname} 是内网地址")
        return True
    except ValueError:
        pass  # 不是纯 IP，需要 DNS 解析

    # DNS 解析
    try:
        infos = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFError(f"DNS 解析失败: {e}")

    has_public = False
    for info in infos:
        family, _, _, _, sockaddr = info
        addr = sockaddr[0]

        if family == socket.AF_INET6:
            try:
                v6 = ipaddress.IPv6Address(addr)
                if v6.ipv4_mapped:
                    addr = str(v6.ipv4_mapped)
            except Exception:
                pass

        if _is_private_ip(addr):
            logger.warning("SSRF: 拒绝解析到私有地址 %s → %s", hostname, addr)
            raise SSRFError(f"目标 {hostname} 解析到内网地址 ({addr})，拒绝访问")

        has_public = True

    if not has_public:
        raise SSRFError(f"目标 {hostname} 无有效公网地址")

    return True
