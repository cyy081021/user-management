"""
SSRF 防护模块 — 白名单 + DNS预解析 + 固定IP连接（防 TOCTOU）
"""
import os
import re
import socket
import ssl
import ipaddress
import logging
from urllib.parse import urlsplit, urljoin

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 配置读取
# ---------------------------------------------------------------------------

def _parse_hosts(raw):
    """从逗号分隔的字符串解析主机白名单"""
    hosts = set()
    if raw and raw.strip():
        for h in raw.split(","):
            h = h.strip().lower()
            if h:
                hosts.add(h)
    return hosts


def _parse_ports(raw):
    """从逗号分隔的字符串解析端口白名单"""
    ports = {80, 443}
    if raw and raw.strip():
        for p in raw.split(","):
            p = p.strip()
            if p:
                try:
                    pval = int(p)
                    if 1 <= pval <= 65535:
                        ports.add(pval)
                except ValueError:
                    pass
    return ports


ALLOWED_HOSTS = _parse_hosts(os.environ.get("FETCH_ALLOWED_HOSTS", ""))
_ALLOWED_PORTS = _parse_ports(os.environ.get("FETCH_ALLOWED_PORTS", ""))

_BLOCKED_NETWORKS = frozenset([
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.0.0.0/29"),
    ipaddress.IPv4Network("192.0.0.170/31"),
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("64:ff9b::/96"),
    ipaddress.IPv6Network("100::/64"),
    ipaddress.IPv6Network("2001::/32"),
    ipaddress.IPv6Network("2001:2::/48"),
    ipaddress.IPv6Network("2001:db8::/32"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("ff00::/8"),
])

MAX_REDIRECTS = 3
MAX_RESPONSE_BYTES = 1 * 1024 * 1024
FETCH_TIMEOUT = 5
ALLOWED_CONTENT_TYPES = {"text/plain", "application/json"}


class SSRFError(Exception):
    """SSRF 校验失败"""


# ---------------------------------------------------------------------------
# IP 校验
# ---------------------------------------------------------------------------

def _is_private_ip(addr_str):
    try:
        ip = ipaddress.ip_address(addr_str)
    except ValueError:
        return True

    if ip.is_loopback or ip.is_private or ip.is_link_local or \
       ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return True

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        v4 = ip.ipv4_mapped
        if v4.is_loopback or v4.is_private or v4.is_link_local or v4.is_reserved:
            return True

    for net in _BLOCKED_NETWORKS:
        if ip in net:
            return True
    return False


# ---------------------------------------------------------------------------
# URL 校验
# ---------------------------------------------------------------------------

def validate_url(raw_url):
    """校验 URL 结构，返回 (parts, hostname_normalized, port)"""
    raw_url = raw_url.strip()
    if not raw_url:
        raise SSRFError("URL 为空")

    if any(ord(c) < 32 for c in raw_url):
        raise SSRFError("URL 包含控制字符")

    parts = urlsplit(raw_url)

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise SSRFError("不允许的协议")

    if parts.username or parts.password:
        raise SSRFError("URL 不允许包含用户信息")

    hostname = parts.hostname
    if not hostname:
        raise SSRFError("URL 缺少主机名")
    # 二次确认：netloc/hostname 中不应出现 @（防御 split 解析差异）
    if "@" in hostname:
        raise SSRFError("URL 不允许包含用户信息")

    hostname = hostname.lower().rstrip(".")
    if not hostname or hostname in ("localhost", "0.0.0.0"):
        raise SSRFError("无效主机名")

    # 端口
    try:
        port = parts.port
    except ValueError:
        raise SSRFError("端口格式无效")
    if port is None:
        port = 443 if scheme == "https" else 80
    if not (1 <= port <= 65535) or port not in _ALLOWED_PORTS:
        raise SSRFError("不允许的端口")

    # 白名单（空=拒绝全部外部请求）
    if not ALLOWED_HOSTS:
        raise SSRFError("未配置 FETCH_ALLOWED_HOSTS，拒绝外部请求")
    # 精确匹配或子域名匹配
    matched = False
    for allowed in ALLOWED_HOSTS:
        if hostname == allowed:
            matched = True
            break
        if hostname.endswith("." + allowed):
            matched = True
            break
    if not matched:
        raise SSRFError("主机不在白名单中")

    return parts, hostname, port


# ---------------------------------------------------------------------------
# DNS + IP 验证，返回可安全使用的 IP 集合（防 TOCTOU）
# ---------------------------------------------------------------------------

def _resolve_safe(hostname, port):
    """
    DNS 解析并返回 (family, sockaddr) 列表，
    只包含公网地址。任一地址私有则整体拒绝。
    """
    hostname_lower = hostname.lower().rstrip(".")
    if hostname_lower in ("localhost", "0.0.0.0"):
        raise SSRFError("禁止访问本地地址")

    # 纯 IP 短路径
    try:
        ip = ipaddress.ip_address(hostname_lower)
        if _is_private_ip(str(ip)):
            raise SSRFError("目标地址是内网地址")
        return [(socket.AF_INET if ip.version == 4 else socket.AF_INET6,
                 (str(ip), port))]
    except ValueError:
        pass

    # DNS
    addrs = socket.getaddrinfo(hostname_lower, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    safe = []
    for info in addrs:
        family, socktype, proto, canon, sockaddr = info
        addr = sockaddr[0]
        if family == socket.AF_INET6:
            try:
                v6 = ipaddress.IPv6Address(addr)
                if v6.ipv4_mapped:
                    addr = str(v6.ipv4_mapped)
            except Exception:
                pass

        if _is_private_ip(addr):
            logger.warning("SSRF: DNS %s → %s 为私有地址，拒绝", hostname, addr)
            raise SSRFError("目标解析到内网地址，拒绝访问")

        safe.append((family, sockaddr))

    if not safe:
        raise SSRFError("DNS 无有效公网地址")
    return safe


# ---------------------------------------------------------------------------
# 安全连接（解析一次，用解析结果连接，拒绝 TOCTOU）
# ---------------------------------------------------------------------------

def _create_connection(hostname, port, family, sockaddr, timeout, ssl_context):
    """创建到指定 IP 的 TCP 连接（跳过 urllib 的二次 DNS 解析）"""
    sock = None
    for af, sa in [(family, sockaddr)]:
        try:
            sock = socket.socket(af, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(sa)
            break
        except Exception:
            if sock:
                sock.close()
            raise

    if ssl_context:
        sock = ssl_context.wrap_socket(sock, server_hostname=hostname)
    return sock


class _SafeHTTPHandler:
    """
    自定义 HTTP handler，使用预解析的 IP 连接，
    不经过 urllib 的二次 DNS。
    """
    def __init__(self, hostname, port, resolved_addrs, timeout, scheme):
        self.hostname = hostname
        self.port = port
        self.resolved = resolved_addrs
        self.timeout = timeout
        self.scheme = scheme

    def _connect(self):
        ssl_ctx = None
        if self.scheme == "https":
            ssl_ctx = ssl.create_default_context()
        # 尝试所有解析地址
        last_err = None
        for family, sockaddr in self.resolved:
            try:
                return _create_connection(
                    self.hostname, self.port, family, sockaddr,
                    self.timeout, ssl_ctx)
            except Exception as e:
                last_err = e
                continue
        raise last_err or OSError("连接失败")


# ---------------------------------------------------------------------------
# 安全抓取（分步：验证→解析→连接→读取，每步不可绕过）
# ---------------------------------------------------------------------------

def safe_fetch(url, max_hops=MAX_REDIRECTS):
    """
    完整 SSRF 安全抓取。返回 (status, body_bytes, content_type)。
    对每次重定向重新执行全链路校验。
    """
    hops = 0
    current_url = url

    while hops <= max_hops:
        # 1. URL 校验
        parts, hostname, port = validate_url(current_url)

        # 2. DNS 解析 + IP 校验（返回安全 IP）
        resolved = _resolve_safe(hostname, port)

        # 3. 用解析到的 IP 建立连接
        handler = _SafeHTTPHandler(hostname, port, resolved, FETCH_TIMEOUT, parts.scheme)
        conn_sock = handler._connect()

        # 4. 发送 HTTP 请求（Host 头保持原始域名）
        import http.client as _hc
        conn = _hc.HTTPConnection(hostname, port) if parts.scheme == "http" else \
               _hc.HTTPSConnection(hostname, port)
        # 将我们自己的 socket 注入
        conn.sock = conn_sock

        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        conn.request(
            "GET", path,
            headers={
                "Host": hostname + (f":{port}" if port not in (80, 443) else ""),
                "User-Agent": "UserManagement/1.0",
            }
        )
        response = conn.getresponse()
        status = response.status

        # 5. 重定向检查
        if 300 <= status < 400 and status != 304 and hops < max_hops:
            location = response.getheader("Location", "")
            response.close()
            if not location:
                raise SSRFError("重定向缺少 Location")
            current_url = urljoin(current_url, location)
            hops += 1
            # 重新进入循环，完整校验下一跳
            continue

        # 6. 非重定向 → 读取响应
        content_type = response.getheader("Content-Type", "")
        body_data = b""
        if status < 400:
            if not any(ct in content_type for ct in ALLOWED_CONTENT_TYPES):
                response.close()
                return status, b"", content_type
            for chunk in iter(lambda: response.read(8192), b""):
                body_data += chunk
                if len(body_data) > MAX_RESPONSE_BYTES:
                    response.close()
                    raise SSRFError("响应超过大小限制")
        response.close()
        return status, body_data, content_type

    raise SSRFError("重定向次数过多")
