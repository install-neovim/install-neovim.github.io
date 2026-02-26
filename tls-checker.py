#!/usr/bin/env python3
"""
Reality 协议目标网站增强检测脚本 v2.0
新增: X25519支持检测、HTTP/2支持检测、完整CDN检测
"""

import socket
import ssl
import requests
import re
import ipaddress
from urllib.parse import urlparse
import time
import sys
import json
import subprocess
from typing import Dict, List, Tuple, Optional, Set
import logging
from dataclasses import dataclass, asdict
from enum import Enum

# 设置日志
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    UNSUITABLE = "unsuitable"


@dataclass
class TLSCheckResult:
    version: str
    cert_valid: bool
    sni_support: bool
    alpn_support: List[str]
    cipher_suite: str
    cert_issuer: str
    cert_expiry: str
    x25519_support: bool
    pfs_support: bool
    ocsp_stapling: bool
    security_level: SecurityLevel
    details: Dict


# 已知CDN IP范围
CDN_IP_RANGES = {
    "cloudflare": [
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "108.162.192.0/18",
        "131.0.72.0/22",
        "141.101.64.0/18",
        "162.158.0.0/15",
        "172.64.0.0/13",
        "173.245.48.0/20",
        "188.114.96.0/20",
        "190.93.240.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
    ],
    "cloudfront": [
        "120.52.22.96/27",
        "205.251.249.0/24",
        "13.32.0.0/15",
        "13.35.0.0/16",
        "13.224.0.0/14",
        "34.192.0.0/12",
        "52.46.0.0/18",
        "52.56.127.0/25",
        "52.66.194.128/25",
        "52.84.0.0/15",
        "52.124.128.0/17",
        "52.199.127.192/26",
        "52.212.248.0/26",
        "52.222.128.0/17",
        "54.182.0.0/16",
        "54.192.0.0/16",
        "54.230.0.0/16",
        "54.239.128.0/18",
        "54.240.128.0/18",
        "64.252.64.0/18",
        "70.132.0.0/18",
        "71.152.0.0/17",
        "99.84.0.0/16",
        "130.176.0.0/16",
        "143.204.0.0/16",
        "144.220.0.0/16",
        "180.163.57.0/25",
        "204.246.164.0/22",
        "204.246.168.0/22",
        "204.246.174.0/23",
        "204.246.176.0/20",
        "205.251.192.0/19",
        "205.251.248.0/24",
        "216.137.32.0/19",
    ],
    "fastly": [
        "23.235.32.0/20",
        "43.249.72.0/22",
        "103.244.50.0/24",
        "103.245.222.0/23",
        "103.245.224.0/24",
        "104.156.80.0/20",
        "140.248.64.0/18",
        "140.248.128.0/17",
        "146.75.0.0/17",
        "151.101.0.0/16",
        "157.52.64.0/18",
        "167.82.0.0/17",
        "167.82.128.0/20",
        "167.82.160.0/20",
        "167.82.224.0/20",
        "172.111.64.0/18",
        "185.31.16.0/22",
        "199.27.72.0/21",
        "199.232.0.0/16",
    ],
}

# X25519相关密码套件
X25519_CIPHERS = [
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",  # TLS 1.2
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",  # TLS 1.2
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",  # TLS 1.2
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",  # TLS 1.2
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",  # TLS 1.2
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",  # TLS 1.2
    "TLS_AES_128_GCM_SHA256",  # TLS 1.3
    "TLS_AES_256_GCM_SHA384",  # TLS 1.3
    "TLS_CHACHA20_POLY1305_SHA256",  # TLS 1.3
]

# 支持前向保密的密码套件
PFS_CIPHERS = X25519_CIPHERS + [
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
]


def check_ip_in_cdn_range(ip: str) -> List[str]:
    """检查IP是否属于已知CDN范围"""
    detected_cdns = []
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cdn_name, ranges in CDN_IP_RANGES.items():
            for cidr in ranges:
                if ip_obj in ipaddress.ip_network(cidr):
                    detected_cdns.append(cdn_name)
                    break
    except Exception:
        pass
    return detected_cdns


def get_domain_ips(domain: str) -> List[str]:
    """获取域名的所有A记录IP"""
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(domain, "A")
        return [str(r) for r in answers]
    except Exception as e:
        logger.warning(f"DNS解析失败: {e}")
        try:
            # 备用方法：使用socket
            return [socket.gethostbyname(domain)]
        except:
            return []


def check_http2_support(domain: str, port: int = 443) -> Tuple[bool, str, Dict]:
    """
    检查HTTP/2支持情况
    """
    try:
        # 方法1: 使用ALPN协商
        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2", "http/1.1"])
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                negotiated_protocol = ssock.selected_alpn_protocol()

                if negotiated_protocol == "h2":
                    # 获取HTTP/2设置
                    http2_details = {
                        "alpn_negotiated": True,
                        "protocol": "h2",
                        "cipher": ssock.cipher(),
                        "version": ssock.version(),
                    }
                    return True, "支持 HTTP/2 (ALPN协商成功)", http2_details

                # 方法2: 检查响应头
                import http.client

                conn = http.client.HTTPSConnection(domain, port, timeout=5)
                conn.request("HEAD", "/")
                response = conn.getresponse()

                http2_details = {
                    "alpn_negotiated": False,
                    "http_version": response.version,
                    "headers": dict(response.getheaders()),
                }

                # 检查HTTP版本
                if response.version == 20:
                    http2_details["protocol"] = "h2"
                    return True, "支持 HTTP/2 (HTTP版本检测)", http2_details

                # 检查alt-svc头部
                alt_svc = response.getheader("alt-svc", "")
                if "h2=" in alt_svc.lower():
                    http2_details["alt_svc"] = alt_svc
                    return True, "支持 HTTP/2 (alt-svc头部)", http2_details

                http2_details["protocol"] = "http/1.1"
                return False, "不支持 HTTP/2", http2_details

    except ssl.SSLError as e:
        if "no application protocol" in str(e).lower():
            return False, "不支持 HTTP/2 (无ALPN支持)", {"error": str(e)}
        else:
            return False, f"TLS错误: {str(e)}", {"error": str(e)}
    except Exception as e:
        logger.error(f"HTTP/2检测异常: {e}")
        return False, f"HTTP/2检测失败: {str(e)}", {"error": str(e)}


def check_x25519_support_openssl(
    domain: str, port: int = 443
) -> Tuple[bool, str, Dict]:
    """
    使用openssl命令行工具检查X25519支持
    更准确，但需要openssl命令行工具
    """
    try:
        # 使用openssl s_client检查TLS连接详情
        cmd = [
            "openssl",
            "s_client",
            "-connect",
            f"{domain}:{port}",
            "-servername",
            domain,
            "-ciphersuites",
            "TLS_AES_128_GCM_SHA256",
            "-curves",
            "X25519",
            "-tls1_3",
            "-brief",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            input="\n",  # 发送空行以获取完整信息
        )

        openssl_output = result.stdout + result.stderr

        details = {
            "openssl_output": openssl_output[:1000],  # 限制输出长度
            "return_code": result.returncode,
        }

        # 检查X25519相关输出
        x25519_indicators = [
            "Server Temp Key: X25519",
            "TLSv1.3, .*X25519",
            "Peer signing digest: .*X25519",
            "NamedGroup: x25519",
        ]

        for indicator in x25519_indicators:
            if re.search(indicator, openssl_output, re.IGNORECASE):
                details["detection_method"] = "openssl_curve_negotiation"
                return True, "支持 X25519 (通过OpenSSL检测)", details

        # 检查TLS 1.3密码套件
        tls13_ciphers = [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ]

        for cipher in tls13_ciphers:
            if cipher in openssl_output:
                details["tls13_cipher"] = cipher
                # TLS 1.3默认使用X25519，所以如果有TLS 1.3，很可能支持X25519
                if "TLSv1.3" in openssl_output:
                    details["detection_method"] = "tls13_default"
                    return True, "可能支持 X25519 (TLS 1.3连接)", details

        return False, "未检测到X25519支持", details

    except subprocess.TimeoutExpired:
        return False, "OpenSSL检测超时", {"error": "timeout"}
    except FileNotFoundError:
        return False, "未找到openssl命令行工具", {"error": "openssl_not_found"}
    except Exception as e:
        return False, f"OpenSSL检测失败: {str(e)}", {"error": str(e)}


def check_x25519_support_python(domain: str, port: int = 443) -> Tuple[bool, str, Dict]:
    """
    使用Python ssl模块检查X25519支持
    """
    details = {"methods_tried": [], "errors": []}

    try:
        # 方法1: 尝试使用X25519曲线
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # 设置密码套件偏好（包含X25519相关的）
        context.set_ciphers("ECDHE:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK")

        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cipher = ssock.cipher()
                tls_version = ssock.version()

                details["cipher"] = cipher
                details["tls_version"] = tls_version
                details["methods_tried"].append("cipher_negotiation")

                # 检查密码套件是否支持前向保密
                cipher_name = cipher[0] if cipher else ""
                for x25519_cipher in X25519_CIPHERS:
                    if x25519_cipher in cipher_name:
                        details["detected_cipher"] = x25519_cipher
                        return True, f"支持 X25519 (密码套件: {cipher_name})", details

                # 方法2: 检查是否是TLS 1.3
                if tls_version == "TLSv1.3":
                    details["methods_tried"].append("tls13_detection")
                    # TLS 1.3 默认使用X25519或P-256，但通常X25519优先
                    return True, "可能支持 X25519 (TLS 1.3连接)", details

                return False, f"不支持X25519 (密码套件: {cipher_name})", details

    except ssl.SSLError as e:
        details["errors"].append(f"SSL错误: {e}")
        return False, f"TLS连接失败: {str(e)}", details
    except Exception as e:
        details["errors"].append(f"连接错误: {e}")
        return False, f"连接失败: {str(e)}", details


def check_x25519_support(domain: str, port: int = 443) -> Tuple[bool, str, Dict]:
    """
    综合检查X25519支持
    优先使用OpenSSL命令行工具，失败时回退到Python检测
    """
    # 首先尝试OpenSSL（更准确）
    openssl_result, openssl_msg, openssl_details = check_x25519_support_openssl(
        domain, port
    )

    if not openssl_result and "openssl_not_found" in openssl_details.get("error", ""):
        # OpenSSL不可用，使用Python方法
        logger.info("OpenSSL不可用，使用Python方法检测X25519")
        return check_x25519_support_python(domain, port)

    return openssl_result, openssl_msg, openssl_details


def check_ocsp_stapling(domain: str, port: int = 443) -> Tuple[bool, str, Dict]:
    """
    检查OCSP装订支持
    """
    try:
        # 使用OpenSSL检查OCSP装订
        cmd = [
            "openssl",
            "s_client",
            "-connect",
            f"{domain}:{port}",
            "-servername",
            domain,
            "-status",  # 启用OCSP装订检查
            "-brief",
        ]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, input="\n"
        )

        output = result.stdout + result.stderr

        details = {
            "openssl_output": output[:500],
            "has_ocsp_response": "OCSP Response Status: successful" in output,
            "ocsp_response_length": len(re.findall(r"OCSP Response Data:", output)),
        }

        if details["has_ocsp_response"]:
            return True, "支持 OCSP 装订", details
        else:
            return False, "不支持 OCSP 装订", details

    except Exception as e:
        return False, f"OCSP检查失败: {str(e)}", {"error": str(e)}


def check_tls_security_level(tls_details: Dict) -> SecurityLevel:
    """
    根据TLS配置评估安全等级
    """
    score = 0

    # TLS版本
    if tls_details.get("version") == "TLSv1.3":
        score += 30
    elif tls_details.get("version") == "TLSv1.2":
        score += 20

    # X25519支持
    if tls_details.get("x25519_support"):
        score += 25

    # 前向保密
    if tls_details.get("pfs_support"):
        score += 20

    # OCSP装订
    if tls_details.get("ocsp_stapling"):
        score += 15

    # 证书有效性
    if tls_details.get("cert_valid"):
        score += 10

    # 评估等级
    if score >= 80:
        return SecurityLevel.EXCELLENT
    elif score >= 60:
        return SecurityLevel.GOOD
    elif score >= 40:
        return SecurityLevel.FAIR
    elif score >= 20:
        return SecurityLevel.POOR
    else:
        return SecurityLevel.UNSUITABLE


def check_cdn_headers(response) -> Dict[str, bool]:
    """
    通过HTTP头部检测CDN
    """
    cdn_results = {"cloudflare": False, "cloudfront": False, "fastly": False}

    if not response:
        return cdn_results

    headers = response.headers

    # Cloudflare检测
    cloudflare_indicators = [
        ("server", r"cloudflare"),
        ("cf-ray", r".*"),
        ("cf-cache-status", r".*"),
        ("cf-request-id", r".*"),
    ]

    for header, pattern in cloudflare_indicators:
        if header in headers and re.search(pattern, headers[header], re.I):
            cdn_results["cloudflare"] = True
            break

    # CloudFront检测
    cloudfront_indicators = [
        ("server", r"cloudfront"),
        ("x-amz-cf-pop", r".*"),
        ("x-amz-cf-id", r".*"),
        ("x-cache", r"^CloudFront"),
    ]

    for header, pattern in cloudfront_indicators:
        if header in headers and re.search(pattern, headers[header], re.I):
            cdn_results["cloudfront"] = True
            break

    # Fastly检测
    fastly_indicators = [
        ("server", r"fastly"),
        ("x-served-by", r"fastly"),
        ("x-cache", r"fastly"),
        ("surrogate-key", r".*"),
    ]

    for header, pattern in fastly_indicators:
        if header in headers and re.search(pattern, headers[header], re.I):
            cdn_results["fastly"] = True
            break

    return cdn_results


def check_special_paths(domain: str) -> Dict[str, bool]:
    """
    检查特定路径以识别CDN
    """
    paths_to_check = {
        "cloudflare": "/cdn-cgi/trace",
        "fastly": "/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1",
    }

    results = {cdn: False for cdn in paths_to_check.keys()}

    for cdn, path in paths_to_check.items():
        try:
            resp = requests.get(
                f"https://{domain}{path}",
                timeout=3,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if cdn == "cloudflare" and "cloudflare" in resp.text.lower():
                results[cdn] = True
            elif cdn == "fastly" and resp.status_code != 404:
                results[cdn] = True
        except:
            pass

    return results


def check_all_cdns(domain: str) -> Tuple[bool, str, Dict]:
    """
    综合检测所有CDN
    """
    detailed_results = {
        "cloudflare": {"detected": False, "methods": []},
        "cloudfront": {"detected": False, "methods": []},
        "fastly": {"detected": False, "methods": []},
    }

    try:
        # 1. 获取响应并检查头部
        response = requests.get(
            f"https://{domain}",
            timeout=5,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0"},
        )

        header_cdns = check_cdn_headers(response)

        # 2. 检查特定路径
        path_cdns = check_special_paths(domain)

        # 3. 检查IP范围
        ip_cdns = []
        ips = get_domain_ips(domain)
        for ip in ips:
            ip_cdns.extend(check_ip_in_cdn_range(ip))

        # 合并结果
        for cdn in detailed_results.keys():
            if header_cdns.get(cdn):
                detailed_results[cdn]["detected"] = True
                detailed_results[cdn]["methods"].append("HTTP头部")

            if path_cdns.get(cdn):
                detailed_results[cdn]["detected"] = True
                detailed_results[cdn]["methods"].append("特定路径")

            if cdn in ip_cdns:
                detailed_results[cdn]["detected"] = True
                detailed_results[cdn]["methods"].append("IP范围")

        # 生成总结信息
        detected_cdns = [
            cdn for cdn, info in detailed_results.items() if info["detected"]
        ]

        if detected_cdns:
            methods_info = []
            for cdn in detected_cdns:
                methods = detailed_results[cdn]["methods"]
                methods_info.append(f"{cdn}({', '.join(methods)})")

            return False, f"检测到CDN: {', '.join(methods_info)}", detailed_results
        else:
            return True, "未检测到常见CDN", detailed_results

    except Exception as e:
        return False, f"CDN检测失败: {str(e)}", detailed_results


def check_tls_details_extended(domain: str, port: int = 443) -> TLSCheckResult:
    """
    详细检查TLS配置，包括X25519支持（修复证书获取问题）
    """
    result_dict = {
        "version": None,
        "cert_valid": False,
        "sni_support": False,
        "alpn_support": [],
        "cipher_suite": None,
        "cert_issuer": None,
        "cert_expiry": None,
        "x25519_support": False,
        "pfs_support": False,
        "ocsp_stapling": False,
        "details": {},
    }

    details = {}

    try:
        # 方法1: 尝试启用证书验证
        context = ssl.create_default_context()
        context.check_hostname = True  # 启用主机名检查
        context.verify_mode = ssl.CERT_REQUIRED  # 要求证书

        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # TLS版本
                result_dict["version"] = ssock.version()

                # 密码套件
                cipher = ssock.cipher()
                result_dict["cipher_suite"] = cipher[0] if cipher else None
                details["full_cipher"] = cipher

                # 检查前向保密
                cipher_name = cipher[0] if cipher else ""
                for pfs_cipher in PFS_CIPHERS:
                    if pfs_cipher in cipher_name:
                        result_dict["pfs_support"] = True
                        break

                # 证书信息 - 关键修复部分
                cert = ssock.getpeercert()
                # print(f"[DEBUG] Certificate from getpeercert(): {cert is not None}")

                if cert:
                    result_dict["cert_valid"] = True

                    # 提取颁发者
                    issuer_dict = {}
                    for item in cert.get("issuer", []):
                        for key, value in item:
                            issuer_dict[key] = value
                    result_dict["cert_issuer"] = issuer_dict.get(
                        "organizationName", issuer_dict.get("CN", "Unknown")
                    )

                    # 证书过期时间
                    expiry_str = cert.get("notAfter", "")
                    if expiry_str:
                        from datetime import datetime

                        try:
                            expiry_date = datetime.strptime(
                                expiry_str, "%b %d %H:%M:%S %Y %Z"
                            )
                            result_dict["cert_expiry"] = expiry_date.isoformat()
                        except ValueError:
                            result_dict["cert_expiry"] = expiry_str

                # 如果 getpeercert() 返回 None，尝试其他方法
                else:
                    print("[DEBUG] getpeercert() returned None, trying DER format...")
                    # 尝试获取DER格式证书
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        result_dict["cert_valid"] = True
                        result_dict["cert_issuer"] = "Certificate (DER format)"
                        print("[DEBUG] Got certificate in DER format")
                    else:
                        print("[DEBUG] No certificate in any format")

                # 检查ALPN支持
                try:
                    context2 = ssl.create_default_context()
                    context2.set_alpn_protocols(["h2", "http/1.1"])
                    context2.check_hostname = False
                    context2.verify_mode = ssl.CERT_NONE

                    with socket.create_connection((domain, port), timeout=5) as sock2:
                        with context2.wrap_socket(
                            sock2, server_hostname=domain
                        ) as ssock2:
                            alpn_protocol = ssock2.selected_alpn_protocol()
                            if alpn_protocol:
                                result_dict["alpn_support"].append(alpn_protocol)
                except:
                    pass

                # 测试SNI支持
                try:
                    with socket.create_connection((domain, port), timeout=5) as sock3:
                        with context.wrap_socket(
                            sock3, server_hostname="invalid.test.com"
                        ) as ssock3:
                            result_dict["sni_support"] = True
                except ssl.SSLError:
                    result_dict["sni_support"] = True
                except:
                    pass

        # 如果前面的方法失败，尝试使用不验证的方式
        if not result_dict["cert_valid"]:
            print("[DEBUG] Trying without certificate verification...")
            context_no_verify = ssl.create_default_context()
            context_no_verify.check_hostname = False
            context_no_verify.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, port), timeout=10) as sock:
                with context_no_verify.wrap_socket(
                    sock, server_hostname=domain
                ) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        result_dict["cert_valid"] = True
                        result_dict["cert_issuer"] = "Certificate (no verification)"

        # 2. 检查X25519支持
        x25519_ok, x25519_msg, x25519_details = check_x25519_support(domain, port)
        result_dict["x25519_support"] = x25519_ok
        details["x25519_check"] = {
            "supported": x25519_ok,
            "message": x25519_msg,
            "details": x25519_details,
        }

        # 3. 检查OCSP装订
        ocsp_ok, ocsp_msg, ocsp_details = check_ocsp_stapling(domain, port)
        result_dict["ocsp_stapling"] = ocsp_ok
        details["ocsp_check"] = {
            "supported": ocsp_ok,
            "message": ocsp_msg,
            "details": ocsp_details,
        }

        # 4. 评估安全等级
        security_level = check_tls_security_level(result_dict)
        result_dict["security_level"] = security_level

        result_dict["details"] = details

    except Exception as e:
        logger.error(f"TLS详细检测失败: {e}")
        details["error"] = str(e)
        result_dict["details"] = details

    return TLSCheckResult(**result_dict)


def comprehensive_check(domain: str, port: int = 443) -> Dict:
    """
    综合检测网站
    """
    print(f"\n{'=' * 80}")
    print(f"🔍 Reality 目标网站全面检测: {domain}:{port}")
    print("=" * 80)

    results = {
        "domain": domain,
        "port": port,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "checks": {},
    }

    # 1. 基本连通性
    print("1. 📡 检查基本连通性...")
    try:
        sock = socket.create_connection((domain, port), timeout=5)
        sock.close()
        results["checks"]["connectivity"] = {
            "status": "✅",
            "message": f"端口 {port} 开放，连接正常",
        }
        print(f"  结果: ✅ 端口 {port} 开放，连接正常")
    except Exception as e:
        results["checks"]["connectivity"] = {
            "status": "❌",
            "message": f"连接失败: {str(e)}",
        }
        print(f"  结果: ❌ 连接失败: {str(e)}")
        return results

    # 2. 详细TLS检查（包含X25519）
    print("2. 🔐 检查TLS安全配置...")
    tls_result = check_tls_details_extended(domain, port)
    results["checks"]["tls"] = asdict(tls_result)

    # 显示TLS详情
    tls_msg = f"✅ TLS {tls_result.version}"
    if tls_result.cert_valid:
        tls_msg += ", 证书有效"
    if tls_result.x25519_support:
        tls_msg += ", ✅ 支持 X25519"
    else:
        tls_msg += ", ❌ 不支持 X25519"
    if tls_result.pfs_support:
        tls_msg += ", ✅ 前向保密"
    if tls_result.ocsp_stapling:
        tls_msg += ", ✅ OCSP装订"

    print(f"  结果: {tls_msg}")

    if tls_result.cert_issuer:
        print(f"     证书颁发者: {tls_result.cert_issuer}")
    if tls_result.cipher_suite:
        print(f"     密码套件: {tls_result.cipher_suite}")
    print(f"     安全等级: {tls_result.security_level.value}")

    # 3. HTTP/2支持
    print("3. ⚡ 检查HTTP/2支持...")
    http2_ok, http2_msg, http2_details = check_http2_support(domain, port)
    results["checks"]["http2"] = {
        "supported": http2_ok,
        "message": http2_msg,
        "details": http2_details,
    }
    print(f"  结果: {'✅' if http2_ok else '❌'} {http2_msg}")

    # 4. CDN检测
    print("4. 🛡️  CDN检测...")
    cdn_ok, cdn_msg, cdn_details = check_all_cdns(domain)
    results["checks"]["cdn"] = {
        "no_cdn": cdn_ok,
        "message": cdn_msg,
        "details": cdn_details,
    }

    # 显示CDN检测详情
    detected_cdns = [cdn for cdn, info in cdn_details.items() if info["detected"]]
    if detected_cdns:
        print(f"  结果: ❌ 检测到CDN: {', '.join(detected_cdns)}")
        for cdn, info in cdn_details.items():
            if info["detected"]:
                print(f"      - {cdn}: 检测方式: {', '.join(info['methods'])}")
    else:
        print(f"  结果: ✅ 未检测到常见CDN")

    # 5. 获取IP信息
    print("5. 🌐 解析域名IP...")
    ips = get_domain_ips(domain)
    if ips:
        results["checks"]["dns"] = {"ips": ips, "count": len(ips)}
        print(f"  结果: ✅ 解析到 {len(ips)} 个IP地址")
        for ip in ips:
            cdn_check = check_ip_in_cdn_range(ip)
            if cdn_check:
                print(f"      - {ip} ⚠️  疑似CDN IP: {', '.join(cdn_check)}")
            else:
                print(f"      - {ip}")
    else:
        results["checks"]["dns"] = {"ips": [], "count": 0}
        print("  结果: ❌ DNS解析失败")

    # 总结
    print(f"\n{'=' * 80}")
    print("📊 检测总结:")
    print("=" * 80)

    # Reality适用性评分
    score = 0
    max_score = 100
    issues = []
    recommendations = []

    # 评分标准
    if results["checks"].get("connectivity", {}).get("status") == "✅":
        score += 20

    tls_check = results["checks"].get("tls", {})
    if tls_check.get("cert_valid"):
        score += 15
    if tls_check.get("x25519_support"):
        score += 20
        recommendations.append("✅ 支持X25519，适合高性能Reality部署")
    else:
        issues.append("⚠️  不支持X25519，性能可能受影响")
        score += 5  # 仍然给部分分数

    if tls_check.get("pfs_support"):
        score += 15
    else:
        issues.append("⚠️  不支持前向保密")

    if tls_check.get("security_level") in ["excellent", "good"]:
        score += 20
    elif tls_check.get("security_level") == "fair":
        score += 10
        issues.append("⚠️  TLS安全等级一般")

    if results["checks"].get("cdn", {}).get("no_cdn"):
        score += 20
    else:
        issues.append("❌ 使用CDN，不适合Reality")
        score = 0  # CDN一票否决

    if results["checks"].get("http2", {}).get("supported"):
        score += 10
        recommendations.append("✅ 支持HTTP/2，连接效率高")

    # 适用性判断
    suitable_for_reality = (
        results["checks"].get("connectivity", {}).get("status") == "✅"
        and tls_check.get("cert_valid") == True
        and results["checks"].get("cdn", {}).get("no_cdn") == True
    )

    # print(results["checks"].get("connectivity", {}).get("status"))
    # print(tls_check.get("cert_valid"))
    # print(results["checks"].get("cdn", {}).get("no_cdn"))
    # print(results)
    # print(tls_check)

    # 输出详细报告
    if suitable_for_reality:
        rating = score / max_score * 5
        stars = "★" * int(rating) + "☆" * (5 - int(rating))

        print(f"\n🎉 适合作为 Reality 目标!")
        print(f"   适用性评分: {score}/{max_score} {stars} ({rating:.1f}/5.0)")

        if tls_check.get("x25519_support"):
            print("   ✨ 优秀特性: 支持X25519椭圆曲线")
        if results["checks"].get("http2", {}).get("supported"):
            print("   ⚡ 优秀特性: 支持HTTP/2")
        if tls_check.get("ocsp_stapling"):
            print("   🔒 优秀特性: 支持OCSP装订")

        # 显示推荐配置
        print(f"\n💡 推荐配置:")
        print(f"   域名: {domain}")
        if ips:
            print(f"   IP地址: {ips[0]} (共{len(ips)}个)")
        print(f"   端口: {port}")
        print(f"   TLS版本: {tls_check.get('version', '未知')}")
        if tls_check.get("x25519_support"):
            print(f"   密钥交换: X25519 (推荐)")
        else:
            print(f"   密钥交换: 其他曲线")

    else:
        print("\n⚠️  可能不适合作为 Reality 目标:")
        for issue in issues:
            print(f"   ❌ {issue}")

        # 给出改进建议
        if not tls_check.get("x25519_support"):
            print(f"\n💡 建议: 寻找支持X25519的网站以获得更好性能")

    # 输出所有建议
    if recommendations:
        print(f"\n📋 技术建议:")
        for rec in recommendations:
            print(f"   {rec}")

    print(f"\n{'=' * 80}")
    return results


def batch_check(domains_file: str, output_file: str = None):
    """
    批量检测域名
    """
    try:
        with open(domains_file, "r") as f:
            domains = [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
    except FileNotFoundError:
        print(f"错误: 文件 {domains_file} 不存在")
        return

    print(f"开始批量检查 {len(domains)} 个域名...\n")

    suitable_domains = []
    all_results = []

    for i, domain in enumerate(domains, 1):
        print(f"\n{'#' * 60}")
        print(f"检测进度: [{i}/{len(domains)}] - {domain}")
        print("#" * 60)

        try:
            results = comprehensive_check(domain)
            all_results.append(results)

            # 判断是否适合
            suitable = (
                results["checks"].get("connectivity", {}).get("status") == "✅"
                and results["checks"].get("tls", {}).get("cert_valid") == True
                and results["checks"].get("cdn", {}).get("no_cdn") == True
            )

            if suitable:
                tls_info = results["checks"].get("tls", {})
                suitable_domains.append(
                    {
                        "domain": domain,
                        "ips": results["checks"].get("dns", {}).get("ips", []),
                        "x25519": tls_info.get("x25519_support", False),
                        "http2": results["checks"]
                        .get("http2", {})
                        .get("supported", False),
                        "tls_version": tls_info.get("version"),
                        "security_level": tls_info.get("security_level"),
                    }
                )

        except Exception as e:
            print(f"❌ 检测 {domain} 时出错: {str(e)}")

    # 输出结果
    if suitable_domains:
        print(f"\n{'=' * 80}")
        print(f"🎯 找到 {len(suitable_domains)} 个适合 Reality 的域名:")
        print("=" * 80)

        # 按安全等级排序
        suitable_domains.sort(
            key=lambda x: (
                1
                if x.get("security_level") == "excellent"
                else 2
                if x.get("security_level") == "good"
                else 3
                if x.get("security_level") == "fair"
                else 4,
                x.get("x25519", False),
                x.get("http2", False),
            ),
            reverse=False,
        )

        for item in suitable_domains:
            features = []
            if item.get("x25519"):
                features.append("X25519")
            if item.get("http2"):
                features.append("HTTP/2")
            if item.get("tls_version") == "TLSv1.3":
                features.append("TLS 1.3")

            features_str = f"({', '.join(features)})" if features else ""
            security_emoji = {
                "excellent": "🟢",
                "good": "🟡",
                "fair": "🟠",
                "poor": "🔴",
            }.get(item.get("security_level"), "⚪")

            print(f"\n{security_emoji} {item['domain']} {features_str}")
            if item["ips"]:
                print(
                    f"   IP地址: {item['ips'][0]}"
                    + (f" 等{len(item['ips'])}个" if len(item["ips"]) > 1 else "")
                )
            print(f"   安全等级: {item.get('security_level', 'unknown')}")
    else:
        print("\n❌ 未找到适合 Reality 的域名")

    # 保存结果
    if output_file:
        try:
            with open(output_file, "w") as f:
                json.dump(all_results, f, indent=2, ensure_ascii=False)
            print(f"\n📁 详细结果已保存到: {output_file}")
        except Exception as e:
            print(f"保存结果失败: {e}")


def quick_x25519_check(domain: str, port: int = 443):
    """
    快速检查X25519支持
    """
    print(f"🔍 快速X25519检测: {domain}:{port}")
    print("=" * 50)

    # 尝试OpenSSL检测
    print("1. 使用OpenSSL检测...")
    result, msg, details = check_x25519_support_openssl(domain, port)

    if "openssl_not_found" in details.get("error", ""):
        print("   ⚠️  OpenSSL不可用，使用Python检测")
        result, msg, details = check_x25519_support_python(domain, port)

    if result:
        print(f"   ✅ {msg}")

        # 显示详情
        if "tls13_cipher" in details:
            print(f"     密码套件: {details['tls13_cipher']}")
        if "cipher" in details:
            print(f"     密码套件: {details['cipher']}")
    else:
        print(f"   ❌ {msg}")

    # 检查TLS版本
    print("\n2. 检查TLS版本...")
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                print(f"   TLS版本: {version}")
                if cipher:
                    print(f"   密码套件: {cipher[0]}")
                    print(f"   协议版本: {cipher[1]}")
                    print(f"   加密位数: {cipher[2]}")
    except Exception as e:
        print(f"   ❌ TLS检测失败: {e}")

    print("\n" + "=" * 50)
    print("💡 X25519是现代TLS连接的推荐椭圆曲线，能提供更好的性能和安全性。")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Reality 协议目标网站全面检测工具 v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 单个网站全面检测
  python reality_checker_x25519.py example.com
  
  # 快速X25519检测
  python reality_checker_x25519.py example.com --quick-x25519
  
  # 指定端口
  python reality_checker_x25519.py example.com -p 8443
  
  # 批量检测
  python reality_checker_x25519.py -b domains.txt
  
  # 批量检测并保存结果
  python reality_checker_x25519.py -b domains.txt -o results.json
        """,
    )

    parser.add_argument("domain", nargs="?", help="要检查的域名")
    parser.add_argument(
        "-p", "--port", type=int, default=443, help="端口号（默认: 443）"
    )
    parser.add_argument("-b", "--batch", help="批量检查，提供包含域名的文本文件路径")
    parser.add_argument("-o", "--output", help="将结果保存到JSON文件")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出")
    parser.add_argument("--quick-x25519", action="store_true", help="快速X25519检测")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # 忽略SSL警告
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    import warnings

    warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    if args.quick_x25519 and args.domain:
        quick_x25519_check(args.domain, args.port)
    elif args.batch:
        batch_check(args.batch, args.output)
    elif args.domain:
        results = comprehensive_check(args.domain, args.port)

        if args.output:
            try:
                with open(args.output, "w") as f:
                    json.dump([results], f, indent=2, ensure_ascii=False)
                print(f"\n📁 结果已保存到: {args.output}")
            except Exception as e:
                print(f"保存结果失败: {e}")
    else:
        parser.print_help()
        print("\n💡 特性说明:")
        print("  • ✅ X25519椭圆曲线支持检测")
        print("  • ✅ TLS 1.3完整支持检测")
        print("  • ✅ 前向保密(PFS)支持检测")
        print("  • ✅ OCSP装订支持检测")
        print("  • ✅ HTTP/2支持检测")
        print("  • ✅ 多CDN检测(Cloudflare, CloudFront, Fastly)")
        print("  • ✅ 安全等级评估")
        print("\n📋 依赖:")
        print("  pip install requests dnspython")
        print("  # 需要系统安装openssl命令行工具以获得最佳检测效果")


if __name__ == "__main__":
    main()
