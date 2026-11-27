from __future__ import annotations

import asyncio
from collections import deque
from copy import deepcopy
from time import monotonic
import base64
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import socket
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
import html
import joblib
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Avoid logging full outbound URLs, which can contain API keys.
logging.getLogger("httpx").setLevel(logging.WARNING)

load_dotenv()

app = FastAPI(title="LinkSentry Scanner", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class ScanRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)

class EmailClassificationRequest(BaseModel):
    subject: str = Field(default="", max_length=500)
    body: str = Field(default="", max_length=20000)


def normalize_url(raw: str) -> tuple[str, str]:
    value = raw.strip()
    if not value:
        raise HTTPException(status_code=422, detail="Enter a website address to scan.")
    if "://" not in value:
        value = "https://" + value
    try:
        parts = urlsplit(value)
        host = (parts.hostname or "").rstrip(".").lower()
        port = parts.port
    except ValueError:
        raise HTTPException(status_code=422, detail="That address is not a valid URL.")
    if parts.scheme not in {"http", "https"} or not host:
        raise HTTPException(status_code=422, detail="Use a valid http or https website address.")
    if parts.username or parts.password:
        raise HTTPException(status_code=422, detail="Links containing embedded usernames or passwords are not accepted.")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise HTTPException(status_code=422, detail="The domain name is not valid.")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".test")):
        raise HTTPException(status_code=422, detail="Private or local network addresses cannot be scanned.")
    try:
        parsed_ip = ipaddress.ip_address(host)
        if not parsed_ip.is_global:
            raise HTTPException(status_code=422, detail="Private or non-public IP addresses cannot be scanned.")
    except ValueError:
        if "." not in host or len(host) > 253 or any(not label or len(label) > 63 for label in host.split(".")):
            raise HTTPException(status_code=422, detail="Enter a public domain name, such as example.com.")
    netloc = host + (f":{port}" if port else "")
    normalized = urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))
    return normalized, host


async def dns_lookup(host: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
        for kind in ("A", "AAAA", "MX", "NS"):
            try:
                response = await client.get(
                    "https://cloudflare-dns.com/dns-query",
                    params={"name": host, "type": kind},
                    headers={"accept": "application/dns-json"},
                )
                response.raise_for_status()
                body = response.json()
                for answer in body.get("Answer", [])[:4]:
                    value = str(answer.get("data", ""))
                    if value and len(value) <= 300:
                        records.append({"type": kind, "value": value})
            except (httpx.HTTPError, ValueError):
                continue
    return records


async def hosting_lookup(host: str, records: list[dict[str, str]]) -> str:
    candidates: list[str] = []
    try:
        address = ipaddress.ip_address(host)
        if address.is_global:
            candidates.append(str(address))
    except ValueError:
        pass

    for record in records:
        if record.get("type") not in {"A", "AAAA"}:
            continue
        try:
            address = ipaddress.ip_address(record.get("value", ""))
            if address.is_global and str(address) not in candidates:
                candidates.append(str(address))
        except ValueError:
            continue

    if not candidates:
        return "No public IP address found"

    ip = candidates[0]
    registered_owner = ""
    network = ""
    prefix = ""

    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            try:
                response = await client.get(f"https://rdap.org/ip/{ip}")
                response.raise_for_status()
                rdap = response.json()

                for entity in rdap.get("entities", []):
                    card = entity.get("vcardArray", [])
                    if len(card) < 2 or not isinstance(card[1], list):
                        continue
                    for item in card[1]:
                        if len(item) >= 4 and item[0] in {"fn", "org"}:
                            value = item[3]
                            if isinstance(value, list):
                                value = " ".join(str(part) for part in value)
                            registered_owner = str(value).strip()
                            if registered_owner:
                                break
                    if registered_owner:
                        break

                if not registered_owner:
                    registered_owner = str(rdap.get("name") or "").strip()

                cidrs = rdap.get("cidr0_cidrs", [])
                if cidrs:
                    block = cidrs[0]
                    if "v4prefix" in block:
                        prefix = f"{block['v4prefix']}/{block.get('length', '')}"
                    elif "v6prefix" in block:
                        prefix = f"{block['v6prefix']}/{block.get('length', '')}"
            except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError):
                pass

            try:
                response = await client.get(
                    "https://stat.ripe.net/data/network-info/data.json",
                    params={"resource": ip},
                )
                response.raise_for_status()
                network_data = response.json().get("data", {})
                asns = network_data.get("asns", [])
                prefix = prefix or str(network_data.get("prefix", ""))

                if asns:
                    asn = str(asns[0])
                    network = f"AS{asn}"
                    try:
                        owner_response = await client.get(
                            "https://stat.ripe.net/data/as-overview/data.json",
                            params={"resource": asn},
                        )
                        owner_response.raise_for_status()
                        holder = str(
                            owner_response.json().get("data", {}).get("holder") or ""
                        ).strip()
                        if holder:
                            network += f" {holder}"
                    except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError):
                        pass
            except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError):
                pass
    except httpx.HTTPError:
        pass

    details = []
    if registered_owner:
        details.append(f"{registered_owner} (registered IP owner)")
    if network:
        details.append(f"{network} (announcing network)")
    if prefix:
        details.append(prefix)

    if not details:
        return "Network owner lookup unavailable"
    return " | ".join(details)


def url_signals(url: str, host: str) -> list[str]:
    flags: list[str] = []

    try:
        ipaddress.ip_address(host)
        flags.append("Uses an IP address directly instead of a domain name")
    except ValueError:
        pass

    labels = host.split(".")
    if any(label.startswith("xn--") for label in labels):
        flags.append("Contains an internationalized (punycode) domain")

    # Check the apparent registered domain, not every subdomain.
    # This avoids flagging ordinary hostnames such as accounts.google.com.
    apparent_registered_label = labels[-2] if len(labels) > 1 else labels[0]
    if re.search(
        r"(login|verify|secure|account|wallet|update|signin|password)",
        apparent_registered_label,
        re.I,
    ):
        flags.append(
            "Registered domain name contains words often used in account or verification lures"
        )

    if host.count(".") >= 4:
        flags.append("Has an unusually deep subdomain structure")

    if len(url) > 180:
        flags.append("URL is unusually long")

    return flags


class PageTitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.parts: list[str] = []
        self.description: str | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        attributes = {key.lower(): value for key, value in attrs if key}

        if tag == "title":
            self.in_title = True
        elif tag == "meta":
            name = str(attributes.get("name") or "").lower()
            prop = str(attributes.get("property") or "").lower()
            content = str(attributes.get("content") or "").strip()
            if content and (name == "description" or prop == "og:description"):
                self.description = content[:300]

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.parts.append(data)


class PublicOnlyResolver:
    def __init__(self) -> None:
        import aiohttp
        self._resolver = aiohttp.resolver.DefaultResolver()

    async def resolve(self, host, port=0, family=socket.AF_UNSPEC):
        results = await self._resolver.resolve(host, port, family)
        for item in results:
            try:
                address = ipaddress.ip_address(item["host"])
            except ValueError as error:
                raise OSError("Could not validate destination address.") from error
            if not address.is_global:
                raise OSError("Destination is private or non-public.")
        return results

    async def close(self) -> None:
        await self._resolver.close()


async def inspect_page(url: str) -> tuple[str | None, str, list[str], str | None]:
    import aiohttp

    max_bytes = 512 * 1024
    redirect_hosts: list[str] = []
    current_url = url

    try:
        connector = aiohttp.TCPConnector(
            resolver=PublicOnlyResolver(),
            use_dns_cache=False,
            limit=2,
        )
        timeout = aiohttp.ClientTimeout(total=6, connect=3, sock_read=3)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            trust_env=False,
            headers={"User-Agent": "LinkSentry-PageCheck/1.0"},
        ) as session:
            for redirect_count in range(6):
                normalized_url, current_host = normalize_url(current_url)
                async with session.get(
                    normalized_url,
                    allow_redirects=False,
                    max_redirects=0,
                ) as response:
                    if response.status in {301, 302, 303, 307, 308}:
                        location = response.headers.get("Location")
                        if not location:
                            return None, "Redirect had no destination.", redirect_hosts, None
                        if redirect_count >= 5:
                            return None, "Stopped after five redirects.", redirect_hosts, None

                        next_url = urljoin(normalized_url, location)
                        safe_url, next_host = normalize_url(next_url)
                        if next_host != current_host:
                            redirect_hosts.append(next_host)
                        current_url = safe_url
                        continue

                    content_type = response.headers.get("Content-Type", "").lower()
                    if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
                        return None, "Destination did not return an HTML page.", redirect_hosts, None

                    body = await response.content.read(max_bytes + 1)
                    body = body[:max_bytes]
                    html_text = body.decode(response.charset or "utf-8", errors="replace")

                    parser = PageTitleParser()
                    parser.feed(html_text)
                    title = " ".join(" ".join(parser.parts).split())[:200] or None

                    details = [f"Page title: {title}" if title else "No page title was found."]
                    if redirect_hosts:
                        details.append("Redirected through: " + " -> ".join(redirect_hosts))
                    else:
                        details.append("No cross-domain redirect was detected.")
                    details.append("Page scripts were not run.")
                    return title, " ".join(details), redirect_hosts, parser.description

        return None, "The page could not be inspected.", redirect_hosts, None
    except HTTPException:
        return None, "A redirect was blocked because its address was invalid or non-public.", redirect_hosts, None
    except (OSError, TimeoutError, ValueError, LookupError):
        return None, "The page could not be safely inspected.", redirect_hosts, None
    except Exception:
        return None, "The page could not be safely inspected.", redirect_hosts, None


async def virustotal_lookup(url: str) -> tuple[str, str]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return "unknown", "VirusTotal is not configured."
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=False) as client:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": api_key},
            )
        if response.status_code == 404:
            return "unknown", "No existing VirusTotal report was found for this URL."
        response.raise_for_status()
        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(value) for value in stats.values() if isinstance(value, int))
        if malicious:
            return "bad", f"VirusTotal reports {malicious} malicious detections across {total} engines."
        if suspicious:
            return "warning", f"VirusTotal reports {suspicious} suspicious detections across {total} engines."
        return "good", f"No malicious detections in the existing VirusTotal report ({total} engines)."
    except (httpx.HTTPError, ValueError, TypeError):
        return "unknown", "VirusTotal could not return a result."


def _read_proto_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data) and shift < 70:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
    raise ValueError("Malformed protobuf varint")


def _proto_fields(data: bytes):
    offset = 0
    while offset < len(data):
        tag, offset = _read_proto_varint(data, offset)
        number, wire_type = tag >> 3, tag & 7
        if number == 0:
            raise ValueError("Invalid protobuf field number")

        if wire_type == 0:
            value, offset = _read_proto_varint(data, offset)
        elif wire_type == 1:
            value = data[offset:offset + 8]
            if len(value) != 8:
                raise ValueError("Truncated protobuf field")
            offset += 8
        elif wire_type == 2:
            length, offset = _read_proto_varint(data, offset)
            value = data[offset:offset + length]
            if len(value) != length:
                raise ValueError("Truncated protobuf field")
            offset += length
        elif wire_type == 5:
            value = data[offset:offset + 4]
            if len(value) != 4:
                raise ValueError("Truncated protobuf field")
            offset += 4
        else:
            raise ValueError("Unsupported protobuf wire type")

        yield number, wire_type, value


def parse_safe_browsing_response(data: bytes) -> tuple[bool, list[str]]:
    names = {
        1: "MALWARE",
        2: "SOCIAL_ENGINEERING",
        3: "UNWANTED_SOFTWARE",
        4: "POTENTIALLY_HARMFUL_APPLICATION",
    }
    matched = False
    found = set()

    # SearchUrlsResponse.threats is field 1.
    # ThreatUrl.threat_types is field 2.
    for field_number, wire_type, threat in _proto_fields(data):
        if field_number != 1 or wire_type != 2:
            continue

        matched = True
        found_in_entry = False
        for child_number, child_wire, value in _proto_fields(threat):
            if child_number != 2:
                continue

            if child_wire == 0:
                enum_values = [value]
            elif child_wire == 2:
                enum_values = []
                offset = 0
                while offset < len(value):
                    enum_value, offset = _read_proto_varint(value, offset)
                    enum_values.append(enum_value)
            else:
                continue

            for enum_value in enum_values:
                found.add(names.get(enum_value, f"UNKNOWN_THREAT_TYPE_{enum_value}"))
                found_in_entry = True

        if not found_in_entry:
            found.add("UNKNOWN_THREAT_TYPE")

    return matched, sorted(found)


async def google_safe_browsing_lookup(url: str) -> tuple[str, str]:
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return "unknown", "Google Safe Browsing is not configured. Add its API key to scanner/.env."

    try:
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=False) as client:
            response = await client.get(
                "https://safebrowsing.googleapis.com/v5/urls:search",
                params=[("key", api_key), ("urls", url)],
            )
        response.raise_for_status()

        matched, categories = parse_safe_browsing_response(response.content)
        if matched:
            label = ", ".join(categories) if categories else "a known threat"
            return "bad", (
                f"Google Safe Browsing identifies this URL as potentially unsafe ({label}). "
                "Advisory provided by Google."
            )

        return "good", (
            "No known threats were found in Google Safe Browsing's lists. "
            "This is not a safety guarantee."
        )
    except httpx.HTTPStatusError as error:
        message = error.response.content[:180].decode("utf-8", errors="replace")
        return "unknown", f"Google API HTTP {error.response.status_code}: {message}"
    except (httpx.HTTPError, ValueError, TypeError) as error:
        return "unknown", f"Google lookup failed: {type(error).__name__}"


async def threat_lookup(url: str) -> tuple[str, str, str | None]:
    if os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip():
        status, detail = await google_safe_browsing_lookup(url)
        return status, detail, "Google Safe Browsing"
    if os.getenv("VIRUSTOTAL_API_KEY", "").strip():
        status, detail = await virustotal_lookup(url)
        return status, detail, "VirusTotal"
    return (
        "unknown",
        "Threat reputation is not configured. Add GOOGLE_SAFE_BROWSING_API_KEY to scanner/.env.",
        None,
    )


def category_for(
    host: str,
    title: str | None = None,
    description: str | None = None,
) -> str:
    known_sites = {
        "google.com": "Search / account services",
        "accounts.google.com": "Account sign-in",
        "paypal.com": "Payments",
        "facebook.com": "Social network",
        "microsoft.com": "Software / account services",
        "amazon.com": "Online shopping",
        "apple.com": "Technology / account services",
        "github.com": "Developer platform",
    }
    known = next(
        (label for domain, label in known_sites.items()
         if host == domain or host.endswith("." + domain)),
        None,
    )
    if known:
        return known

    text = f"{title or ''} {description or ''}".casefold()
    categories = [
        ("Cybersecurity tool", ("phishing link checker", "url scanner", "url scanning", "link checker", "security scanner", "malware scanner")),
        ("Travel website", ("travel", "trip", "tour", "destination", "holiday", "vacation", "flight", "hotel", "itinerary")),
        ("Online store", ("shop", "shopping", "store", "products", "product catalog", "e-commerce", "checkout")),
        ("Financial services", ("banking", "bank", "payments", "payment services", "wallet", "fintech")),
        ("News or media", ("news", "newspaper", "journalism", "magazine", "articles")),
        ("Education website", ("school", "university", "course", "learning", "education")),
        ("Software or documentation", ("developer", "documentation", "api reference", "software")),
    ]
    for label, keywords in categories:
        if any(keyword in text for keyword in keywords):
            return f"{label} (inferred from page metadata)"
    return "Website (not classified)"




_SCAN_RATE_WINDOW_SECONDS = 60.0
_SCAN_CACHE_MAX_ENTRIES = 500
_scan_request_times: dict[str, deque[float]] = {}
_scan_cache: dict[str, tuple[float, dict]] = {}


def _scan_rate_limit() -> int:
    try:
        return max(1, min(int(os.getenv("SCAN_RATE_LIMIT_PER_MINUTE", "15")), 120))
    except ValueError:
        return 15


def _scan_cache_ttl() -> int:
    try:
        return max(0, min(int(os.getenv("SCAN_CACHE_TTL_SECONDS", "300")), 3600))
    except ValueError:
        return 300


def enforce_scan_rate_limit(client_key: str) -> None:
    now = monotonic()
    bucket = _scan_request_times.setdefault(client_key, deque())

    while bucket and now - bucket[0] >= _SCAN_RATE_WINDOW_SECONDS:
        bucket.popleft()

    if len(bucket) >= _scan_rate_limit():
        raise HTTPException(
            status_code=429,
            detail="Scan limit reached. Please wait a minute before scanning again.",
            headers={"Retry-After": "60"},
        )

    bucket.append(now)

    if len(_scan_request_times) > 5000:
        for key, events in list(_scan_request_times.items()):
            while events and now - events[0] >= _SCAN_RATE_WINDOW_SECONDS:
                events.popleft()
            if not events:
                _scan_request_times.pop(key, None)


def get_cached_scan(url: str) -> dict | None:
    now = monotonic()
    entry = _scan_cache.get(url)
    if entry is None:
        return None

    expires_at, result = entry
    if expires_at <= now:
        _scan_cache.pop(url, None)
        return None

    cached_result = deepcopy(result)
    cached_result["checkedAt"] = datetime.now(timezone.utc).isoformat()
    return cached_result


def cache_scan_result(url: str, result: dict) -> None:
    ttl = _scan_cache_ttl()
    if ttl <= 0:
        return

    now = monotonic()
    for key, (expires_at, _) in list(_scan_cache.items()):
        if expires_at <= now:
            _scan_cache.pop(key, None)

    if len(_scan_cache) >= _SCAN_CACHE_MAX_ENTRIES and url not in _scan_cache:
        oldest_key = next(iter(_scan_cache))
        _scan_cache.pop(oldest_key, None)

    _scan_cache[url] = (now + ttl, deepcopy(result))


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "LinkSentry Scanner"}


@app.post("/api/scan")
async def scan(request: ScanRequest, http_request: Request) -> dict:
    url, host = normalize_url(request.url)
    client_key = http_request.client.host if http_request.client else "unknown"
    enforce_scan_rate_limit(client_key)

    cached_result = get_cached_scan(url)
    if cached_result is not None:
        return cached_result
    dns_records = await dns_lookup(host)
    reputation, hosting, page_inspection = await asyncio.gather(
        threat_lookup(url),
        hosting_lookup(host, dns_records),
        inspect_page(url),
    )
    site_title, page_detail, redirect_chain, site_description = page_inspection
    reputation_status, reputation_detail, threat_source = reputation
    signals = url_signals(url, host)
    findings: list[dict[str, str]] = []
    findings.append({"name": "Threat reputation", "status": reputation_status, "detail": reputation_detail})
    findings.append({
        "name": "DNS records",
        "status": "good" if dns_records else "warning",
        "detail": f"Found {len(dns_records)} public DNS answers." if dns_records else "No public DNS answers were returned; this could be temporary or the domain may not resolve.",
    })
    findings.append({
        "name": "URL structure",
        "status": "warning" if signals else "good",
        "detail": "; ".join(signals) if signals else "No common suspicious URL patterns were found.",
    })
    findings.append({
        "name": "Page inspection",
        "status": "unknown",
        "detail": page_detail,
    })

    score = 0
    if reputation_status == "bad":
        score += 85
    elif reputation_status == "warning":
        score += 45
    score += min(len(signals) * 18, 54)
    if not dns_records:
        score += 12
    score = min(score, 100)
    if reputation_status == "bad" or score >= 60:
        risk, summary = "high", "Strong warning signals were found. Avoid opening this link or entering information."
    elif score >= 25:
        risk, summary = "medium", "Some warning signals need review. Check the evidence before proceeding."
    elif reputation_status == "good" and not signals and dns_records:
        risk, summary = "low", "No threats were reported by the connected checks. This is not a safety guarantee."
    else:
        risk, summary, score = "unknown", "There is not enough threat intelligence to rate this link confidently.", None

    result = {
        "url": url,
        "domain": host,
        "risk": risk,
        "score": score,
        "summary": summary,
        "checkedAt": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "threatSource": threat_source,
        "dns": dns_records,
        "hosting": hosting,
        "siteTitle": site_title,
        "redirects": redirect_chain,
        "category": category_for(host, site_title, site_description),
    }
    cache_scan_result(url, result)
    return result


_EMAIL_MODEL = None
_EMAIL_MODEL_PATH = Path(__file__).resolve().parent / "models" / "email_content_model.joblib"

def _get_email_model():
    global _EMAIL_MODEL
    if _EMAIL_MODEL is None:
        if not _EMAIL_MODEL_PATH.exists():
            raise HTTPException(status_code=503, detail="Email classifier model is not installed.")
        try:
            _EMAIL_MODEL = joblib.load(_EMAIL_MODEL_PATH)["model"]
        except Exception as error:
            raise HTTPException(status_code=503, detail="Email classifier model could not be loaded.") from error
    return _EMAIL_MODEL

def _clean_email_text(value: str) -> str:
    text = html.unescape(value or "")
    text = re.sub(r"(?i)\\b(?:https?://|www\\.)\\S+", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\\s+", " ", text).strip()

@app.post("/api/email-classify")
def classify_email(request: EmailClassificationRequest):
    text = " ".join(
        part for part in (
            _clean_email_text(request.subject),
            _clean_email_text(request.body),
        ) if part
    )
    if not text:
        raise HTTPException(status_code=422, detail="Paste an email subject or message body.")

    model = _get_email_model()
    try:
        positive_index = list(model.classes_).index(1)
        phishing_score = float(model.predict_proba([text])[0][positive_index])
    except Exception as error:
        raise HTTPException(status_code=503, detail="Email classification failed.") from error

    verdict = "likely_phishing" if phishing_score >= 0.5 else "no_obvious_phishing_signs"
    return {
        "verdict": verdict,
        "phishing_score": round(phishing_score * 100, 1),
        "note": "This is a content-model estimate, not a guarantee. Review the evidence and verify the sender independently.",
    }
