#!/usr/bin/env python3
"""CloakSee - triagem superficial de ameaças em sites via matriz de User-Agents.

Busca a mesma URL com varios perfis de User-Agent em paralelo, registra a
cadeia de redirecionamentos de cada perfil, compara as respostas entre si
(cloaking) e aplica assinaturas estaticas de malware/obfuscação.

Especificação completa: PLANO.md neste diretório.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import ipaddress
import json
import math
import os
import re
import secrets
import socket
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from html.parser import HTMLParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


# ---------------------------------------------------------------------------
# Configuração
# Precedência: variável de ambiente > arquivo .env > default abaixo.
ROOT = Path(__file__).resolve().parent


def load_env_file(path: Path) -> dict[str, str]:
    """Parser .env mínimo (stdlib): KEY=VALUE, ignora comentários e vazias."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def env_config(file_values: dict[str, str], key: str, default: str) -> str:
    return os.environ.get(key, file_values.get(key, default))


_ENV = load_env_file(ROOT / ".env")

SERVER_PORT = int(env_config(_ENV, "SERVER_PORT", "8791"))
PASSWORD_PROTECTED = int(env_config(_ENV, "PASSWORD_PROTECTED", "0"))
ACCESS_PASSWORD = env_config(_ENV, "ACCESS_PASSWORD", "")
SESSION_COOKIE_NAME = "cloaksee_session"
APP_NAME = "CloakSee"

MAX_BYTES = 3_000_000
TIMEOUT_SECONDS = 15
MAX_REDIRECTS = 8
# 1 = permite escanear hosts privados/localhost (staging interno e testes).
# Deixe 0 se a ferramenta for exposta em rede não confiável.
ALLOW_PRIVATE_HOSTS = int(env_config(_ENV, "CLOAKSEE_ALLOW_PRIVATE_HOSTS", "0"))

SESSION_TOKEN = secrets.token_urlsafe(32)
BASELINE_UA = "chrome-win"
BLOCKED_STATUSES = {403, 429, 503}
SIMILARITY_SAME = 0.90
SIMILARITY_LOW = 0.70
SHINGLE_K = 8
SHINGLE_STRIDE_TARGET = 100_000

# ---------------------------------------------------------------------------
# Matriz de User-Agents (editável sem tocar em lógica)
USER_AGENTS: list[dict[str, str]] = [
    {
        "id": "chrome-win",
        "label": "Chrome · Windows",
        "category": "browser",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    },
    {
        "id": "firefox-win",
        "label": "Firefox · Windows",
        "category": "browser",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    },
    {
        "id": "safari-mac",
        "label": "Safari · macOS",
        "category": "browser",
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    },
    {
        "id": "chrome-android",
        "label": "Chrome · Android",
        "category": "browser",
        "ua": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    },
    {
        "id": "safari-iphone",
        "label": "Safari · iPhone",
        "category": "browser",
        "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    },
    {
        "id": "googlebot",
        "label": "Googlebot",
        "category": "bot",
        "ua": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    },
    {
        "id": "bingbot",
        "label": "Bingbot",
        "category": "bot",
        "ua": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    },
    {
        "id": "curl",
        "label": "curl (UA mínimo)",
        "category": "tool",
        "ua": "curl/8.5.0",
    },
    {
        "id": "powershell",
        "label": "PowerShell · Windows",
        "category": "tool",
        "ua": "Mozilla/5.0 (Windows NT; Windows NT 10.0; pt-BR) WindowsPowerShell/5.1.22621.2506",
    },
]

# Perfis usados na passada por origem (Referer)
REFERER_UA_IDS = ("chrome-win", "chrome-android")

# Origens testadas: malware costuma redirecionar só quem vem de busca/redes sociais
REFERERS: list[dict[str, str]] = [
    {"id": "google", "label": "Google", "referer": "https://www.google.com/search?q=teste"},
    {"id": "bing", "label": "Bing", "referer": "https://www.bing.com/search?q=teste"},
    {"id": "whatsapp", "label": "WhatsApp", "referer": "https://l.whatsapp.com/"},
    {"id": "instagram", "label": "Instagram", "referer": "https://l.instagram.com/"},
    {"id": "youtube", "label": "YouTube", "referer": "https://www.youtube.com/"},
    {"id": "facebook", "label": "Facebook", "referer": "https://l.facebook.com/"},
    {"id": "twitter", "label": "X/Twitter", "referer": "https://t.co/"},
    {"id": "tiktok", "label": "TikTok", "referer": "https://www.tiktok.com/"},
]
RISK_TLDS = {
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "club", "online", "live",
    "rest", "surf", "cyou", "icu", "cam", "sbs", "monster", "buzz",
}

# Seed conservadora; edite livremente (case-insensitive).
MALWARE_KEYWORDS = [
    "wp-vcd",
    "wp_temp_setup",
    "class_wpvcd",
    "wp_enqueue_code",
    "coinhive",
    "cryptoloot",
    "jsecoin",
    "deepminer",
    "minero",
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

CC_WITH_SLD = {"br", "uk", "ar", "cl", "co", "mx", "au", "jp", "cn", "in", "nz", "za"}
SLD_LABELS = {"com", "net", "org", "gov", "edu"}

NONCE_ATTR_RE = re.compile(r'nonce="[^"]*"')
QS_NOISE_RE = re.compile(r"[?&](?:_wpnonce|nonce|ts|timestamp|cache|v|ver)=[A-Za-z0-9_.\-]{1,24}")
COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
JSON_SECRET_RE = re.compile(r'"(?:nonce|_wpnonce|security|csrf|token)"\s*:\s*"[A-Za-z0-9_\-]{6,64}"')
HIDDEN_TOKEN_RE = re.compile(r'(name="[^"]*(?:nonce|token|security|csrf)[^"]*"[^>]*?value=")[^"]*"', re.IGNORECASE)
JQUERY_CB_RE = re.compile(r"[?&]_=\d{10,}")
TOKEN_RE = re.compile(r"[a-z0-9]+")
WS_RE = re.compile(r"\s+")

EVAL_CODED_RE = re.compile(
    r"eval\s*\(\s*(?:atob|window\.atob|unescape|decodeURIComponent|String\.fromCharCode)"
)
DOCWRITE_RE = re.compile(r"document\.write\s*\(\s*unescape\s*\(")
FROMCHARCODE_RE = re.compile(r"String\.fromCharCode\s*\(\s*\d{1,3}(?:\s*,\s*\d{1,3}){19,}")
ATOB_INLINE_RE = re.compile(r"atob\s*\(\s*[\"'][A-Za-z0-9+/=]{80,}[\"']")
B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/=]{400,}")
HEX_BLOB_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){60,}")
JS_REDIR_RE = re.compile(
    r"(?:window\.)?location(?:\.(?:href|replace|assign))?\s*[=(](?!=)\s*[\"']https?://([^/\"'\s]+)"
)
META_REFRESH_URL_RE = re.compile(r"url\s*=\s*[\"']?([^;\"']+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Helpers gerais
def normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(value or "")).strip()


def clip(text: str, limit: int = 240) -> str:
    clean = (text or "").replace("\n", " ").strip()
    return clean if len(clean) <= limit else clean[: limit - 1] + "…"


def decode_body(data: bytes, content_type: str) -> str:
    match = re.search(r"charset=([^;\s]+)", content_type, re.IGNORECASE)
    encoding = match.group(1).strip("\"'") if match else "utf-8"
    try:
        return data.decode(encoding, errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in freq.values())


def root_domain(host: str) -> str:
    name = (host or "").strip().lower().removeprefix("www.")
    if not name:
        return ""
    parts = name.split(".")
    if len(parts) >= 3 and parts[-1] in CC_WITH_SLD and parts[-2] in SLD_LABELS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").strip().lower()


def is_external(url: str, base_host: str) -> bool:
    target = root_domain(host_of(url))
    return bool(target) and target != root_domain(base_host)


def risk_tld_of(url: str) -> bool:
    name = host_of(url).removeprefix("www.")
    if not name:
        return False
    return name.split(".")[-1] in RISK_TLDS


# ---------------------------------------------------------------------------
# Guarda SSRF / validação de entrada (PLANO.md 7.1)
def guard_public_host(host: str) -> None:
    if ALLOW_PRIVATE_HOSTS:
        return
    name = (host or "").strip().lower()
    if not name:
        raise ValueError("Host vazio na URL.")
    if name == "localhost" or name.endswith(".localhost") or name.endswith(".local"):
        raise ValueError("Host local bloqueado (ALLOW_PRIVATE_HOSTS=0).")
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        return
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        raise ValueError("IP privado/local bloqueado (ALLOW_PRIVATE_HOSTS=0).")


def validate_target_url(raw_url: str) -> str:
    candidate = raw_url.strip()
    if len(candidate) > 2048:
        raise ValueError("URL longa demais.")
    parsed = urlparse(candidate)
    if not parsed.scheme:
        candidate = f"https://{candidate}"
        parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Use uma URL http ou https válida.")
    guard_public_host(parsed.hostname or "")
    return candidate


# ---------------------------------------------------------------------------
# Parser de página (PLANO.md 7.4)
class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.in_title = False
        self.scripts: list[dict[str, Any]] = []
        self.inline_scripts: list[str] = []
        self.in_script = False
        self.script_buf: list[str] = []
        self.iframes: list[dict[str, str]] = []
        self.refresh: list[str] = []
        self.tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value or "" for name, value in attrs}
        self.tags.append(tag)

        if tag == "title":
            self.in_title = True
            return

        if tag == "script":
            self.in_script = True
            self.script_buf = []
            self.scripts.append({"src": values.get("src", "").strip(), "bytes": 0})
            return

        if tag == "iframe":
            self.iframes.append(
                {
                    "src": values.get("src", "").strip(),
                    "width": values.get("width", "").strip(),
                    "height": values.get("height", "").strip(),
                    "style": values.get("style", "").strip(),
                }
            )
            return

        if tag == "meta":
            equiv = (values.get("http-equiv") or "").strip().lower()
            if equiv == "refresh" and values.get("content"):
                self.refresh.append(values["content"].strip())

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False
        elif tag == "script" and self.in_script:
            self.in_script = False
            content = "".join(self.script_buf)
            self.inline_scripts.append(content)
            if self.scripts:
                self.scripts[-1]["bytes"] = len(content.encode("utf-8", "replace"))

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
        elif self.in_script:
            self.script_buf.append(data)

    @property
    def title(self) -> str:
        return normalize_text(" ".join(self.title_parts))


# ---------------------------------------------------------------------------
# Fingerprints (PLANO.md 7.5)
def normalize_body(body: str) -> str:
    text = COMMENT_RE.sub("", body)
    text = NONCE_ATTR_RE.sub("", text)
    text = JSON_SECRET_RE.sub('"token":"X"', text)
    text = HIDDEN_TOKEN_RE.sub(r'\1X"', text)
    text = JQUERY_CB_RE.sub("", text)
    text = QS_NOISE_RE.sub("", text)
    text = WS_RE.sub(" ", text)
    return text.strip()


def content_fingerprint(body: str) -> str:
    return hashlib.sha256(normalize_body(body).encode("utf-8", "replace")).hexdigest()


def structure_fingerprint(tags: list[str]) -> str:
    return hashlib.sha256(" ".join(tags[:4000]).encode("utf-8", "replace")).hexdigest()


def clean_script_src(src: str) -> str:
    """Remove cache-busters da URL de script antes de comparar entre UAs."""
    return QS_NOISE_RE.sub("", JQUERY_CB_RE.sub("", src))


def shingle_set(body: str) -> set[int]:
    tokens = TOKEN_RE.findall(normalize_body(body).lower())
    total = len(tokens) - SHINGLE_K + 1
    if total <= 0:
        return {hash(" ".join(tokens))} if tokens else set()
    stride = max(1, total // SHINGLE_STRIDE_TARGET)
    return {hash(" ".join(tokens[i : i + SHINGLE_K])) for i in range(0, total, stride)}


def jaccard(first: set[int], second: set[int]) -> float:
    if not first and not second:
        return 1.0
    if not first or not second:
        return 0.0
    return len(first & second) / len(first | second)


# ---------------------------------------------------------------------------
# Fetch por agente (PLANO.md 7.2 / 7.3)
class RedirectTracer(HTTPRedirectHandler):
    def __init__(self, trace: list[dict[str, Any]]) -> None:
        super().__init__()
        self.trace = trace

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        location = headers.get("Location", "")
        self.trace.append(
            {"url": req.full_url, "code": code, "location": location or newurl}
        )
        if len(self.trace) >= MAX_REDIRECTS:
            raise RuntimeError(f"Cadeia passou de {MAX_REDIRECTS} redirecionamentos.")
        try:
            guard_public_host(urlparse(newurl).hostname or "")
        except ValueError as error:
            raise ValueError(f"Redirect não seguido - host do destino bloqueado: {error}") from None
        scheme = urlparse(newurl).scheme.lower()
        if scheme and scheme not in {"http", "https"}:
            return None  # scheme inválido: o 3xx vira resposta final e vira achado
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_agent(profile: dict[str, str], url: str, referer: dict[str, str] | None = None) -> tuple[dict[str, Any], str, PageParser | None]:
    trace: list[dict[str, Any]] = []
    opener = build_opener(RedirectTracer(trace))
    headers = {
        "User-Agent": profile["ua"],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.7",
        "Accept-Encoding": "identity",
    }
    if referer:
        headers["Referer"] = referer["referer"]
    request = Request(url, headers=headers, method="GET")
    started = time.perf_counter()

    agent: dict[str, Any] = {
        "id": f"{profile['id']}@{referer['id']}" if referer else profile["id"],
        "label": f"{profile['label']} ← {referer['label']}" if referer else profile["label"],
        "via": referer["label"] if referer else "",
        "baseId": profile["id"] if referer else "",
        "category": profile.get("category", "browser"),
        "ok": False,
        "error": "",
        "status": 0,
        "finalUrl": "",
        "elapsedMs": 0,
        "bodyBytes": 0,
        "truncated": False,
        "contentType": "",
        "title": "",
        "server": "",
        "redirects": [],
        "hops": 0,
        "contentHash": "",
        "structureHash": "",
        "scripts": [],
        "externalHosts": [],
    }

    def fail(error: BaseException) -> tuple[dict[str, Any], str, None]:
        agent["error"] = str(error) or error.__class__.__name__
        agent["elapsedMs"] = round((time.perf_counter() - started) * 1000)
        agent["redirects"] = trace
        agent["hops"] = len(trace)
        return agent, "", None

    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            status = response.status
            final_url = response.url
            resp_headers = response.headers
            data = response.read(MAX_BYTES + 1)
    except HTTPError as error:
        status = error.code
        if trace:
            final_url = urljoin(trace[-1]["url"], trace[-1]["location"])
        else:
            final_url = getattr(error, "url", "") or url
        resp_headers = error.headers
        try:
            data = error.read(MAX_BYTES + 1)
        except Exception:
            data = b""
    except (URLError, TimeoutError, socket.timeout, RuntimeError, ValueError) as error:
        return fail(error)
    except Exception as error:  # nunca derruba o scan inteiro
        return fail(error)

    elapsed = round((time.perf_counter() - started) * 1000)
    truncated = len(data) > MAX_BYTES
    if truncated:
        data = data[:MAX_BYTES]
    content_type = (resp_headers.get("Content-Type", "") if resp_headers else "") or ""
    body = decode_body(data, content_type)

    page = PageParser()
    try:
        page.feed(body)
        page.close()
    except Exception:
        pass

    final_url = final_url or url
    base_host = host_of(final_url)
    scripts: list[dict[str, Any]] = []
    for item in page.scripts[:120]:
        src = clean_script_src(urljoin(final_url, item["src"])) if item["src"] else ""
        scripts.append({"src": src, "inline": not src, "bytes": item["bytes"]})
    external_hosts = sorted(
        {
            host_of(s["src"])
            for s in scripts
            if s["src"] and is_external(s["src"], base_host)
        }
    )

    agent.update(
        {
            "ok": True,
            "status": status,
            "finalUrl": final_url,
            "elapsedMs": elapsed,
            "bodyBytes": len(data),
            "truncated": truncated,
            "contentType": content_type,
            "title": page.title,
            "server": (resp_headers.get("Server", "") if resp_headers else "") or "",
            "redirects": trace,
            "hops": len(trace),
            "contentHash": content_fingerprint(body),
            "structureHash": structure_fingerprint(page.tags),
            "scripts": scripts,
            "externalHosts": [h for h in external_hosts if h],
        }
    )
    return agent, body, page


# ---------------------------------------------------------------------------
# Assinaturas estáticas (PLANO.md 7.8)
def _dim_is_small(value: str) -> bool:
    match = re.match(r"^\s*(\d+)", value or "")
    return bool(match) and int(match.group(1)) <= 2


def _style_is_hidden(style: str) -> bool:
    flat = (style or "").lower().replace(" ", "")
    return (
        "display:none" in flat
        or "visibility:hidden" in flat
        or "opacity:0" in flat
    )


def scan_signatures(agent: dict[str, Any], body: str, page: PageParser | None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not page:
        return findings

    label = agent["label"]
    final_url = agent["finalUrl"]
    base_host = host_of(final_url)

    def add(key: str, severity: str, title: str, detail: str, evidence: str) -> None:
        findings.append(
            {
                "key": key,
                "severity": severity,
                "title": title,
                "detail": detail,
                "evidence": clip(evidence),
                "agents": [label],
            }
        )

    # iframes ocultos
    for frame in page.iframes:
        src = urljoin(final_url, frame["src"]) if frame["src"] else ""
        if not src:
            continue
        hidden = _style_is_hidden(frame["style"]) or _dim_is_small(frame["width"]) or _dim_is_small(frame["height"])
        if not hidden:
            continue
        if is_external(src, base_host):
            add(
                "iframe-hidden-ext",
                "high",
                "Iframe oculto apontando para domínio externo",
                "iframe carregado escondido (display:none/dimensão ~0) de outro domínio",
                f"src={src} width={frame['width']!r} height={frame['height']!r} style={frame['style']!r}",
            )
        else:
            add(
                "iframe-hidden-int",
                "low",
                "Iframe oculto no próprio domínio",
                "iframe escondido no mesmo domínio; pode ser legítimo (tracking interno, player)",
                f"src={src} style={frame['style']!r}",
            )

    # meta refresh externo
    for content in page.refresh:
        match = META_REFRESH_URL_RE.search(content)
        if not match:
            continue
        target = urljoin(final_url, match.group(1).strip().strip("'\""))
        if is_external(target, base_host):
            add(
                "meta-refresh-ext",
                "high",
                "Meta refresh para domínio externo",
                "a página recarrega para outro domínio via <meta http-equiv=refresh>",
                f"content={content!r} -> {target}",
            )

    # regexes de obfuscação / redirecionamento JS
    for regex, key, severity, title, detail in (
        (EVAL_CODED_RE, "eval-coded", "high", "eval() sobre conteúdo codificado", "eval chamando atob/unescape/decodeURIComponent/fromCharCode é assinatura clássica de payload ofuscado"),
        (DOCWRITE_RE, "docwrite-unescape", "high", "document.write(unescape(...))", "escrita de conteúdo desofuscado em runtime"),
        (FROMCHARCODE_RE, "fromcharcode-blob", "high", "Blob String.fromCharCode", "sequência longa de códigos de caractere - payload montado em runtime"),
        (ATOB_INLINE_RE, "atob-inline", "high", "Payload base64 inline decodificado", "string base64 longa decodificada via atob"),
        (HEX_BLOB_RE, "hex-escape-blob", "medium", "Blob com escapes hexadecimais", "sequência longa de \\xNN - código ofuscado"),
    ):
        match = regex.search(body)
        if match:
            start = max(0, match.start() - 40)
            end = min(len(body), match.end() + 40)
            add(key, severity, title, detail, body[start:end])

    blobs = 0
    for match in B64_BLOB_RE.finditer(body):
        if shannon_entropy(match.group(0)) >= 4.7:
            start = max(0, match.start() - 30)
            end = min(len(body), match.end() + 30)
            add(
                "b64-entropy",
                "medium",
                "Blob longo de alta entropia (possível payload)",
                "string base64-like extensa com entropia ≥ 4.7 bits/char",
                body[start:end],
            )
            blobs += 1
            if blobs >= 3:
                break

    for match in JS_REDIR_RE.finditer(body):
        target_host = match.group(1)
        if is_external(f"http://{target_host}", base_host):
            start = max(0, match.start() - 40)
            end = min(len(body), match.end() + 60)
            add(
                "js-redirect-ext",
                "medium",
                "Redirecionamento JS para domínio externo",
                "location.href/replace/assign para outro domínio no código da página",
                body[start:end],
            )
            break

    # scripts: scheme, extensão, TLD
    for item in agent["scripts"]:
        src = item["src"]
        if not src:
            continue
        scheme = urlparse(src).scheme.lower()
        if scheme in {"data", "javascript"}:
            add(
                "script-data-uri",
                "critical",
                "Script inline em data:/javascript: URI",
                "script embutido em data: URI - técnica de evasão",
                src[:240],
            )
            continue
        if ".php" in urlparse(src).path:
            add(
                "script-php",
                "high",
                "Script carregado de arquivo PHP",
                "<script src> apontando para .php - comum em malware para gerar payload dinâmico",
                src,
            )
        if risk_tld_of(src):
            add(
                "script-risk-tld",
                "medium",
                "Script de domínio com TLD de risco",
                "script servido de domínio em TLD frequentemente usado em campanhas maliciosas",
                src,
            )

    # keywords conhecidas
    lowered = body.lower()
    for keyword in MALWARE_KEYWORDS:
        index = lowered.find(keyword.lower())
        if index >= 0:
            start = max(0, index - 40)
            end = min(len(body), index + len(keyword) + 80)
            add(
                f"keyword-{keyword}",
                "high",
                f"Keyword de malware conhecida: {keyword}",
                "termo associado a famílias conhecidas de malware/mineradoras",
                body[start:end],
            )

    return findings


# ---------------------------------------------------------------------------
# Comparações cross-UA (PLANO.md 7.9)
def script_is_risky(src: str, input_host: str) -> bool:
    return ".php" in urlparse(src).path or risk_tld_of(src) or is_external(src, input_host)


def neutral_reason(agent: dict[str, Any]) -> str:
    """Bot/tool bloqueado por WAF (403/429/503) ou falho -> neutro nas comparações."""
    if agent.get("category", "browser") not in {"bot", "tool"}:
        return ""
    if not agent["ok"]:
        return f"erro: {clip(agent['error'], 80)}"
    if agent["status"] in BLOCKED_STATUSES:
        return f"HTTP {agent['status']}"
    return ""


def compare_agents(
    ok_raw: list[tuple[dict[str, Any], str, PageParser | None]], input_host: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    comparisons: dict[str, Any] = {
        "finalUrls": [],
        "statuses": [],
        "contentVariants": 0,
        "structureVariants": 0,
        "contentSimilarity": {},
        "neutralAgents": [],
        "scriptDiff": [],
    }

    scored = [r for r in ok_raw if not neutral_reason(r[0])]
    comparisons["neutralAgents"] = [
        {"id": r[0]["id"], "label": r[0]["label"], "reason": neutral_reason(r[0])}
        for r in ok_raw
        if neutral_reason(r[0])
    ]
    if len(scored) < 2:
        return findings, comparisons

    def add(key: str, severity: str, title: str, detail: str, evidence: str, agents: list[str]) -> None:
        findings.append(
            {
                "key": key,
                "severity": severity,
                "title": title,
                "detail": detail,
                "evidence": clip(evidence),
                "agents": agents,
            }
        )

    ok_agents = [r[0] for r in scored]
    final_urls = [a["finalUrl"] for a in ok_agents]
    distinct_urls = sorted(set(final_urls))
    distinct_roots = {root_domain(host_of(u)) for u in distinct_urls}
    comparisons["finalUrls"] = distinct_urls
    comparisons["statuses"] = sorted({a["status"] for a in ok_agents})
    comparisons["contentVariants"] = len({a["contentHash"] for a in ok_agents})
    comparisons["structureVariants"] = len({a["structureHash"] for a in ok_agents})

    majority_url = Counter(final_urls).most_common(1)[0][0]
    divergent_url = [a for a in ok_agents if a["finalUrl"] != majority_url]
    if divergent_url:
        cross_domain = len(distinct_roots) > 1
        add(
            "final-url-divergent-domains" if cross_domain else "final-url-divergent-paths",
            "high" if cross_domain else "medium",
            "URL final diverge entre user-agents (" + ("domínios diferentes" if cross_domain else "mesmo domínio, caminhos diferentes") + ")",
            "resposta muda conforme o visitante - assinatura de cloaking",
            " | ".join(f"{a['label']} -> {a['finalUrl']}" for a in divergent_url[:4]),
            [a["label"] for a in divergent_url],
        )

    majority_status = Counter(a["status"] for a in ok_agents).most_common(1)[0][0]
    divergent_status = [a for a in ok_agents if a["status"] != majority_status]
    if divergent_status:
        add(
            "status-divergent",
            "medium",
            "Status HTTP diverge entre user-agents",
            "perfis diferentes recebem códigos HTTP distintos",
            " | ".join(f"{a['label']} -> HTTP {a['status']}" for a in divergent_status[:4]),
            [a["label"] for a in divergent_status],
        )

    # divergência de conteúdo = similaridade de shingles vs baseline
    # (hash exato falsava em WP: nonce/comentário de cache mudam a cada request)
    baseline_entry = next((r for r in scored if r[0]["id"] == BASELINE_UA), scored[0])
    baseline = baseline_entry[0]
    base_shingles = shingle_set(baseline_entry[1])
    similarities: dict[str, float] = {}
    for agent, body, _page in scored:
        if agent["id"] == baseline["id"]:
            similarities[agent["id"]] = 1.0
            continue
        similarities[agent["id"]] = jaccard(base_shingles, shingle_set(body))
    comparisons["contentSimilarity"] = {
        aid: round(sim, 4) for aid, sim in similarities.items()
    }

    low_similarity = [
        (agent, similarities[agent["id"]])
        for agent, _body, _page in scored
        if agent["id"] != baseline["id"] and similarities[agent["id"]] < SIMILARITY_SAME
    ]
    if low_similarity:
        worst = min(sim for _a, sim in low_similarity)
        add(
            "content-divergent",
            "high" if worst < SIMILARITY_LOW else "medium",
            "Conteúdo divergente entre user-agents",
            "similaridade de conteúdo vs baseline abaixo de "
            f"{SIMILARITY_SAME:.2f} - resposta realmente diferente por perfil",
            " | ".join(f"{a['label']}: {sim:.2f}" for a, sim in low_similarity[:4]),
            [a["label"] for a, _sim in low_similarity],
        )

    baseline_srcs = {s["src"] for s in baseline["scripts"] if s["src"]}
    for agent in ok_agents:
        if agent["id"] == baseline["id"]:
            continue
        srcs = {s["src"] for s in agent["scripts"] if s["src"]}
        only = sorted(srcs - baseline_srcs)
        if not only:
            continue
        comparisons["scriptDiff"].append(
            {"id": agent["id"], "label": agent["label"], "onlyScripts": only}
        )
        risky = any(script_is_risky(s, input_host) for s in only)
        add(
            "scripts-unique-to-agent",
            "high" if risky else "medium",
            "Scripts carregados apenas para um perfil de user-agent",
            "código servido seletivamente por UA - padrão de cloaking/injeção direcionada"
            + (" (script de risco)" if risky else ""),
            f"{agent['label']}: {'; '.join(only[:4])}",
            [agent["label"]],
        )

    for agent in ok_agents:
        for hop in agent["redirects"]:
            location = hop.get("location", "")
            scheme = urlparse(location).scheme.lower()
            if scheme and scheme not in {"http", "https"}:
                add(
                    "redirect-bad-scheme",
                    "critical",
                    "Redirect para scheme não-HTTP",
                    "Location com scheme javascript:/data: - tentativa de evasão",
                    location,
                    [agent["label"]],
                )
            elif is_external(location, input_host):
                add(
                    "redirect-external-domain",
                    "high",
                    "Redirecionamento para domínio externo",
                    "a cadeia de redirect sai do domínio original",
                    f"{hop['url']} -{hop['code']}-> {location}",
                    [agent["label"]],
                )

    return findings, comparisons


# ---------------------------------------------------------------------------
# Comparações por Referer (origem do clique)
def compare_referers(
    referer_raw: list[tuple[dict[str, Any], str, PageParser | None]],
    matrix_raw: list[tuple[dict[str, Any], str, PageParser | None]],
    input_host: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    base_by_id = {r[0]["id"]: r for r in matrix_raw if r[0]["ok"]}
    base_shingles: dict[str, set[int]] = {}

    def add(key: str, severity: str, title: str, detail: str, evidence: str, agents: list[str]) -> None:
        findings.append(
            {
                "key": key,
                "severity": severity,
                "title": title,
                "detail": detail,
                "evidence": clip(evidence),
                "agents": agents,
            }
        )

    for agent, body, _page in referer_raw:
        if not agent["ok"]:
            continue
        base_entry = base_by_id.get(agent["baseId"])
        if not base_entry:
            continue
        base = base_entry[0]
        label = agent["label"]

        if agent["finalUrl"] != base["finalUrl"]:
            cross_domain = root_domain(host_of(agent["finalUrl"])) != root_domain(host_of(base["finalUrl"]))
            add(
                "referer-final-url",
                "high" if cross_domain else "medium",
                "URL final muda conforme a origem do clique (Referer)",
                "o site redireciona diferente para quem vem dessa origem - cloaking por referer",
                f"{label}: {agent['finalUrl']} (sem referer: {base['finalUrl']})",
                [label],
            )

        if agent["status"] != base["status"]:
            add(
                "referer-status",
                "medium",
                "Status HTTP muda conforme a origem do clique (Referer)",
                "mesmo user-agent recebe resposta diferente quando vem dessa origem",
                f"{label}: HTTP {agent['status']} (sem referer: {base['status']})",
                [label],
            )

        if base["id"] not in base_shingles:
            base_shingles[base["id"]] = shingle_set(base_entry[1])
        sim = jaccard(base_shingles[base["id"]], shingle_set(body))
        if sim < SIMILARITY_SAME:
            add(
                "referer-content",
                "high" if sim < SIMILARITY_LOW else "medium",
                "Conteúdo divergente para quem vem dessa origem (Referer)",
                "mesmo user-agent recebe conteúdo diferente com esse Referer",
                f"{label}: similaridade {sim:.2f} vs sem referer",
                [label],
            )

        base_srcs = {s["src"] for s in base["scripts"] if s["src"]}
        only = sorted({s["src"] for s in agent["scripts"] if s["src"]} - base_srcs)
        if only:
            risky = any(script_is_risky(s, input_host) for s in only)
            add(
                "referer-scripts",
                "high" if risky else "medium",
                "Scripts carregados apenas para quem vem dessa origem (Referer)",
                "código servido seletivamente por origem - cloaking/injeção direcionada"
                + (" (script de risco)" if risky else ""),
                f"{label}: {'; '.join(only[:4])}",
                [label],
            )

        for hop in agent["redirects"]:
            location = hop.get("location", "")
            scheme = urlparse(location).scheme.lower()
            if scheme and scheme not in {"http", "https"}:
                add(
                    "redirect-bad-scheme",
                    "critical",
                    "Redirect para scheme não-HTTP",
                    "Location com scheme javascript:/data: - tentativa de evasão",
                    location,
                    [label],
                )
            elif is_external(location, input_host):
                add(
                    "redirect-external-domain",
                    "high",
                    "Redirecionamento para domínio externo",
                    "a cadeia de redirect sai do domínio original",
                    f"{hop['url']} -{hop['code']}-> {location}",
                    [label],
                )

    return findings


# ---------------------------------------------------------------------------
# Orquestração do scan (PLANO.md 7.10 / 7.11)
def merge_findings(lists: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for findings in lists:
        for finding in findings:
            current = merged.get(finding["key"])
            if current:
                for label in finding["agents"]:
                    if label not in current["agents"]:
                        current["agents"].append(label)
            else:
                merged[finding["key"]] = finding
    return sorted(
        merged.values(),
        key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["key"]),
    )


def build_verdict(findings: list[dict[str, Any]]) -> str:
    severities = {f["severity"] for f in findings}
    if "critical" in severities:
        return "ALERTA"
    if "high" in severities:
        return "SUSPEITO"
    if "medium" in severities:
        return "ATENÇÃO"
    return "OK"


def scan_url(raw_url: str) -> dict[str, Any]:
    url = validate_target_url(raw_url)
    started = time.perf_counter()
    input_host = host_of(url)

    matrix_profiles = list(USER_AGENTS)
    referer_profiles = [p for p in USER_AGENTS if p["id"] in REFERER_UA_IDS]
    jobs: list[tuple[dict[str, str], dict[str, str] | None]] = [(p, None) for p in matrix_profiles]
    jobs += [(p, ref) for ref in REFERERS for p in referer_profiles]

    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = [pool.submit(fetch_agent, p, url, ref) for p, ref in jobs]
        raw_all = [f.result() for f in futures]

    matrix_raw = raw_all[: len(matrix_profiles)]
    referer_raw = raw_all[len(matrix_profiles):]

    agents = [r[0] for r in matrix_raw]
    ok_agents = [a for a in agents if a["ok"]]
    if not ok_agents:
        errors = "; ".join(f"{a['label']}: {a['error']}" for a in agents[:3])
        raise URLError(f"Nenhum perfil conseguiu buscar a URL ({errors})")

    ok_raw = [r for r in matrix_raw if r[0]["ok"]]
    comparison_findings, comparisons = compare_agents(ok_raw, input_host)
    referer_findings = compare_referers(referer_raw, matrix_raw, input_host)
    signature_findings = [
        scan_signatures(agent, body, page)
        for agent, body, page in matrix_raw + referer_raw
        if agent["ok"]
    ]

    findings = merge_findings([comparison_findings, referer_findings, *signature_findings])
    summary = Counter(f["severity"] for f in findings)

    return {
        "inputUrl": raw_url,
        "startedAt": datetime.now().astimezone().isoformat(timespec="seconds"),
        "elapsedMs": round((time.perf_counter() - started) * 1000),
        "verdict": build_verdict(findings),
        "summary": {key: summary.get(key, 0) for key in SEVERITY_ORDER},
        "agents": agents,
        "refererAgents": [r[0] for r in referer_raw],
        "comparisons": comparisons,
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Servidor HTTP (espelho LinkSee)
class Handler(BaseHTTPRequestHandler):
    server_version = f"{APP_NAME}/1.0"

    def do_HEAD(self) -> None:
        parsed = urlparse(self.path)
        file_path = self.resolve_static_path(parsed.path)
        if file_path is None:
            return

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/api/scan":
            if not self.has_access():
                self.write_json(HTTPStatus.UNAUTHORIZED, {"error": "Sessão expirada. Faça login novamente."})
                return
            self.handle_scan(parsed.query)
            return

        if parsed.path == "/logout":
            self.redirect_to_login(clear_cookie=True)
            return

        file_path = self.resolve_static_path(parsed.path)
        if file_path is None:
            return

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(file_path.read_bytes())

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/login":
            self.send_error(HTTPStatus.NOT_FOUND, "Rota não encontrada")
            return

        if not PASSWORD_PROTECTED:
            self.write_json(HTTPStatus.OK, {"ok": True})
            return

        try:
            length = min(int(self.headers.get("Content-Length", "0")), 2048)
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self.write_json(HTTPStatus.BAD_REQUEST, {"error": "JSON inválido."})
            return

        password = str(payload.get("password", ""))
        if hmac.compare_digest(password, ACCESS_PASSWORD):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE_NAME}={SESSION_TOKEN}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800",
            )
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
            return

        self.write_json(HTTPStatus.UNAUTHORIZED, {"error": "Senha incorreta."})

    def resolve_static_path(self, request_path: str) -> Path | None:
        if not self.has_access():
            path = "login.html"
        else:
            path = "index.html" if request_path in {"/", "", "/login.html"} else request_path.lstrip("/")

        file_path = (ROOT / path).resolve()
        if not str(file_path).startswith(str(ROOT)) or not file_path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "Arquivo não encontrado")
            return None
        return file_path

    def has_access(self) -> bool:
        return not PASSWORD_PROTECTED or self.is_authenticated()

    def is_authenticated(self) -> bool:
        cookie = self.headers.get("Cookie", "")
        for chunk in cookie.split(";"):
            name, _, value = chunk.strip().partition("=")
            if name == SESSION_COOKIE_NAME:
                return hmac.compare_digest(value, SESSION_TOKEN)
        return False

    def redirect_to_login(self, clear_cookie: bool = False) -> None:
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", "/")
        self.send_header("Cache-Control", "no-store")
        if clear_cookie:
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
            )
        self.end_headers()

    def handle_scan(self, query: str) -> None:
        params = parse_qs(query)
        url = params.get("url", [""])[0]

        try:
            if not url.strip():
                raise ValueError("Informe uma URL.")
            payload = scan_url(url)
            self.write_json(HTTPStatus.OK, payload)
        except URLError as error:
            self.write_json(
                HTTPStatus.BAD_GATEWAY,
                {"error": "Nenhum perfil conseguiu buscar essa URL.", "detail": str(error)},
            )
        except ValueError as error:
            self.write_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
        except Exception as error:  # noqa: BLE001
            self.write_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Erro inesperado no scan.", "detail": str(error)},
            )

    def write_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        sys.stderr.write("%s - %s\n" % (self.log_date_time_string(), format % args))


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", SERVER_PORT), Handler)
    print(f"{APP_NAME}: http://127.0.0.1:{SERVER_PORT}")
    print(f"ALLOW_PRIVATE_HOSTS={ALLOW_PRIVATE_HOSTS}")
    server.serve_forever()


if __name__ == "__main__":
    main()
