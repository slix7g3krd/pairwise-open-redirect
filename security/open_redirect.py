"""Safe redirect handling for post-login return_url.

Defends against open-redirect tricks:
- scheme-relative URLs (//evil.com)
- userinfo camouflage (https://app.example@evil.com)
- percent / double-percent encoding (%2f%2f, %252f%252f)
- path traversal (..)
- CRLF header injection
- prefix/suffix host whitelist bypass (app.example.evil.com)
- dangerous schemes (javascript:, intent:, data:, ...)
- multi-hop chains: every hop is re-validated
"""

from posixpath import normpath
from urllib.parse import unquote, urljoin, urlsplit

ALLOWED_SCHEMES = frozenset({'http', 'https'})

# Fixed fallback when validation fails -- never the Referer header.
FALLBACK_REDIRECT = '/'


def _fully_unquote(value, max_rounds=8):
    """Percent-decode until stable so double/triple encoding can't hide anything."""
    prev = value
    for _ in range(max_rounds):
        decoded = unquote(prev)
        if decoded == prev:
            break
        prev = decoded
    return prev


def check_crlf(url):
    """True if the (decoded) URL is free of CR/LF header-injection bytes."""
    if not isinstance(url, str):
        return False
    decoded = _fully_unquote(url)
    return '\r' not in decoded and '\n' not in decoded


def parse_url(url):
    """Parse an absolute URL into components. Raises ValueError on anything
    malformed, relative, userinfo-bearing, or non-http(s)."""
    if not isinstance(url, str) or not url:
        raise ValueError('empty or non-string URL')
    decoded = _fully_unquote(url)
    parts = urlsplit(decoded)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(f'scheme not allowed: {scheme!r}')
    if parts.username is not None or parts.password is not None:
        raise ValueError('userinfo not allowed')
    host = parts.hostname
    if not host:
        raise ValueError('missing host')
    return {
        'scheme': scheme,
        'host': host.lower(),
        'port': parts.port,
        'path': parts.path or '/',
        'query': parts.query,
    }


def _normalize_path(path):
    """Normalize a URL path; returns None if it tries to escape via '..'."""
    segments = path.split('/')
    if '..' in segments:
        return None
    normalized = normpath(path)
    if not normalized.startswith('/'):
        normalized = '/' + normalized
    if path.endswith('/') and not normalized.endswith('/'):
        normalized += '/'
    return normalized


def normalize_redirect(url):
    """Fully decode and normalize a redirect target. Returns the canonical
    form, or None if it fails CRLF / traversal checks."""
    if not isinstance(url, str) or not url:
        return None
    if not check_crlf(url):
        return None
    decoded = _fully_unquote(url)
    parts = urlsplit(decoded)
    if parts.path:
        normalized_path = _normalize_path(parts.path)
        if normalized_path is None:
            return None
    else:
        normalized_path = ''
    rebuilt = ''
    if parts.scheme:
        rebuilt += parts.scheme.lower() + ':'
    if parts.netloc:
        rebuilt += '//' + parts.netloc
    rebuilt += normalized_path
    if parts.query:
        rebuilt += '?' + parts.query
    if parts.fragment:
        rebuilt += '#' + parts.fragment
    return rebuilt


def is_safe_redirect(url, allowed_hosts):
    """True only for same-site relative paths or absolute http(s) URLs whose
    host exactly matches the whitelist. Any failure falls back to
    FALLBACK_REDIRECT at the call site -- never to Referer."""
    if not isinstance(url, str) or not url:
        return False
    if not check_crlf(url):
        return False
    decoded = _fully_unquote(url)
    parts = urlsplit(decoded)

    if not parts.scheme and not parts.netloc:
        # Relative reference: must be a root-anchored path, no traversal.
        if not decoded.startswith('/') or decoded.startswith('//'):
            return False
        return _normalize_path(parts.path) is not None

    try:
        parsed = parse_url(decoded)
    except ValueError:
        return False
    # Exact host match -- no prefix/suffix games.
    return parsed['host'] in {h.lower() for h in allowed_hosts}


def resolve_redirect(base, target, allowed_hosts=None, max_hops=8):
    """Resolve target against base (RFC 3986). When allowed_hosts is given,
    every hop is re-validated; any unsafe hop returns FALLBACK_REDIRECT."""
    if not isinstance(base, str) or not isinstance(target, str):
        return FALLBACK_REDIRECT
    current = urljoin(base, target)
    hops = 0
    while hops < max_hops:
        if allowed_hosts is None:
            return current
        if is_safe_redirect(current, allowed_hosts):
            return current
        return FALLBACK_REDIRECT
    return FALLBACK_REDIRECT
