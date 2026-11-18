import pytest

from security.open_redirect import (
    normalize_redirect,
    is_safe_redirect,
    check_crlf,
    resolve_redirect,
    parse_url
)


def test_relative():
    assert is_safe_redirect('/home', {'app.example'}) is True

def test_scheme_relative():
    assert is_safe_redirect('//evil.com', {'app.example'}) is False

def test_userinfo():
    assert is_safe_redirect('https://app.example@evil.com', {'app.example'}) is False

def test_encoded():
    assert is_safe_redirect('%2f%2fevil.com', {'app.example'}) is False

def test_crlf():
    assert check_crlf('a\r\nLocation: x') is False

def test_absolute_ok():
    assert is_safe_redirect('https://app.example/x', {'app.example'}) is True

def test_suffix():
    assert is_safe_redirect('https://app.example.evil.com', {'app.example'}) is False

def test_dotdot():
    assert is_safe_redirect('/a/../admin', {'app.example'}) is False

def test_javascript():
    assert is_safe_redirect('javascript:alert(1)', {'app.example'}) is False

def test_https():
    assert normalize_redirect('https://app.example/x') == 'https://app.example/x'

def test_resolve():
    assert resolve_redirect('https://app.example', '/x') == 'https://app.example/x'

def test_empty():
    assert is_safe_redirect('', {'app.example'}) is False

def test_double():
    assert is_safe_redirect('%252f%252fevil.com', {'app.example'}) is False

def test_parse():
    assert parse_url('https://app.example/x')['host'] == 'app.example'

def test_intent():
    assert is_safe_redirect('intent://evil', {'app.example'}) is False
