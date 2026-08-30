
from generate_cves_2025 import clean_text, encode_single_line_text, is_valid_name


def test_clean_text_strips_whitespace():
    assert clean_text("  hello  ") == "hello"


def test_clean_text_non_string_returns_empty_string():
    assert clean_text(None) == ""
    assert clean_text(123) == ""


def test_is_valid_name_rejects_known_placeholders():
    assert is_valid_name("n/a") is False
    assert is_valid_name("Unknown") is False
    assert is_valid_name("   ") is False


def test_is_valid_name_accepts_real_value():
    assert is_valid_name("Acme Corp") is True


def test_encode_single_line_text_escapes_backslash_and_newline():
    assert encode_single_line_text("a\\b\nc") == "a\\\\b\\nc"
