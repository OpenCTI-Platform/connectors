"""Tests for the minimal .env reader."""

from crowdstrike_indicators.dotenv import parse_dotenv, read_dotenv


def test_key_value():
    assert parse_dotenv("KEY=value") == {"KEY": "value"}


def test_key_and_value_are_trimmed():
    assert parse_dotenv("  KEY  =  value  ") == {"KEY": "value"}


def test_export_prefix():
    assert parse_dotenv("export KEY=value") == {"KEY": "value"}


def test_double_quotes_keep_hash_and_equals():
    assert parse_dotenv('SECRET="a=b#c"') == {"SECRET": "a=b#c"}


def test_single_quotes_keep_content_verbatim():
    assert parse_dotenv("SECRET='a #b'") == {"SECRET": "a #b"}


def test_spec_example():
    text = '# comment\n\nexport CROWDSTRIKE_CLIENT_SECRET="a=b#c"\n'
    assert parse_dotenv(text) == {"CROWDSTRIKE_CLIENT_SECRET": "a=b#c"}


def test_trailing_comment_removed_from_unquoted_value():
    assert parse_dotenv("KEY=value # comment") == {"KEY": "value"}


def test_hash_without_space_is_part_of_an_unquoted_value():
    assert parse_dotenv("KEY=val#ue") == {"KEY": "val#ue"}


def test_blank_and_comment_lines_are_skipped():
    assert parse_dotenv("\n   \n# KEY=ignored\n  # indented\nA=1\n") == {"A": "1"}


def test_equals_inside_a_value():
    assert parse_dotenv("URL=https://x.example/?a=1&b=2") == {
        "URL": "https://x.example/?a=1&b=2"
    }


def test_empty_value():
    assert parse_dotenv("KEY=") == {"KEY": ""}


def test_no_variable_expansion():
    assert parse_dotenv("A=1\nB=${A}\nC=$A") == {"A": "1", "B": "${A}", "C": "$A"}


def test_lines_without_equals_or_key_are_ignored():
    assert parse_dotenv("JUSTTEXT\n=value\nA=1") == {"A": "1"}


def test_unmatched_quote_is_kept():
    assert parse_dotenv('KEY="abc') == {"KEY": '"abc'}


def test_later_definition_wins():
    assert parse_dotenv("A=1\nA=2") == {"A": "2"}


def test_windows_line_endings():
    assert parse_dotenv("A=1\r\nB=2\r\n") == {"A": "1", "B": "2"}


def test_read_file(tmp_path):
    path = tmp_path / ".env"
    path.write_text("A=1\n", encoding="utf-8")
    assert read_dotenv(path) == {"A": "1"}


def test_missing_file_gives_an_empty_dict(tmp_path):
    assert read_dotenv(tmp_path / "missing.env") == {}
