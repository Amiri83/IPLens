import logging

from iplens.logging_setup import LOG_FILE, configure_logging, read_log, redact

FAKE_KEY_ID = "AKIAEXAMPLEEXAMPLE00"
FAKE_SECRET = "example/secret/value/for/tests/only/0000"


def test_redact():
    assert FAKE_KEY_ID not in redact(f"key {FAKE_KEY_ID} used")
    assert FAKE_SECRET not in redact(f"value {FAKE_SECRET}")
    assert redact("secret_access_key=abc123") == "secret_access_key=[REDACTED]"
    assert redact("'password': 'hunter2'") == "'password': '[REDACTED]'"
    assert redact("subnet-0000000a has 10.0.1.4") == "subnet-0000000a has 10.0.1.4"


def test_file_logging_redacts_and_reads_back(tmp_path):
    path = configure_logging(tmp_path / "logs")
    log = logging.getLogger("iplens.test")
    log.info("hello %s", "world")
    log.warning("credentials %s / %s", FAKE_KEY_ID, FAKE_SECRET)
    try:
        raise RuntimeError(f"boom token={FAKE_SECRET}")
    except RuntimeError:
        log.exception("it failed")
    log.debug("not written at INFO")

    text = path.read_text()
    assert path.name == LOG_FILE
    assert FAKE_SECRET not in text and FAKE_KEY_ID not in text
    assert "not written" not in text

    entries = read_log(tmp_path / "logs")
    assert [e["level"] for e in entries] == ["ERROR", "WARNING", "INFO"]
    assert "Traceback" in entries[0]["msg"] and "RuntimeError" in entries[0]["msg"]
    assert [e["msg"] for e in read_log(tmp_path / "logs", min_level="WARNING")][1].startswith(
        "credentials")
    assert len(read_log(tmp_path / "logs", min_level="ERROR")) == 1
    assert [e["msg"] for e in read_log(tmp_path / "logs", q="WORLD")] == ["hello world"]
    assert len(read_log(tmp_path / "logs", limit=1)) == 1


def test_reconfigure_switches_directory(tmp_path):
    configure_logging(tmp_path / "a")
    logging.getLogger("iplens").info("first")
    configure_logging(tmp_path / "b")
    logging.getLogger("iplens").info("second")
    assert [e["msg"] for e in read_log(tmp_path / "a")] == ["first"]
    assert [e["msg"] for e in read_log(tmp_path / "b")] == ["second"]
    handlers = [h for h in logging.getLogger("iplens").handlers if h.get_name() == "iplens-file"]
    assert len(handlers) == 1


def test_read_log_missing_file(tmp_path):
    assert read_log(tmp_path / "nowhere") == []
