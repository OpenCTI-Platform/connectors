import hashlib
import json
from unittest.mock import MagicMock

import pytest
import requests
from privara_unmask_client import (
    DEFAULT_MAX_FILE_MB,
    UnmaskClient,
    UnmaskError,
    UnmaskTimeout,
    defang,
    idempotency_key,
    liveness_text,
    outcome_label,
)

API_KEY = "pvu_test1234_s3cr3tvalue-never-log-me"


def response(status, body=None, headers=None):
    resp = requests.Response()
    resp.status_code = status
    resp._content = b"" if body is None else json.dumps(body).encode()
    resp.headers.update(headers or {})
    return resp


def make_client(*responses, **kwargs):
    session = MagicMock()
    session.request.side_effect = list(responses)
    sleeps = []
    clock = iter(range(0, 100000, 10))
    client = UnmaskClient(
        API_KEY,
        integration="opencti",
        session=session,
        sleep=sleeps.append,
        clock=lambda: next(clock),
        **kwargs,
    )
    return client, session, sleeps


def test_headers_and_tls():
    client, session, _ = make_client(response(200, {"balance_cents": 1}))
    client.get_balance()
    kwargs = session.request.call_args.kwargs
    assert kwargs["headers"]["Authorization"] == f"Bearer {API_KEY}"
    assert kwargs["headers"]["User-Agent"] == "privara-unmask-opencti/1.0"
    assert kwargs["timeout"] == 30.0
    assert kwargs["allow_redirects"] is False
    assert session.verify is True


def test_retries_429_with_retry_after():
    client, session, sleeps = make_client(
        response(
            429,
            {"error": {"code": "rate_limited", "message": "slow down"}},
            {"Retry-After": "7"},
        ),
        response(200, {"job_id": "j_a"}),
    )
    assert client.get_job("j_a") == {"job_id": "j_a"}
    assert sleeps == [7.0]


def test_retries_5xx_then_gives_up():
    client, session, sleeps = make_client(*[response(503)] * 4)
    with pytest.raises(UnmaskError) as err:
        client.get_job("j_a")
    assert err.value.status == 503
    assert session.request.call_count == 4  # 1 + 3 retries


@pytest.mark.parametrize(
    "status,code",
    [
        (402, "insufficient_balance"),
        (403, "fair_use_reached"),
        (403, "missing_scope"),
        (401, "invalid_key"),
        (400, "no_files"),
    ],
)
def test_no_retry_on_client_errors(status, code):
    client, session, sleeps = make_client(
        response(status, {"error": {"code": code, "message": "m"}})
    )
    with pytest.raises(UnmaskError) as err:
        client.submit_sample("a.apk", b"PK")
    assert (err.value.status, err.value.code) == (status, code)
    assert not err.value.transient
    assert session.request.call_count == 1 and sleeps == []


def test_retry_after_too_long_is_not_waited():
    client, session, sleeps = make_client(
        response(429, headers={"Retry-After": "3600"})
    )
    with pytest.raises(UnmaskError):
        client.get_job("j_a")
    assert sleeps == []


def test_upload_sends_a_valid_idempotency_key():
    client, session, _ = make_client(response(201, {"jobs": []}))
    client.submit_sample("a.apk", b"PK\x03\x04", label="x" * 200, notify_email=False)
    kwargs = session.request.call_args.kwargs
    assert (
        kwargs["headers"]["Idempotency-Key"]
        == hashlib.sha256(b"PK\x03\x04").hexdigest()
    )
    assert kwargs["files"][0][0] == "files"
    assert kwargs["data"] == {"label": "x" * 100, "notify_email": "false"}


def test_transport_errors_hide_details():
    session = MagicMock()
    session.request.side_effect = requests.ConnectionError(
        f"boom Authorization: Bearer {API_KEY}"
    )
    client = UnmaskClient(API_KEY, session=session)
    with pytest.raises(UnmaskError) as err:
        client.get_balance()
    assert API_KEY not in str(err.value)
    assert API_KEY not in repr(client)


def test_https_required():
    with pytest.raises(ValueError):
        UnmaskClient(API_KEY, base_url="http://app.tajapps.com/api/unmask/v1")
    UnmaskClient(API_KEY, base_url="http://127.0.0.1:9/api/unmask/v1")  # tests only


def test_wait_for_job_follows_retry_after_with_a_floor():
    client, session, sleeps = make_client(
        response(200, {"job_id": "j", "status": "queued"}, {"Retry-After": "30"}),
        response(200, {"job_id": "j", "status": "running"}, {"Retry-After": "5"}),
        response(200, {"job_id": "j", "status": "running"}),  # no hint: backoff
        response(503),  # transient: counted, polling goes on
        response(200, {"job_id": "j", "status": "done", "outcome": "none"}),
    )
    client.max_retries = 0
    job = client.wait_for_job("j", max_wait=3600, initial_interval=20)
    assert job["outcome"] == "none"
    # 30 (hint), 15 (hint 5 raised to the 15 s floor), 45 (backoff 20*1.5^2), 67.5
    assert sleeps == [30.0, 15.0, 45.0, 67.5]


def test_wait_for_job_timeout():
    client, session, sleeps = make_client(
        *[response(200, {"job_id": "j", "status": "running"})] * 50
    )
    with pytest.raises(UnmaskTimeout) as err:
        client.wait_for_job("j", max_wait=60, initial_interval=10)
    assert err.value.job["status"] == "running"


def test_wait_for_job_not_found_is_not_retried():
    client, session, sleeps = make_client(
        response(404, {"error": {"code": "not_found", "message": "No such job."}})
    )
    with pytest.raises(UnmaskError) as err:
        client.wait_for_job("j_other", max_wait=600)
    assert err.value.code == "not_found" and sleeps == []


def test_lookup_reuses_only_a_recent_charged_result():
    now = 1_800_000_000
    client, session, _ = make_client(
        response(
            200,
            {
                "jobs": [
                    {"job_id": "j_3-_x", "status": "failed", "outcome": None},
                    {
                        "job_id": "j_2-_x",
                        "status": "done",
                        "outcome": "none",
                        "finished_at": now - 60,
                    },
                    {
                        "job_id": "j_1-_x",
                        "status": "done",
                        "outcome": "dead",
                        "finished_at": now - 3600,
                    },
                ],
                "next": None,
            },
        ),
        response(
            200, {"job_id": "j_1-_x", "status": "done", "outcome": "dead", "c2": []}
        ),
    )
    job, earlier = client.lookup("AB" * 32, now=now)
    assert job["job_id"] == "j_1-_x" and earlier is None
    assert session.request.call_args_list[0].kwargs["params"]["sha256"] == "ab" * 32
    # the id is used as it is in the URL (opaque, "_" and "-" kept)
    assert session.request.call_args_list[1].args[1].endswith("/jobs/j_1-_x")


def test_lookup_runs_again_after_none_void_or_an_old_result():
    now = 1_800_000_000
    for jobs in (
        [{"job_id": "j_n-_1", "status": "done", "outcome": "none", "finished_at": now}],
        [{"job_id": "j_n-_1", "status": "done", "outcome": "void", "finished_at": now}],
        [
            {
                "job_id": "j_n-_1",
                "status": "done",
                "outcome": "live",
                "finished_at": now - 31 * 86400,
            }
        ],
        [{"job_id": "j_n-_1", "status": "canceled", "outcome": None}],
    ):
        client, _, _ = make_client(response(200, {"jobs": jobs, "next": None}))
        job, earlier = client.lookup("ab" * 32, now=now)
        assert job is None and earlier["job_id"] == "j_n-_1"


def test_idempotency_key_format():
    sha = "AB" * 32
    assert idempotency_key("opencti", sha) == "opencti-" + "ab" * 32
    again = idempotency_key("opencti", sha, "j_p_vArc3oFeSz-aMwZyOQNOamS" + "x" * 40)
    assert again.startswith("opencti-" + "ab" * 32 + "-") and len(again) <= 128
    assert again == idempotency_key(
        "opencti", sha, "j_p_vArc3oFeSz-aMwZyOQNOamS" + "x" * 40
    )
    assert again != idempotency_key("opencti", sha, "j_other")
    import re

    assert re.match(r"^[A-Za-z0-9_.:-]{8,128}$", again)


def test_upload_in_progress_is_asked_again():
    client, session, sleeps = make_client(
        response(
            409,
            {"error": {"code": "idempotency_in_progress", "message": "later"}},
            {"Retry-After": "10"},
        ),
        response(
            201, {"batch_id": "b_1", "jobs": [{"job_id": "j_1", "status": "queued"}]}
        ),
    )
    answer = client.submit_sample("a.apk", b"PK\x03\x04", idempotency_key="k" * 10)
    assert answer["jobs"][0]["job_id"] == "j_1" and sleeps == [10.0]
    keys = {
        c.kwargs["headers"]["Idempotency-Key"] for c in session.request.call_args_list
    }
    assert keys == {"k" * 10}


def test_idempotency_key_reused_is_not_retried():
    client, session, sleeps = make_client(
        response(
            409, {"error": {"code": "idempotency_key_reused", "message": "other files"}}
        )
    )
    with pytest.raises(UnmaskError) as err:
        client.submit_sample("a.apk", b"PK", idempotency_key="k" * 10)
    assert err.value.code == "idempotency_key_reused" and sleeps == []


def test_wait_never_polls_faster_than_15_s_near_the_end():
    running = response(
        200, {"job_id": "j_1", "status": "running"}, {"Retry-After": "30"}
    )
    client, session, sleeps = make_client(*([running] * 20))
    with pytest.raises(UnmaskTimeout):
        client.wait_for_job("j_1", max_wait=50)
    assert sleeps and min(sleeps) >= 15


def test_liveness_text():
    assert liveness_text({"live": True}) == "answered"
    assert liveness_text({"live": False}) == "did not answer"
    entry = {
        "live": False,
        "liveness": {
            "state": "unreachable",
            "reason": "ai_not_c2",
            "explain": "A parked page answered.",
            "ai": {},
        },
    }
    assert liveness_text(entry) == "did not answer: A parked page answered."
    assert liveness_text(
        {"liveness": {"state": "unknown", "reason": "tcp_timeout"}}
    ) == ("not confirmed (tcp_timeout)")
    assert liveness_text({"liveness": {"state": "new_state"}}) == "new_state"


def test_find_reusable_job_returns_a_running_one_and_skips_failed():
    client, _, _ = make_client(
        response(200, {"jobs": [{"job_id": "j2", "status": "queued"}]})
    )
    assert client.find_reusable_job("ab" * 32)["job_id"] == "j2"
    client, _, _ = make_client(
        response(200, {"jobs": [{"job_id": "j3", "status": "canceled"}]})
    )
    assert client.find_reusable_job("ab" * 32) is None


def test_max_file_bytes_from_balance_limits():
    client, session, _ = make_client(
        response(200, {"limits": {"max_file_mb": 50, "max_files_per_batch": 10}})
    )
    assert client.max_file_bytes() == 50 * 1024 * 1024
    assert client.max_file_bytes() == 50 * 1024 * 1024  # cached
    assert session.request.call_count == 1


def test_max_file_bytes_falls_back_on_outage_but_not_on_bad_key():
    client, _, _ = make_client(*[response(503)] * 4)
    assert client.max_file_bytes() == DEFAULT_MAX_FILE_MB * 1024 * 1024
    client, _, _ = make_client(
        response(401, {"error": {"code": "invalid_key", "message": "revoked"}})
    )
    with pytest.raises(UnmaskError):
        client.max_file_bytes()


def test_outcome_label():
    assert outcome_label({"status": "done", "outcome": "live"}).startswith("C2 found")
    assert "not charged" in outcome_label({"status": "failed", "outcome": None})
    assert "canceled" in outcome_label({"status": "canceled", "outcome": None})


def test_defang_fallback():
    assert defang("http://1.2.3.4/x") == "hxxp://1.2.3[.]4/x"
    assert defang("evil.example") == "evil[.]example"
