import os

import pytest

from halcyon import audit
from halcyon.pg_store import PostgresStore, init_schema

DSN = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")


@pytest.fixture
def store():
    init_schema(DSN)
    s = PostgresStore(DSN)
    # isolate this test's session
    yield s


def test_pg_append_query_reset_and_progress(store):
    sid = "pg-test-1"
    store.append_event(sid, "m1", audit.INTERNAL_TOKEN_DISCLOSED, sid, {})
    assert audit.has_event(store, sid, "m1", audit.INTERNAL_TOKEN_DISCLOSED)
    store.write_reset_marker(sid, "m1")
    assert not audit.has_event(store, sid, "m1", audit.INTERNAL_TOKEN_DISCLOSED)
    store.upsert_progress(sid, "m1", True, False)
    assert store.get_progress(sid, "m1") == (True, False)
    assert store.ping() is True
