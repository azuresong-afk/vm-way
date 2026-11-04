import pytest
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError

from app import audit


def test_audit_is_append_only(db):
    audit.record(db, None, "test.action", object_type="x", object_id=1)
    db.commit()
    with pytest.raises(DatabaseError):
        db.execute(text("UPDATE audit_log SET action='hacked'"))
    db.rollback()
    with pytest.raises(DatabaseError):
        db.execute(text("DELETE FROM audit_log"))
    db.rollback()
    assert db.execute(text("SELECT count(*) FROM audit_log")).scalar() == 1


def test_audit_duplicated_to_outbox(db):
    audit.record(db, None, "test.action", project_id="p1")
    db.commit()
    row = db.execute(text("SELECT type, project_id FROM outbox")).one()
    assert tuple(row) == ("audit.recorded", "p1")
