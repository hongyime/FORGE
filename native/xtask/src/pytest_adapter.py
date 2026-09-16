"""Migration-only pytest event adapter. Never a deployed application fallback."""
import json
import os
from pathlib import Path

import pytest

_stream = None


def emit(kind, **fields):
    global _stream
    if _stream is None:
        _stream = open(os.environ["FORGE_BASELINE_EVENTS"], "x", encoding="utf-8")
    _stream.write(json.dumps(dict(kind=kind, **fields), ensure_ascii=True) + "\n")
    _stream.flush()


def case(item):
    return dict(node_id=item.nodeid, markers=sorted({m.name for m in item.iter_markers()}))


def pytest_sessionstart(session):
    emit("start", version=1)


def pytest_itemcollected(item):
    emit("case", **case(item))


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_collection_modifyitems(session, config, items):
    original = list(items)
    yield
    for item in original:
        emit("case", **case(item))


def pytest_deselected(items):
    for item in items:
        emit("deselected", node_id=item.nodeid)


def pytest_collectreport(report):
    if report.passed and report.nodeid.endswith(".py"):
        emit("collection_file", node_id=report.nodeid)
    if report.failed or report.skipped:
        emit("collection_problem", node_id=report.nodeid, outcome=report.outcome)


def pytest_collection_finish(session):
    emit("collection_finish", selected=len(session.items))


def pytest_runtest_logstart(nodeid, location):
    emit("running", node_id=nodeid)


def pytest_runtest_logreport(report):
    emit("report", node_id=report.nodeid, phase=report.when,
         outcome=report.outcome, xfail=hasattr(report, "wasxfail"))


def pytest_sessionfinish(session, exitstatus):
    emit("finish", exit_code=int(exitstatus))
