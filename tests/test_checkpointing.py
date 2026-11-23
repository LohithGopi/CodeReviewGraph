"""Tests for LangGraph state persistence and checkpoint manager."""
from langgraph.checkpoint.memory import MemorySaver
from codereviewgraph.graph.workflow import create_code_review_graph
from codereviewgraph.storage.checkpointer import CheckpointManager


def test_checkpoint_persistence_and_retrieval():
    checkpointer = MemorySaver()
    app = create_code_review_graph(checkpointer=checkpointer)
    manager = CheckpointManager(checkpointer)

    thread_id = "thread-12345"
    app.invoke(
        {"raw_code": "x = 10\ny = 20", "language": "python"},
        config={"configurable": {"thread_id": thread_id}}
    )

    state = manager.get_run_state(app, thread_id)
    assert state is not None
    assert state["thread_id"] == thread_id
    assert state["values"]["current_stage"] == "REVIEW_COMPLETED"
    assert "final_report" in state["values"]


def test_thread_isolation():
    checkpointer = MemorySaver()
    app = create_code_review_graph(checkpointer=checkpointer)

    app.invoke(
        {"raw_code": "def a(): pass", "language": "python"},
        config={"configurable": {"thread_id": "thread-A"}}
    )
    app.invoke(
        {"raw_code": "eval('bad')", "language": "python"},
        config={"configurable": {"thread_id": "thread-B"}}
    )

    state_a = app.get_state({"configurable": {"thread_id": "thread-A"}})
    state_b = app.get_state({"configurable": {"thread_id": "thread-B"}})

    assert state_a.values["overall_score"] == 100
    assert state_b.values["overall_score"] < 100
    assert state_a.values["needs_refactor"] is False
    assert state_b.values["needs_refactor"] is True
