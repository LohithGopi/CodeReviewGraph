"""Persistence and checkpointer management for CodeReviewGraph."""
from typing import Optional, Dict, Any
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import MemorySaver


class CheckpointManager:
    """Manages thread-scoped graph execution state and checkpoint inspection."""

    def __init__(self, checkpointer: Optional[BaseCheckpointSaver] = None):
        self.checkpointer: BaseCheckpointSaver = checkpointer or MemorySaver()

    def get_run_state(self, app: Any, thread_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve latest checkpoint state for a specific thread/run."""
        config = {"configurable": {"thread_id": thread_id}}
        try:
            state = app.get_state(config)
            if state and state.values:
                return {
                    "thread_id": thread_id,
                    "values": state.values,
                    "next": list(state.next) if state.next else [],
                    "metadata": state.metadata
                }
        except Exception:
            return None
        return None


# Default global checkpointer
default_checkpointer = MemorySaver()
checkpoint_manager = CheckpointManager(default_checkpointer)
