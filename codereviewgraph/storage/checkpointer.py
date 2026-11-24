"""Persistence and checkpointer management for CodeReviewGraph."""
from typing import Optional, Dict, Any, List
from langgraph.checkpoint.memory import MemorySaver


class BoundedMemorySaver(MemorySaver):
    """In-memory checkpointer with bounded LRU eviction to prevent memory leaks."""

    def __init__(self, max_threads: int = 500):
        super().__init__()
        self.max_threads = max_threads
        self._thread_order: List[str] = []

    def put(self, config: Dict[str, Any], checkpoint: Any, metadata: Any, new_versions: Any) -> Any:
        thread_id = config.get("configurable", {}).get("thread_id")
        if thread_id:
            if thread_id in self._thread_order:
                self._thread_order.remove(thread_id)
            self._thread_order.append(thread_id)
            while len(self._thread_order) > self.max_threads:
                oldest = self._thread_order.pop(0)
                self.delete_thread(oldest)
        return super().put(config, checkpoint, metadata, new_versions)


class CheckpointManager:
    """Manages thread-scoped graph execution state and checkpoint inspection."""

    def __init__(self, checkpointer: Optional[Any] = None):
        self.checkpointer = checkpointer

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


checkpoint_manager = CheckpointManager()
