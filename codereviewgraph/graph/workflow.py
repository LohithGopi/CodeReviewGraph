"""Workflow graph definition and compilation using LangGraph."""
from typing import Optional, Literal
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import MemorySaver

from codereviewgraph.core.state import CodeReviewState
from codereviewgraph.graph.nodes_analysis import (
    planner_node,
    security_auditor_node,
    quality_performance_node,
)
from codereviewgraph.graph.nodes_review import (
    verification_critic_node,
    refactoring_advisor_node,
    report_compiler_node,
)


def route_after_critic(state: CodeReviewState) -> Literal["refactoring_advisor", "report_compiler"]:
    """Conditional router: sends code with critical/high flaws to refactoring, else directly to report."""
    if state.get("needs_refactor", False):
        return "refactoring_advisor"
    return "report_compiler"


def create_code_review_graph(checkpointer: Optional[BaseCheckpointSaver] = None):
    """Build and compile the LangGraph CodeReview workflow."""
    builder = StateGraph(CodeReviewState)

    # Register nodes
    builder.add_node("planner", planner_node)
    builder.add_node("security_auditor", security_auditor_node)
    builder.add_node("quality_performance", quality_performance_node)
    builder.add_node("verification_critic", verification_critic_node)
    builder.add_node("refactoring_advisor", refactoring_advisor_node)
    builder.add_node("report_compiler", report_compiler_node)

    # Register edges
    builder.add_edge(START, "planner")
    builder.add_edge("planner", "security_auditor")
    builder.add_edge("security_auditor", "quality_performance")
    builder.add_edge("quality_performance", "verification_critic")

    # Conditional routing based on reflection / critic verdict
    builder.add_conditional_edges(
        "verification_critic",
        route_after_critic,
        {
            "refactoring_advisor": "refactoring_advisor",
            "report_compiler": "report_compiler"
        }
    )

    builder.add_edge("refactoring_advisor", "report_compiler")
    builder.add_edge("report_compiler", END)

    # Compile graph with optional persistence checkpointer
    checkpoint_saver = checkpointer if checkpointer is not None else MemorySaver()
    compiled_app = builder.compile(checkpointer=checkpoint_saver)
    
    return compiled_app


# Default singleton graph instance for fast runs
review_app = create_code_review_graph()
