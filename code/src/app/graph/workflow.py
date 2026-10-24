"""LangGraph workflow orchestrating the deletion audit pipeline."""

from langgraph.graph import StateGraph, END
from code.src.guardrails.schemas import CaseState
from code.src.app.graph.nodes.intent_classifier import classify_request_intent
from code.src.app.graph.nodes.plan_builder import build_audit_plan
from code.src.guardrails.critic import critic_verifier


def intent_node(state: CaseState) -> CaseState:
    """Classify user request intent."""
    return classify_request_intent(state)


def plan_node(state: CaseState) -> CaseState:
    """Audit evidence and assemble steps."""
    return build_audit_plan(state)


def critic_node(state: CaseState) -> CaseState:
    """Verify output with critic."""
    passed, issues = critic_verifier.verify_case(state)
    state.critic_passed = passed
    state.critic_feedback = issues
    return state


def route_after_intent(state: CaseState) -> str:
    """Short-circuit NOT_APPLICABLE cases or continue to audit plan."""
    if state.authorizes_deletion is False:
        return "critic"
    return "plan"


def create_deletion_audit_graph():
    """Build and compile the LangGraph audit graph."""
    workflow = StateGraph(CaseState)

    workflow.add_node("intent", intent_node)
    workflow.add_node("plan", plan_node)
    workflow.add_node("critic", critic_node)

    workflow.set_entry_point("intent")

    workflow.add_conditional_edges(
        "intent",
        route_after_intent,
        {
            "critic": "critic",
            "plan": "plan",
        },
    )

    workflow.add_edge("plan", "critic")
    workflow.add_edge("critic", END)

    return workflow.compile()


# Compiled application graph
audit_graph = create_deletion_audit_graph()
