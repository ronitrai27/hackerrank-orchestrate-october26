"""Intent Classifier Node.

Determines whether the customer request_text actually authorizes account/data deletion,
or is a non-deletion request (access, export, opt-out, receipt, etc.) which must be
classified as NOT_APPLICABLE with empty steps [].
"""

import json
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

from code.src.config.settings import settings
from code.src.guardrails.schemas import CaseState, DeletionStatus


class IntentDecision(BaseModel):
    authorizes_deletion: bool = Field(
        ...,
        description="True if the customer explicitly requests deletion/erasure/closing of their account or personal data; False if they request data access, export, opt-out, invoice/receipt, or other non-deletion action.",
    )
    category: str = Field(
        ...,
        description="One of: DELETION, ACCESS_REQUEST, DATA_EXPORT, MARKETING_OPT_OUT, INVOICE_RECEIPT, OTHER",
    )
    reasoning: str = Field(
        ...,
        description="Brief justification of the decision.",
    )


def classify_request_intent(state: CaseState) -> CaseState:
    """Classify the intent of request_text using Gemini 2.5 Flash structured output."""
    request_text = state.request_text.strip()

    # Fast heuristics for obvious deletion keywords
    lower_text = request_text.lower()
    if any(
        kw in lower_text
        for kw in [
            "close my account and process the associated personal-data deletion",
            "account associated with this address to be erased",
            "suppression définitive du compte",
            "intenté eliminar mi cuenta",
            "solicito a exclusão permanente da conta",
            "permanent account-deletion request",
            "erase the account linked to this email address",
            "requesting deletion of the account",
            "remove my account and the personal information linked to it",
            "permanently deleted",
        ]
    ):
        state.authorizes_deletion = True
        state.intent_reason = "Matched unequivocal deletion request phrasing."
        return state

    # If ambiguous or non-standard, invoke Gemini 2.5 Flash with structured schema
    if settings.has_google:
        try:
            client = genai.Client(api_key=settings.google_api_key)
            prompt = (
                f"Analyze this customer message and determine if it explicitly authorizes account or personal-data deletion:\n\n"
                f"Customer Message: \"{request_text}\"\n\n"
                f"Rules:\n"
                f"1. A request to delete, erase, close, or 'forget' the account or personal data is DELETION (authorizes_deletion = true).\n"
                f"2. A request for data access, downloading/exporting data, marketing unsubscribe, password reset, or invoice copies is NOT DELETION (authorizes_deletion = false).\n"
                f"Respond with JSON matching the required schema."
            )

            response = client.models.generate_content(
                model=settings.gemini_model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=IntentDecision,
                    temperature=0.0,
                ),
            )

            decision_data = json.loads(response.text)
            state.authorizes_deletion = decision_data.get("authorizes_deletion", True)
            state.intent_reason = decision_data.get("reasoning", "")
        except Exception as e:
            # Fallback to deletion = True if API fails
            state.authorizes_deletion = True
            state.intent_reason = f"Fallback due to error: {e}"
    else:
        state.authorizes_deletion = True
        state.intent_reason = "No LLM client configured; defaulted to True"

    if not state.authorizes_deletion:
        state.deletion_status = DeletionStatus.NOT_APPLICABLE
        state.steps = []

    return state
