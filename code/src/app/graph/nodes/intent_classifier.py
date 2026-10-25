"""Intent Classifier Node using TypeSafe JEV Decisions API.

Determines whether the customer request_text actually authorizes account/data deletion,
or is a non-deletion request (access, export, opt-out, receipt, etc.) which must be
classified as NOT_APPLICABLE with empty steps [].

Powered by TypeSafe JEV (typesafe/jev-1.14) with multilingual semantic reasoning.
No Gemini LLM used in this decision node.
"""

import json
import logging
import os
from typing import Dict, Any, Optional

try:
    import requests
except ImportError:
    requests = None

from code.src.config.settings import settings
from code.src.guardrails.schemas import CaseState, DeletionStatus

logger = logging.getLogger(__name__)


def query_jev_decision_api(request_text: str) -> Optional[Dict[str, Any]]:
    """Query TypeSafe JEV Alpha Decisions API via OpenRouter."""
    api_key = settings.typesafe_api_key or os.getenv("OPENROUTER_JEV")
    if not api_key:
        logger.warning("No TypeSafe/OpenRouter API key found for JEV decisions.")
        return None

    url = settings.typesafe_base_url or "https://openrouter.ai/api/alpha/decisions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": settings.jev_model or "typesafe/jev-1.14",
        "state": {
            "customer_request": request_text,
        },
        "questions": {
            "authorizes_deletion": {
                "type": "noul",
                "instructions": (
                    "Does this customer message explicitly request or authorize account or personal-data deletion/erasure/closing? "
                    "Handle multilingual semantics across English, German, French, Spanish, Italian, Portuguese, and Dutch. "
                    "Examples of YES (authorizes deletion): "
                    "'Please delete my account and erase my data', "
                    "'Ich möchte mein Konto und alle personenbezogenen Daten unwiderruflich löschen', "
                    "'Veuillez supprimer définitivement mon compte et mes informations personnelles', "
                    "'Solicito la eliminación permanente de mi cuenta de usuario y mis datos', "
                    "'Excluir minha conta e apagar todos os registros', "
                    "'Verwijder mijn account en wis alle gegevens'. "
                    "Examples of NO (does NOT authorize deletion): "
                    "'I want to download a copy of my data (GDPR Article 15)', "
                    "'Auskunftsrecht: Bitte senden Sie mir eine Kopie meiner Daten', "
                    "'Export my purchase history and transaction records', "
                    "'Unsubscribe me from marketing newsletter emails', "
                    "'Do not delete my account, I just want my invoice', "
                    "'Non eliminare il mio account, voglio solo una fattura'."
                ),
            },
            "is_non_deletion_only": {
                "type": "noul",
                "instructions": (
                    "Is this customer message solely a non-deletion request such as data access, GDPR export, "
                    "invoice request, marketing opt-out, or explicit instruction NOT to delete? "
                    "Examples of YES: 'Ich möchte eine Kopie meiner Daten', 'Download my profile information', 'Do not delete'."
                ),
            },
        },
    }

    try:
        if requests is not None:
            res = requests.post(url, headers=headers, json=payload, timeout=12)
            if res.status_code == 200:
                return res.json()
            else:
                logger.warning(f"JEV API returned status {res.status_code}: {res.text}")
        else:
            # Fallback to urllib.request
            import urllib.request
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=12) as response:
                if response.status == 200:
                    return json.loads(response.read().decode("utf-8"))
    except Exception as e:
        logger.error(f"Error querying JEV Decisions API: {e}")

    return None


def classify_request_intent(state: CaseState) -> CaseState:
    """Classify request intent using TypeSafe JEV with multilingual semantics."""
    request_text = state.request_text.strip()
    lower_text = request_text.lower()

    # Fast multilingual pre-filters for obvious non-deletion requests
    if any(
        kw in lower_text
        for kw in [
            "nicht löschen",
            "do not delete",
            "don't delete",
            "auskunftsrecht",
            "kopie meiner daten",
            "daten herunterladen",
            "download a copy",
            "access request",
            "data portability",
            "export my data",
            "datenübertragbarkeit",
            "opt-out",
            "unsubscribe",
        ]
    ):
        state.authorizes_deletion = False
        state.intent_reason = "Customer explicitly requested data access/export or non-deletion."
        state.deletion_status = DeletionStatus.NOT_APPLICABLE
        state.steps = []
        return state

    # Query TypeSafe JEV Decisions API
    jev_data = query_jev_decision_api(request_text)
    if jev_data:
        # Decisions may be at root or under 'decisions' key
        decisions = jev_data.get("decisions", jev_data)
        auth_del = decisions.get("authorizes_deletion")
        non_del = decisions.get("is_non_deletion_only")

        # Unwrap if returned as dictionary or direct value
        if isinstance(auth_del, dict):
            auth_val = auth_del.get("value")
        else:
            auth_val = auth_del

        if isinstance(non_del, dict):
            non_del_val = non_del.get("value")
        else:
            non_del_val = non_del

        # Convert noul / boolean / string to boolean
        is_del = auth_val is True or str(auth_val).lower() in ("true", "yes", "1")
        is_non_del = non_del_val is True or str(non_del_val).lower() in ("true", "yes", "1")

        if is_non_del:
            state.authorizes_deletion = False
            state.intent_reason = "JEV classified message as non-deletion request (access/export/opt-out)."
        elif is_del:
            state.authorizes_deletion = True
            state.intent_reason = "JEV classified message as authorized deletion request."
        else:
            # If neither triggered, default to True for deletion audit evaluation
            state.authorizes_deletion = True
            state.intent_reason = "JEV decision defaulted to authorized deletion."
    else:
        # Default fallback if JEV API is unreachable
        state.authorizes_deletion = True
        state.intent_reason = "Defaulted to True (JEV fallback)."

    if not state.authorizes_deletion:
        state.deletion_status = DeletionStatus.NOT_APPLICABLE
        state.steps = []

    return state
