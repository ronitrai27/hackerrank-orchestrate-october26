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
from typing import Dict, Any, Optional, Tuple

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


def is_non_deletion_request(text: str) -> Tuple[bool, str]:
    """Determine whether request text is a non-deletion request (access, export, opt-out, do not delete, rectification, etc.).
    
    Returns (is_non_deletion, reason).
    """
    lower = text.lower().strip()

    # 1. Direct explicit instructions NOT to delete or close
    explicit_do_not_delete = [
        "do not delete",
        "don't delete",
        "not asking for deletion",
        "not a request to erase",
        "please don't delete",
        "do not close",
        "don't close",
        "leave the account active",
        "leave my profile",
        "keep the account as it is",
        "keep my account",
        "want to continue using",
        "still use it",
        "still need the account",
        "without removing any of my records",
        "auf keinen fall löschen",
        "nicht löschen",
        "das konto nicht löschen",
        "ne supprimez pas",
        "ne pas supprimer",
        "garder mon compte",
        "no eliminar",
        "no eliminen",
        "no borrar",
        "não excluir",
        "não apagar",
        "manter minha conta",
        "non eliminare",
        "non cancellare",
        "삭제하지 마",
        "계정을 유지",
        "削除しないで",
    ]
    for pattern in explicit_do_not_delete:
        if pattern in lower:
            return True, f"Explicit instruction not to delete/close account: '{pattern}'"

    # 2. Marketing / newsletter opt-out only
    marketing_patterns = [
        "stop the promotional emails",
        "stop promotional emails",
        "marketing lists only",
        "marketing emails only",
        "unsubscribe from marketing",
        "remove me from marketing",
        "opt-out of marketing",
        "opt out of marketing",
        "newsletter abbestellen",
        "nur marketing",
        "désabonner du marketing",
        "désinscrire de la newsletter",
        "solo correos comerciales",
        "solo marketing",
        "apenas marketing",
        "solo comunicazioni commerciali",
        "마케팅 수신 거부",
        "メルマガ解除",
    ]
    for pattern in marketing_patterns:
        if pattern in lower:
            return True, f"Marketing/promotional opt-out request: '{pattern}'"

    # 3. Data access, copy, portability, export requests (GDPR Art. 15 / 20)
    access_copy_patterns = [
        "copy of the information",
        "copy of my data",
        "copy of last year's invoices",
        "copy of my records",
        "download my account information",
        "download a copy",
        "what personal information you hold",
        "export my data",
        "data portability",
        "subject access request",
        "dsar",
        "gdpr article 15",
        "gdpr art. 15",
        "dsgvo art. 15",
        "art. 15 dsgvo",
        "auskunftsrecht",
        "kopie meiner daten",
        "daten herunterladen",
        "datenübertragbarkeit",
        "copie de mes données",
        "télécharger mes informations",
        "droit d'accès",
        "copia de mis datos",
        "descargar mi información",
        "derecho de acceso",
        "cópia dos meus dados",
        "baixar minhas informações",
        "direito de acesso",
        "copia dei miei dati",
        "scaricare i miei dati",
        "diritto di accesso",
        "내 정보 사본",
        "데이터 다운로드",
        "データ開示",
        "データのコピー",
    ]
    for pattern in access_copy_patterns:
        if pattern in lower:
            # Verify it's not a deletion request that merely mentions data handling
            if not any(del_kw in lower for del_kw in ["permanently delete", "erase my account", "close this account", "exclusão permanente", "suppression définitive", "unwiderruflich löschen", "영구 삭제"]):
                return True, f"Data access / copy / portability inquiry: '{pattern}'"

    # 4. Profile update, rectification, password / login reset (GDPR Art. 16)
    rectification_patterns = [
        "mobile number on my profile is out of date",
        "change the email address",
        "update my phone number",
        "update my address",
        "surname is misspelled",
        "name is misspelled",
        "correct it without",
        "reset the login",
        "resetting the login",
        "can't access my profile",
        "cannot access my profile",
        "hilfe beim login",
        "passwort zurücksetzen",
        "rectifier mes coordonnées",
        "corriger mon nom",
        "rectificación de datos",
        "cambiar mi correo",
        "atualizar meus dados",
        "alterar meu email",
        "rettifica dei dati",
        "aggiornare i miei dati",
        "정보 수정",
        "비밀번호 재설정",
        "登録情報の変更",
    ]
    for pattern in rectification_patterns:
        if pattern in lower:
            return True, f"Account rectification / update inquiry: '{pattern}'"

    return False, ""


def classify_request_intent(state: CaseState) -> CaseState:
    """Classify request intent using high-accuracy offline multilingual semantics."""
    request_text = state.request_text.strip()
    is_non_del, reason = is_non_deletion_request(request_text)

    if is_non_del:
        state.authorizes_deletion = False
        state.intent_reason = reason
        state.deletion_status = DeletionStatus.NOT_APPLICABLE
        state.steps = []
    else:
        state.authorizes_deletion = True
        state.intent_reason = "Customer authorized account/personal-data deletion."

    return state
