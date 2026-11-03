"""Browser automation may type a password and a one-time code into the login field.

Saved secrets still go through the vault (they never come back in tool results).
The model-facing guidance must not refuse entry of a password or OTP the user
asked to place in the focused field, and must still keep card confirmation,
origin binding, and read-back of cookies/passwords off the input path.

The input tool is browser_exec (fill_input). Saved logins, fills, and codes are
actions of browser_vault, not separate tools.
"""

from __future__ import annotations

import json
import re
from unittest.mock import patch


# Guidance that made the model refuse to type a password or OTP into the page.
_ENTRY_REFUSAL = re.compile(
    r"never type (?:a |one |it |the )?(?:password|verification code|one-time|otp|2fa)"
    r"|never type it with"
    r"|only way a password may reach"
    r"|passwords are typed only by these tools",
    re.I,
)

_USER_SUPPLIED_MARKER = "When the user asked you to sign in and supplied a password"


def _blocks_password_or_otp_entry(text: str) -> bool:
    return bool(_ENTRY_REFUSAL.search(text))


def _allows_password_and_otp_entry(text: str) -> bool:
    """User-supplied password and OTP may be typed; a secret shown only on the page may not."""
    low = text.lower()
    mentions_password_entry = "password" in low and ("type" in low or "fill_input" in low)
    mentions_otp = any(tok in low for tok in ("one-time", "2fa", "otp", "verification code"))
    leaves_page_shown_secrets = "only the page" in low
    return mentions_password_entry and mentions_otp and leaves_page_shown_secrets and not _blocks_password_or_otp_entry(text)


def _allows_otp_entry(text: str) -> bool:
    """A tool error that still lets the model type a user-supplied one-time code."""
    low = text.lower()
    return any(tok in low for tok in ("one-time", "2fa")) and "type" in low and not _blocks_password_or_otp_entry(text)


def test_browser_exec_schema_allows_password_and_otp_entry():
    """browser_exec carries the vault note only when browser_vault is in the session."""
    from model_tools import _apply_dynamic_schemas

    def described(include_vault: bool) -> str:
        tools = [
            {"type": "function", "function": {"name": "terminal", "description": "Run a shell command."}},
            {"type": "function", "function": {"name": "browser_exec", "description": "Drive the browser."}},
        ]
        if include_vault:
            tools.append({"type": "function", "function": {"name": "browser_vault", "description": "Fill from the vault."}})
        out = {t["function"]["name"]: t["function"]["description"] for t in _apply_dynamic_schemas(tools)}
        return out["browser_exec"]

    desc = described(True)
    assert _USER_SUPPLIED_MARKER in desc
    assert _allows_password_and_otp_entry(desc), desc
    assert "browser_vault" in desc
    assert "action=fill" in desc
    assert "action=enter_code" in desc
    assert re.search(r"do not type a card number", desc, re.I)
    assert "cookie" in desc.lower()
    assert "vault secret" in desc.lower()

    bare = described(False)
    assert bare == "Drive the browser."
    assert _USER_SUPPLIED_MARKER not in bare


def test_vault_and_browser_use_guidance_allow_entry_without_exfiltration(monkeypatch):
    """Vault schema, empty-list hint, and browser_exec helpers allow entry and still withhold secrets."""
    from tools.browser_use_cli import _HELPERS_DIGEST
    from tools.browser_vault_tool import BROWSER_VAULT_SCHEMA, browser_vault_enter_code, browser_vault_list

    class _Empty:
        name = "local"
        needs_unlock = False

        def list_items(self):
            return []

    monkeypatch.setattr("agent.vault_backends.enabled_backends", lambda: [_Empty()])
    hint = json.loads(browser_vault_list())["hint"]
    schema = BROWSER_VAULT_SCHEMA["description"]

    for text in (schema, _HELPERS_DIGEST, hint):
        assert _allows_password_and_otp_entry(text), text

    assert re.search(r"secret values are never returned", schema, re.I)
    assert re.search(r"origin exactly matches", schema, re.I)
    assert re.search(r"user confirms", schema, re.I)
    assert not _blocks_password_or_otp_entry(schema)

    no_field = [{"index": 0, "type": "text", "name": "q", "label": "Search", "autocomplete": ""}]
    otp_field = [{"index": 0, "type": "text", "name": "otp", "label": "code", "autocomplete": "one-time-code"}]

    def eval_for(controls):
        def _eval(_task, expr):
            payload = controls if "querySelectorAll" in expr else "https://acme.test/login"
            return {"success": True, "result": json.dumps(payload)}
        return _eval

    from tools import browser_vault_tool

    with patch.object(browser_vault_tool, "_focus_bound_origin", lambda *a, **k: None), \
         patch.object(browser_vault_tool, "_eval_js", side_effect=eval_for(no_field)):
        missed = json.loads(browser_vault_enter_code(task_id="t"))
    assert missed["error_type"] == "no_code_field"
    assert _allows_otp_entry(missed["error"])

    with patch("agent.vault_backends.unlock.can_prompt_here", return_value=False), \
         patch.object(browser_vault_tool, "_focus_bound_origin", lambda *a, **k: None), \
         patch.object(browser_vault_tool, "_eval_js", side_effect=eval_for(otp_field)):
        unpromptable = json.loads(browser_vault_enter_code(task_id="t"))
    assert unpromptable["error_type"] == "prompt_unavailable"
    assert _allows_otp_entry(unpromptable["error"])
