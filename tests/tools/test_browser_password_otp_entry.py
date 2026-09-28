"""Browser automation may type a password and a one-time code into the login field.

Saved secrets still go through the vault (they never come back in tool results).
The model-facing guidance must not refuse entry of a password or OTP the user
asked to place in the focused field, and must still keep card confirmation,
origin binding, and read-back of cookies/passwords off the input path.
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


def test_browser_input_schemas_allow_password_and_otp_entry():
    """local browser_type and browser-use browser_exec share one vault note. It must permit entry."""
    from model_tools import _apply_dynamic_schemas

    tools = [
        {"type": "function", "function": {"name": "terminal", "description": "Run a shell command."}},
        {"type": "function", "function": {"name": "browser_type", "description": "Type text into a field."}},
        {"type": "function", "function": {"name": "browser_exec", "description": "Drive the browser."}},
        {"type": "function", "function": {"name": "browser_vault_fill", "description": "Fill from a vault handle."}},
    ]
    described = {t["function"]["name"]: t["function"]["description"] for t in _apply_dynamic_schemas(tools)}

    for name in ("browser_type", "browser_exec"):
        desc = described[name]
        assert _allows_password_and_otp_entry(desc), desc
        assert "browser_vault_fill" in desc
        assert "browser_vault_enter_code" in desc
        assert re.search(r"do not type a card number", desc, re.I)
        assert "cookie" in desc.lower()
        assert "vault secret" in desc.lower()


def test_vault_and_browser_use_guidance_allow_entry_without_exfiltration(monkeypatch):
    """Sibling surfaces that used to say 'never type' must allow entry and still withhold secrets."""
    from tools.browser_use_cli import _HELPERS_DIGEST
    from tools.browser_vault_tool import (
        BROWSER_VAULT_ENTER_CODE_SCHEMA,
        BROWSER_VAULT_FILL_SCHEMA,
        BROWSER_VAULT_LIST_SCHEMA,
        BROWSER_VAULT_SAVE_LOGIN_SCHEMA,
        browser_vault_enter_code,
        browser_vault_list,
    )

    class _Empty:
        name = "local"
        needs_unlock = False

        def list_items(self):
            return []

    monkeypatch.setattr("agent.vault_backends.enabled_backends", lambda: [_Empty()])
    hint = json.loads(browser_vault_list())["hint"]

    surfaces = [
        BROWSER_VAULT_LIST_SCHEMA["description"],
        BROWSER_VAULT_SAVE_LOGIN_SCHEMA["description"],
        BROWSER_VAULT_ENTER_CODE_SCHEMA["description"],
        _HELPERS_DIGEST,
        hint,
    ]
    for text in surfaces:
        assert _allows_password_and_otp_entry(text), text

    listed = BROWSER_VAULT_LIST_SCHEMA["description"]
    assert re.search(r"secret values are never returned", listed, re.I)

    fill = BROWSER_VAULT_FILL_SCHEMA["description"]
    assert re.search(r"origin exactly matches", fill, re.I)
    assert re.search(r"user confirms", fill, re.I)
    assert not _blocks_password_or_otp_entry(fill)

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
