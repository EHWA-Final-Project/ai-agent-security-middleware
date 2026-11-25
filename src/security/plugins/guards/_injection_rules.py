"""Shared prompt-injection rule set for Input Guard and Context Guard.

Internal to the Guard package (no interface, DTO, enum or policy change).

Why this exists: the Sprint-1 guards returned one fixed score for any
literal-phrase hit and 0.0 otherwise. That gives only a few distinct score
values, so a threshold sweep produces step changes and cannot separate B
from C in a meaningful way. Here a text is scored by the *strength* and the
*number* of distinct rules that fire:

* tier ``strong``  - unambiguous override / prompt-extraction wording. The
  legacy literal phrases live here, so they keep their exact legacy score.
* tier ``medium``  - role spoofing, delimiter tricks, imperative tool or
  exfiltration directives. Suspicious, but also appears in benign text.
* tier ``weak``    - generic steering language. Only meaningful in numbers.

Score = tier base + ``_EXTRA_RULE_BONUS`` per additional distinct rule,
capped per tier, so a tier can never reach the tier above it.

Text is normalised first (Unicode NFKC, zero-width / format characters
removed, case-folded, whitespace collapsed). Strong phrases are also checked
on a "squashed" copy (letters and digits only) to catch spaced-out or
punctuated variants, and on decoded base64 tokens. These are limited
countermeasures, not full obfuscation handling.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

STRONG = "strong"
MEDIUM = "medium"
WEAK = "weak"

_EXTRA_RULE_BONUS = 0.05
#: score ceiling per tier relative to the tier base (strong gets no bonus,
#: so legacy phrases keep exactly the legacy score).
_TIER_BONUS_CAP = {STRONG: 0.0, MEDIUM: 0.15, WEAK: 0.15}
#: a warn-level decision starts here (the default strict threshold).
WARN_SCORE = 0.50


@dataclass(frozen=True)
class Rule:
    rule: str
    family: str
    tier: str
    pattern: re.Pattern[str]
    #: restrict the rule to one guard ("input" / "context"); None = both.
    only_for: str | None = None


def _r(rule: str, family: str, tier: str, regex: str, only_for: str | None = None) -> Rule:
    return Rule(rule, family, tier, re.compile(regex, re.IGNORECASE), only_for)


_QUALIFIER = r"(?:\s+(?:all|any|the|your|my|of|these|those|every))*"
_PRIOR = r"(?:previous|prior|above|earlier|preceding|former)"
_INSTR = r"(?:instructions?|prompts?|rules?|directions?|guidelines?|commands?)"

RULES: tuple[Rule, ...] = (
    # --- strong: override -------------------------------------------------
    _r("override.ignore_previous", "override", STRONG,
       rf"\b(?:ignore|disregard|forget|override|bypass|skip){_QUALIFIER}\s+{_PRIOR}\s+{_INSTR}\b"),
    _r("override.disregard_above", "override", STRONG, r"\bdisregard\s+the\s+above\b"),
    _r("override.ignore_above", "override", STRONG,
       r"\b(?:ignore|disregard)\s+(?:everything|anything|all)\s+(?:above|before|so\s+far)\b"),
    _r("override.korean", "override", STRONG,
       r"(?:이전|위의|앞의|기존)\s*(?:모든\s*)?(?:지시|지침|명령|규칙)[을를]?\s*(?:모두\s*)?(?:무시|잊)"),
    # --- strong: prompt extraction ---------------------------------------
    _r("extraction.system_prompt", "extraction", STRONG,
       r"\b(?:reveal|show|print|repeat|output|display|leak|tell\s+me)\b[^.\n]{0,40}\b"
       r"(?:system\s+prompt|initial\s+prompt|hidden\s+prompt|your\s+instructions)\b"),
    # --- strong: new-instruction marker (legacy, context) -----------------
    _r("marker.new_instructions", "marker", STRONG, r"\bnew\s+instructions\s*:"),
    _r("marker.system_colon", "marker", STRONG, r"(?:^|\s)system\s*:", only_for="context"),
    # --- medium: role spoofing / persona ---------------------------------
    _r("role.system_colon", "role", MEDIUM, r"(?:^|\s)(?:system|assistant|developer)\s*:", only_for="input"),
    _r("role.you_are_now", "role", MEDIUM, r"\byou\s+are\s+now\b"),
    _r("role.act_as", "role", MEDIUM, r"\b(?:act|behave|respond)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+|the\s+)?"
                                      r"(?:unrestricted|jailbroken|dan|developer|admin|root|system)\b"),
    _r("role.developer_mode", "role", MEDIUM, r"\b(?:developer|debug|god|admin|sudo)\s+mode\b"),
    _r("role.pretend", "role", WEAK, r"\bpretend\s+(?:that\s+)?(?:you|to\s+be)\b"),
    # --- medium: delimiter / prompt-boundary tricks ----------------------
    _r("delimiter.end_of_prompt", "delimiter", MEDIUM,
       r"(?:\bend\s+of\s+(?:the\s+)?(?:prompt|instructions|system|document|context)\b|"
       r"\[/?(?:system|inst|instructions?)\]|<\|?(?:im_start|im_end|system|endoftext)\|?>)"),
    _r("delimiter.access_granted", "delimiter", WEAK, r"\baccess\s+granted\b"),
    # --- medium: imperative tool / exfiltration directive ----------------
    _r("directive.send_to_address", "directive", MEDIUM,
       r"\b(?:send|forward|email|mail|post|upload|transmit)\b[^.\n]{0,80}"
       r"(?:\bto\b[^.\n]{0,30})?[\w.+-]+@[\w-]+\.[\w.-]+", only_for="context"),
    _r("directive.exfiltrate_data", "directive", MEDIUM,
       r"\b(?:send|forward|leak|exfiltrate|upload|transmit|email)\b[^.\n]{0,60}"
       r"\b(?:sensitive|confidential|secret|private|credentials?|passwords?|api[\s_-]?keys?)\b",
       only_for="context"),
    _r("directive.call_tool", "directive", MEDIUM,
       r"\b(?:call|invoke|run|execute|use)\s+(?:the\s+)?(?:tool|function|command)\b", only_for="context"),
    _r("directive.delete", "directive", MEDIUM, r"\b(?:delete|remove|erase|wipe)\s+(?:all\s+|the\s+|every\s+)?(?:files?|data|records?|logs?)\b",
       only_for="context"),
    # --- medium: untrusted content telling the assistant what to put in its output
    _r("directive.shape_response", "directive", MEDIUM,
       r"\b(?:add|include|insert|append|prepend|mention|use|integrate|embed|feature|ensure|make\s+sure|"
       r"start|begin|end|finish|conclude|enhance|recommend|suggest|invite|incorporate|write|respond|answer|reply)\b"
       r"(?:[^.\n]|\.(?=\S)){0,80}\b(?:in|to|into|within|for)\s+your\s+(?:response|reply|answer|output|message|summary|answers|responses)\b",
       only_for="context"),
    _r("directive.insert_code_or_link", "directive", MEDIUM,
       r"\b(?:add|include|use|insert|incorporate|feature|ensure|embed|integrate)\b[^.\n]{0,60}"
       r"\b(?:following|below)\s+(?:code|snippet|script|command|link|url|text)\b", only_for="context"),
    _r("extraction.repeat_instructions", "extraction", MEDIUM,
       r"\b(?:repeat|recite|restate|summari[sz]e|translate|convert|print)\b[^.\n]{0,40}"
       r"\b(?:your|the)\s+(?:instructions|rules|prompt|system\s+message|pre[-\s]?prompt)\b", only_for="input"),
    # --- weak: generic steering ------------------------------------------
    _r("steer.note_to_ai", "steer", WEAK, r"\b(?:note|message|instruction)s?\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|model|llm|agent)\b"),
    _r("steer.important", "steer", WEAK, r"\b(?:important|urgent|critical)\s*[:!]"),
    _r("steer.must_always", "steer", WEAK, r"\byou\s+(?:must|should|have\s+to|need\s+to)\s+(?:now\s+|always\s+|immediately\s+)?(?:do|follow|obey|comply|respond|answer|say|reply)\b"),
    _r("steer.instead", "steer", WEAK, r"\binstead(?:\s+of\s+(?:that|this|the\s+(?:above|task)))?,?\s+(?:please\s+)?(?:do|say|write|output|respond|answer)\b"),
    _r("steer.hidden_url", "steer", WEAK, r"\bhttps?://\S+"),
)

#: Trigger words per rule for the gated scan (condition D, FAST mode). A rule is
#: skipped only if NONE of its words occurs in the normalised text, so each entry
#: must be a necessary condition for the rule's regex: every possible match
#: contains at least one of these literals. Text is already case-folded with
#: single spaces, so plain lowercase substrings are enough. A rule without an
#: entry always runs (the safe default). tests/unit/test_injection_rule_gating.py
#: checks this table against the real rules.
_RULE_NEEDS: dict[str, tuple[str, ...]] = {
    "override.ignore_previous": ("ignore", "disregard", "forget", "override", "bypass", "skip"),
    "override.disregard_above": ("disregard",),
    "override.ignore_above": ("ignore", "disregard"),
    "override.korean": ("이전", "위의", "앞의", "기존"),
    "extraction.system_prompt": ("system prompt", "initial prompt", "hidden prompt", "your instructions"),
    "marker.new_instructions": ("new instructions",),
    "marker.system_colon": ("system",),
    "role.system_colon": ("system", "assistant", "developer"),
    "role.you_are_now": ("you are now",),
    "role.act_as": ("act as", "behave as", "respond as"),
    "role.developer_mode": ("mode",),
    "role.pretend": ("pretend",),
    "delimiter.end_of_prompt": ("end of", "[", "<"),
    "delimiter.access_granted": ("access granted",),
    "directive.send_to_address": ("send", "forward", "email", "mail", "post", "upload", "transmit"),
    "directive.exfiltrate_data": ("send", "forward", "leak", "exfiltrate", "upload", "transmit", "email"),
    "directive.call_tool": ("call", "invoke", "run", "execute", "use"),
    "directive.delete": ("delete", "remove", "erase", "wipe"),
    "directive.shape_response": (
        "your response", "your reply", "your answer", "your output", "your message", "your summary",
    ),
    "directive.insert_code_or_link": ("following", "below"),
    "extraction.repeat_instructions": (
        "repeat", "recite", "restate", "summari", "translate", "convert", "print",
    ),
    "steer.note_to_ai": ("note", "message", "instruction"),
    "steer.important": ("important", "urgent", "critical"),
    "steer.must_always": ("you must", "you should", "you have to", "you need to"),
    "steer.instead": ("instead",),
    "steer.hidden_url": ("http",),
}

_WS = re.compile(r"\s+")
_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def normalize(text: str) -> str:
    """NFKC, drop zero-width/format chars, case-fold, collapse whitespace."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return _WS.sub(" ", text.casefold()).strip()


def _squash(text: str) -> str:
    return "".join(ch for ch in text if ch.isalnum())


_STRONG_SQUASHED = {
    "override.ignore_previous": ("ignorepreviousinstructions", "ignoreallpreviousinstructions",
                                 "disregardpreviousinstructions", "disregardtheabove",
                                 "ignorepriorinstructions", "ignoretheaboveinstructions"),
    "extraction.system_prompt": ("revealyoursystemprompt", "showyoursystemprompt", "printyoursystemprompt"),
}


def _decoded_b64_variants(text: str) -> list[str]:
    out: list[str] = []
    for token in _B64_TOKEN.findall(text)[:5]:
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=False)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded and sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded) > 0.95:
            out.append(decoded)
    return out


@dataclass(frozen=True)
class Match:
    rule: str
    family: str
    tier: str
    text: str
    variant: str  # "plain" | "squashed" | "base64"


def scan(text: str, *, guard: str, gated: bool = False) -> list[Match]:
    """Return distinct rule matches for ``text`` (``guard`` = input|context).

    ``gated=True`` skips a rule when none of its trigger words (``_RULE_NEEDS``)
    occurs in the text. It returns exactly the same matches as the ungated scan;
    it only avoids running regexes that cannot match. Used by condition D while
    no risk has been seen in the run.
    """
    norm = normalize(text)
    matches: dict[str, Match] = {}

    def run(candidate: str, variant: str) -> None:
        for rule in RULES:
            if rule.only_for not in (None, guard) or rule.rule in matches:
                continue
            if gated:
                needs = _RULE_NEEDS.get(rule.rule)
                if needs is not None and not any(word in candidate for word in needs):
                    continue
            m = rule.pattern.search(candidate)
            if m:
                matches[rule.rule] = Match(rule.rule, rule.family, rule.tier, m.group(0).strip(), variant)

    run(norm, "plain")

    squashed = _squash(norm)
    for rule_name, phrases in _STRONG_SQUASHED.items():
        if rule_name not in matches:
            for phrase in phrases:
                if phrase in squashed:
                    family = rule_name.split(".")[0]
                    matches[rule_name] = Match(rule_name, family, STRONG, phrase, "squashed")
                    break

    # base64 is case-sensitive, so decode from the original text, not `norm`
    for decoded in _decoded_b64_variants(text[:20000]):
        run(normalize(decoded), "base64")

    return list(matches.values())


def score(matches: list[Match], *, strong: float, medium: float, weak: float) -> float:
    """Tier base + small bonus per extra distinct rule, capped per tier."""
    if not matches:
        return 0.0
    base = {STRONG: strong, MEDIUM: medium, WEAK: weak}
    top = max(matches, key=lambda m: base[m.tier])
    if top.tier == WEAK and len(matches) < 2:
        return 0.0  # one generic steering phrase alone is not evidence
    extras = len(matches) - 1
    bonus = min(_EXTRA_RULE_BONUS * extras, _TIER_BONUS_CAP[top.tier])
    return round(min(base[top.tier] + bonus, 0.99), 4)
