"""Knowledge base injected into the hunt briefing.

Markdown files versioned in the repository: the useful schemas of each SIEM and the
specifics of the environment. The content is trusted context — it is read
like code, unlike SIEM results or threat intelligence pages — and it lives
in the stable prompt prefix, hence under prompt caching.

No dynamic content enters here: the loader only reads known file names,
in a single directory, with a size cap. What is not in the repository
does not reach the briefing.
"""

from __future__ import annotations

import re
from pathlib import Path

KNOWN_FILES = ("sentinel", "defender", "secops", "environment")

_MAX_CHARS_PER_FILE = 9_000
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)


def load_knowledge(base_dir: str | Path) -> dict[str, str]:
    """Loads the known sheets. Missing or empty file = no section, never an error."""

    base = Path(base_dir)
    knowledge: dict[str, str] = {}
    for name in KNOWN_FILES:
        path = base / f"{name}.md"
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            continue
        content = _HTML_COMMENT_RE.sub("", raw).strip()
        if content:
            knowledge[name] = content[:_MAX_CHARS_PER_FILE]
    return knowledge
