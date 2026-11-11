"""Turn Sphinx roles in docstrings into Markdown cross-references.

The library docstrings use roles such as ``:class:`CveRecord``` and
``:class:`~nvd_client.exceptions.NvdNotFoundError```. Griffe's Sphinx
parser reads field lists (``:param:``) and leaves these inline roles in
the text, so the API pages would show the raw markup. This hook rewrites
them before Markdown runs.
"""

from __future__ import annotations

import re

from markdown.extensions import Extension
from markdown.preprocessors import Preprocessor

# Short names used in docstrings, mapped to the object the role should open.
_SHORT_TARGETS = {
    "CpeMatchResponse": "nvd_client.models.CpeMatchResponse",
    "CveListResponse": "nvd_client.models.CveListResponse",
    "CveRecord": "nvd_client.models.CveRecord",
    "NvdApi.get_cve_by_id": "nvd_client.api.NvdApi.get_cve_by_id",
}

_ROLE = re.compile(r":(?:class|meth|func|mod|attr):`(~?)([^`]+)`")


def _replace(match: re.Match[str]) -> str:
    target = match.group(2).strip()
    label = target.rsplit(".", 1)[-1] if match.group(1) else target
    identifier = _SHORT_TARGETS.get(target, target)
    return f"[{label}][{identifier}]"


class _SphinxRolePreprocessor(Preprocessor):
    def run(self, lines: list[str]) -> list[str]:
        rewritten: list[str] = []
        in_fence = False
        for line in lines:
            stripped = line.lstrip()
            if stripped.startswith("```"):
                in_fence = not in_fence
                rewritten.append(line)
                continue
            if in_fence:
                rewritten.append(line)
                continue
            rewritten.append(_ROLE.sub(_replace, line))
        return rewritten


class SphinxRoleExtension(Extension):
    """Markdown extension that rewrites Sphinx cross-reference roles."""

    def extendMarkdown(self, md) -> None:
        md.preprocessors.register(_SphinxRolePreprocessor(md), "nvd_sphinx_roles", 175)


def on_config(config):
    config.markdown_extensions.append(SphinxRoleExtension())
    return config
