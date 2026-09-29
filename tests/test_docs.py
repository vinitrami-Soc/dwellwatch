"""The documentation's links: every relative link resolves, and every #anchor names a real heading.

The docs cross-link heavily (the checklist to the threat model, the README to sections of the
catalogue), and a renamed heading or file breaks a link silently on GitHub.
"""

import re
from pathlib import Path

import pytest

from conftest import ROOT

DOCS = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md")), *sorted((ROOT / "atomics").glob("*.md"))]
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
FENCE = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)


def anchors(path: Path) -> set[str]:
    """GitHub's heading ids: lower case, punctuation dropped, spaces to hyphens, repeats numbered."""
    seen: dict[str, int] = {}
    ids = set()
    text = FENCE.sub("", path.read_text(encoding="utf-8"))
    for heading in re.findall(r"^#{1,6}\s+(.+?)\s*$", text, re.MULTILINE):
        slug = re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        ids.add(slug if count == 0 else f"{slug}-{count}")
    return ids


def links(path: Path) -> list[str]:
    text = FENCE.sub("", path.read_text(encoding="utf-8"))
    return [target for target in LINK.findall(text) if not re.match(r"[a-z]+:", target)]


@pytest.mark.parametrize("path", DOCS, ids=lambda p: p.name)
def test_every_relative_link_resolves(path):
    for target in links(path):
        file, _, anchor = target.partition("#")
        linked = (path.parent / file).resolve() if file else path
        assert linked.exists(), f"{path.name}: {target} does not exist"
        if anchor and linked.suffix == ".md":
            assert anchor in anchors(linked), f"{path.name}: {target} names no heading in {linked.name}"


def test_the_slugs_follow_githubs_rules(tmp_path):
    page = tmp_path / "page.md"
    page.write_text("# Counting: note sprays and FIM bursts\n## `POST /api/alerts`\n## Live lab (planned)\n"
                    "## Stage 6\n## Stage 6\n```\n# not a heading\n```\n")
    assert anchors(page) == {"counting-note-sprays-and-fim-bursts", "post-apialerts", "live-lab-planned",
                             "stage-6", "stage-6-1"}
