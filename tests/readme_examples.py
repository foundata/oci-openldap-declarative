"""Select executable documentation by stable section anchors."""

from __future__ import annotations

import re


def bash_example(document: str, anchor: str) -> str:
    headings: list[tuple[int, int, str]] = []
    offset = 0
    fenced = False
    for line in document.splitlines(keepends=True):
        if line.startswith("```"):
            fenced = not fenced
        elif not fenced and re.match(r"^#{1,6} ", line):
            headings.append((offset, offset + len(line), line))
        offset += len(line)
    matches = [
        index for index, item in enumerate(headings) if f'id="{anchor}"' in item[2]
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one documentation section: {anchor}")
    index = matches[0]
    end = headings[index + 1][0] if index + 1 < len(headings) else len(document)
    section = document[headings[index][1] : end]
    blocks = list(
        re.finditer(r"^```bash\n(.*?)^```$", section, re.MULTILINE | re.DOTALL)
    )
    if len(blocks) != 1:
        raise ValueError(f"expected one Bash example in section: {anchor}")
    return blocks[0][1]
