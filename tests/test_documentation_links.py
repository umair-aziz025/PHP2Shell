"""Catch broken relative Markdown references without accessing any external URL.

Run: python -m unittest discover -s tests -v
"""
import re
from pathlib import Path
from urllib.parse import unquote
import unittest

ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"\]\(([^)]+)\)")


class DocumentationLinkTests(unittest.TestCase):
    def test_relative_markdown_links_resolve(self):
        files = list(ROOT.rglob("*.md"))
        self.assertTrue(files, "Expected at least one Markdown document")
        missing = []
        for document in files:
            content = document.read_text(encoding="utf-8")
            for raw in LINK_RE.findall(content):
                address = raw.strip().split("#", 1)[0].split("?", 1)[0]
                if not address or address.startswith(("http://", "https://", "mailto:")):
                    continue
                destination = (document.parent / unquote(address)).resolve()
                if not destination.is_file() and not destination.is_dir():
                    missing.append(f"{document.relative_to(ROOT)} -> {raw}")
        self.assertFalse(missing, "Broken local links:\n" + "\n".join(missing))


if __name__ == "__main__":
    unittest.main()
