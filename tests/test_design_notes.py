"""The course narrative lives in docs/design-notes.md, and code points at it.

Two things keep that true:
  * no course markers (lesson IDs, MAESTRO finding IDs, "the learner") in the
    code, packaging metadata or CI config -- the why stays, in plain words;
  * every `design-notes.md#anchor` pointer anywhere in the repo names an
    anchor that exists, so editing the notes cannot silently strand the code.
"""
import glob
import os
import re
import unittest

from tests.support import ROOT

NOTES = os.path.join(ROOT, "docs", "design-notes.md")

SHIPPED = (glob.glob(os.path.join(ROOT, "tooling", "*.py"))
           + glob.glob(os.path.join(ROOT, "examples", "*.py"))
           + glob.glob(os.path.join(ROOT, ".github", "workflows", "*.yml"))
           + [os.path.join(ROOT, "pyproject.toml"),
              os.path.join(ROOT, ".pre-commit-hooks.yaml")])
# User docs point at the notes too, rather than retelling the course.
DOCS = ([os.path.join(ROOT, "README.md"), os.path.join(ROOT, "tooling", "README.md")]
        + [p for p in glob.glob(os.path.join(ROOT, "docs", "*.md")) if p != NOTES])

COURSE_MARKERS = re.compile(
    r"\bL\d{2}\b"                 # lesson IDs: L04, L17
    r"|\b[XDF]\d\b"               # finding / day IDs: X3, D2, F8 (not F811)
    r"|\blessons? \d"             # "lesson 13", "lessons 01-17"
    r"|\blearner\b"
    r"|\b(this|training) workspace\b"
    r"|\bcapstone\b"
    r"|\bseventeen lessons\b",
    re.I)

POINTER = re.compile(r"design-notes\.md#([\w-]+)")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class CourseNarrative(unittest.TestCase):

    def test_no_course_markers_in_shipped_files_or_docs(self):
        hits = []
        for path in SHIPPED + DOCS:
            for n, line in enumerate(read(path).splitlines(), 1):
                m = COURSE_MARKERS.search(line)
                if m:
                    hits.append("%s:%d  %s" % (os.path.relpath(path, ROOT), n, m.group(0)))
        self.assertFalse(hits, "course markers belong in docs/design-notes.md:\n  "
                         + "\n  ".join(hits))


class Pointers(unittest.TestCase):

    def test_every_pointer_names_an_anchor_that_exists(self):
        anchors = set(re.findall(r'<a id="([\w-]+)"></a>', read(NOTES)))
        self.assertTrue(anchors, "design-notes.md defines no anchors")
        files = SHIPPED + glob.glob(os.path.join(ROOT, "**", "*.md"), recursive=True)
        dangling = []
        for path in files:
            for anchor in POINTER.findall(read(path)):
                if anchor not in anchors:
                    dangling.append("%s -> #%s" % (os.path.relpath(path, ROOT), anchor))
        self.assertFalse(dangling, "pointers to missing anchors:\n  " + "\n  ".join(dangling))

    def test_code_points_at_the_notes(self):
        pointing = [p for p in SHIPPED if POINTER.search(read(p))]
        self.assertGreaterEqual(len(pointing), 5, pointing)


if __name__ == "__main__":
    unittest.main()
