"""Make sure nothing compiles to an empty translation.

Python's gettext hands back the empty msgstr it finds in a .mo rather than falling back to
the msgid, so a message added to the Chinese source and never carried into a catalogue
would simply render as nothing. The rules, applied to whatever catalogues exist on disk:

* zh_CN - the msgids ARE Chinese, so an untranslated entry mirrors its own msgid;
* every other locale - a translation is a human decision, so an empty or fuzzy entry stops
  the build and names the source line that introduced the string.

Scanning locale/ instead of listing languages here is deliberate: a catalogue added with
``pybabel init`` is held to the strict rule from its first compile, and a language that is
promised in LANGUAGE_NAMES but never initialised fails too, so the menu can't offer a
locale whose .mo does not exist.

Run after ``pybabel update`` and before ``pybabel compile`` (build.ps1 does both).
"""

from __future__ import annotations

import argparse
import ast
import sys
from io import BytesIO
from pathlib import Path

from babel.messages.pofile import read_po, write_po

#: Languages where an empty msgstr means "the Chinese msgid is already the answer".
MIRROR = ("zh_CN",)


def _po_path(locale_root: Path, language: str) -> Path:
    return locale_root / language / "LC_MESSAGES" / "app.po"


def catalogues(locale_root: Path) -> list[str]:
    """Every locale that has a .po under the root, whatever the name table promises."""
    return sorted(path.relative_to(locale_root).parts[0] for path in locale_root.glob("*/LC_MESSAGES/app.po"))


def promised(i18n_module: Path) -> dict[str, str]:
    """LANGUAGE_NAMES read out of the source, so this script stays free of Qt imports."""
    try:
        tree = ast.parse(i18n_module.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return {}
    for node in tree.body:
        target = getattr(node, "target", None)
        if getattr(target, "id", "") == "LANGUAGE_NAMES" and isinstance(getattr(node, "value", None), ast.Dict):
            return {key.value: value.value for key, value in zip(node.value.keys, node.value.values) if isinstance(value, ast.Constant)}
    return {}


def _mirror(msg) -> list[str]:
    """The Chinese text of one entry, one item per plural form."""
    if isinstance(msg.id, tuple):
        return [msg.id[0], *(msg.id[1:] or msg.id[:1])]
    return [str(msg.id)]


def _fill_empty(msg) -> bool:
    """Copy the msgid into every empty msgstr slot; return True when anything changed."""
    changed = False
    if isinstance(msg.string, (list, tuple)):
        source = _mirror(msg)
        filled = list(msg.string)
        for index, value in enumerate(filled):
            if not value:
                filled[index] = source[min(index, len(source) - 1)]
                changed = True
        if changed:
            msg.string = filled
        return changed
    if msg.id and not msg.string:
        msg.string = str(msg.id)
        return True
    return False


def sync(locale_root: Path, *, write: bool = True) -> int:
    locale_root = Path(locale_root)
    failures = 0
    on_disk = catalogues(locale_root)
    if not on_disk:
        print(f"no catalogues under {locale_root}", file=sys.stderr)
        return 1
    for language in sorted(set(promised(locale_root.parent / "app" / "i18n.py")) - set(on_disk)):
        print(f"{language}: promised in LANGUAGE_NAMES but {_po_path(locale_root, language)} does not exist", file=sys.stderr)
        failures += 1
    for language in on_disk:
        path = _po_path(locale_root, language)
        text = path.read_text(encoding="utf-8")
        # The file's own leading comment is ours, not Babel's; keep it byte for byte.
        preamble = text[: text.index('msgid ""')] if 'msgid ""' in text else ""
        with path.open("r", encoding="utf-8") as handle:
            catalog = read_po(handle)
        filled = 0
        problems: list[str] = []
        for message in catalog:
            if not message.id:
                continue
            where = f"{message.locations[0][0]}:{message.locations[0][1]}" if message.locations else "?"
            if language in MIRROR and message.fuzzy:
                # For the mirror language the msgid IS the translation, so Babel's guess is
                # thrown away together with the flag, and the entry is re-mirrored below.
                message.flags = [flag for flag in message.flags if flag != "fuzzy"]
                message.string = [""] * len(message.string) if isinstance(message.string, (list, tuple)) else ""
            elif message.fuzzy:
                # Babel guessed this entry from a similar msgid, and compiling ships the
                # guess as the translation, so a fuzzy entry is a wrong string in waiting.
                problems.append(f"{where} (fuzzy guess)")
                continue
            if language in MIRROR and _fill_empty(message):
                filled += 1
                continue
            values = message.string if isinstance(message.string, (list, tuple)) else [message.string]
            if any(not value for value in values):
                problems.append(where)
        if problems:
            failures += 1
            print(
                f"{language}: {len(problems)} untranslated or fuzzy message(s) - fix {path}:\n  "
                + "\n  ".join(problems),
                file=sys.stderr,
            )
        if filled:
            print(f"{language}: mirrored {filled} message(s) from their msgid")
        if write and filled:
            body = _dump(catalog)
            # Babel keeps the file's own leading comment; add it back only if it dropped it.
            if preamble and not body.startswith(preamble):
                body = preamble + body
            path.write_text(body, encoding="utf-8")
    return failures


def _dump(catalog) -> str:
    # Babel's write_po encodes every line itself, so it needs a binary sink.
    buffer = BytesIO()
    write_po(buffer, catalog, width=79)
    return buffer.getvalue().decode(catalog.charset or "utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--locale-root", type=Path, default=Path(__file__).resolve().parent.parent / "locale")
    parser.add_argument("--check", action="store_true", help="report only, do not write catalogues")
    args = parser.parse_args()
    return 1 if sync(args.locale_root, write=not args.check) else 0


if __name__ == "__main__":
    sys.exit(main())
