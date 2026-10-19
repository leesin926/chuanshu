"""Single source of truth for product identity.

installer/setup.iss and app.spec read these values through build.ps1, so bumping
them here is the only change needed for a new release.
"""

APP_NAME = "ChuanShu"
#: Chinese-facing brand. Kept out of paths, exe names and registry keys, which all
#: use APP_NAME because a CJK exe filename makes command lines and uninstall keys fragile.
APP_TITLE_ZH = "传书"
ORG_NAME = "ChuanShu"
VERSION = "0.1.0"
PUBLISHER = "ChuanShu"
COPYRIGHT = "Copyright (C) 2026 ChuanShu"
TRANSLATION_DOMAIN = "app"


def display_name(locale: str) -> str:
    """Pick the brand for the active locale.

    A brand is not a translatable string: putting 传书 in the catalogue would let
    `pybabel update` mark it obsolete the moment a msgid stops matching, so the
    choice is made here instead.
    """
    return APP_TITLE_ZH if locale.split("_")[0] == "zh" else APP_NAME
