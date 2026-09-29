"""
reflectra.config
-------------------
Persistent local config so the user is never asked for the same thing
twice. Currently stores Telegram bot token + chat_id.

Storage: ~/.reflectra/config.json, file permissions set to 0600 (owner
read/write only) since this holds a bot token. This is local machine
config, never committed to the repo (see .gitignore) and never sent
anywhere except to Telegram's own API when the user has opted in.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("REFLECTRA_HOME", str(Path.home() / ".reflectra")))
CONFIG_FILE = CONFIG_DIR / "config.json"


def load_config() -> dict:
    if not CONFIG_FILE.is_file():
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def save_config(data: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    try:
        os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        pass


def get_telegram_creds() -> tuple[str | None, str | None]:
    cfg = load_config()
    tg = cfg.get("telegram", {})
    return tg.get("token"), tg.get("chat_id")


def save_telegram_creds(token: str, chat_id: str) -> None:
    cfg = load_config()
    cfg["telegram"] = {"token": token, "chat_id": chat_id}
    save_config(cfg)


def clear_telegram_creds() -> None:
    cfg = load_config()
    cfg.pop("telegram", None)
    save_config(cfg)


def config_path_display() -> str:
    return str(CONFIG_FILE)
