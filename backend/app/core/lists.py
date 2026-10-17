"""Loads the bundled domain lists in app/data once."""

from functools import lru_cache
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _load(name: str) -> frozenset[str]:
    path = DATA_DIR / name
    lines = path.read_text(encoding="utf-8").splitlines()
    return frozenset(l.strip().lower() for l in lines if l.strip() and not l.startswith("#"))


@lru_cache
def freemail() -> frozenset[str]:
    return _load("freemail.txt")


@lru_cache
def disposable() -> frozenset[str]:
    return _load("disposable.txt")


@lru_cache
def shorteners() -> frozenset[str]:
    return _load("shorteners.txt")


@lru_cache
def brands() -> frozenset[str]:
    return _load("brands.txt")
