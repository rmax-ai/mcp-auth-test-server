"""Terminal UI helpers."""

from __future__ import annotations

import getpass
import json
import sys
from collections.abc import Callable
from typing import Any, TextIO


class TerminalUI:
    """Console input/output wrapper."""

    def __init__(
        self,
        *,
        verbose: bool = False,
        out: TextIO | None = None,
        err: TextIO | None = None,
        input_fn: Callable[[str], str] | None = None,
        secret_input_fn: Callable[[str], str] | None = None,
    ) -> None:
        self.verbose = verbose
        self.out = out or sys.stdout
        self.err = err or sys.stderr
        self._input_fn = input_fn or input
        self._secret_input_fn = secret_input_fn or getpass.getpass

    def step(self, message: str) -> None:
        print(message, file=self.out)

    def info(self, message: str) -> None:
        print(message, file=self.out)

    def detail(self, message: str) -> None:
        if self.verbose:
            print(message, file=self.out)

    def error(self, message: str) -> None:
        print(message, file=self.err)

    def prompt(self, label: str, *, default: str | None = None) -> str:
        suffix = f" [{default}]" if default else ""
        value = self._input_fn(f"{label}{suffix}: ").strip()
        if value:
            return value
        return default or ""

    def prompt_secret(self, label: str) -> str:
        return self._secret_input_fn(f"{label}: ").strip()

    def dump_json(self, payload: dict[str, Any]) -> None:
        print(json.dumps(payload, indent=2, sort_keys=True), file=self.out)
