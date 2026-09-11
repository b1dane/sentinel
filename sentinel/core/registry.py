"""Module registry and selection logic."""

from __future__ import annotations

from typing import Sequence

from sentinel.core.module import Module
from sentinel.tracekit import TraceKit
from sentinel.promptfence import PromptFence
from sentinel.memoryaudit import MemoryAudit
from sentinel.extensionscope import ExtensionScope
from sentinel.stackcheck import StackCheck


class Registry:
    def __init__(self) -> None:
        self._modules: list[Module] = [
            TraceKit(),
            PromptFence(),
            MemoryAudit(),
            ExtensionScope(),
            StackCheck(),
        ]

    def all(self) -> list[Module]:
        return list(self._modules)

    def select(self, names: Sequence[str]) -> list[Module]:
        by_name = {module.name: module for module in self._modules}
        selected: list[Module] = []
        for name in names:
            module = by_name.get(name)
            if module:
                selected.append(module)
            else:
                raise ValueError(f"Unknown module: {name}")
        return selected
