"""Run the module-docstring doctests (Prompt 5.3) as part of the suite."""
from __future__ import annotations

import doctest
import importlib

import pytest

MODULES = [
    "logicward.engine.events",
    "logicward.engine.l5x",
    "logicward.engine.baseline",
    "logicward.engine.classify",
    "logicward.plant.modbus_server",
]


@pytest.mark.parametrize("name", MODULES)
def test_module_doctests(name: str) -> None:
    mod = importlib.import_module(name)
    failures, _ = doctest.testmod(mod, verbose=False)
    assert failures == 0, f"{name} has {failures} failing doctest(s)"
