"""Tests for YAML config loading."""

import pytest
import tempfile
from pathlib import Path

from agenthalt.config import load_config, load_config_from_dict


def test_load_from_dict():
    engine = load_config_from_dict(
        {
            "guards": {
                "budget": {"max_daily_spend": 10.0},
                "deletion": {"allow_patterns": ["temp_*"]},
                "scope": {"deny_functions": ["drop_*"]},
            }
        }
    )
    assert len(engine.guards) == 3
    names = [g.name for g in engine.guards]
    assert "budget" in names
    assert "deletion" in names
    assert "scope" in names


def test_load_from_yaml():
    yaml_content = """
guards:
  budget:
    max_daily_spend: 5.0
    default_cost: 0.02
  purchase:
    max_single_purchase: 50.0
    blocked_categories:
      - gambling
  rate_limit:
    max_calls_per_minute: 20
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(yaml_content)
        f.flush()
        engine = load_config(f.name)

    assert len(engine.guards) == 3
    names = [g.name for g in engine.guards]
    assert "budget" in names
    assert "purchase" in names
    assert "rate_limit" in names


def test_unknown_guard_raises():
    with pytest.raises(ValueError, match="Unknown guard"):
        load_config_from_dict({"guards": {"nonexistent_guard": {}}})


def test_empty_config():
    engine = load_config_from_dict({"guards": {}})
    assert len(engine.guards) == 0


def test_disabled_guard():
    engine = load_config_from_dict(
        {
            "guards": {
                "budget": {"max_daily_spend": 10.0, "enabled": False},
            }
        }
    )
    assert len(engine.guards) == 1
    assert not engine.guards[0].enabled


def test_all_guards():
    engine = load_config_from_dict(
        {
            "guards": {
                "budget": {},
                "purchase": {},
                "deletion": {},
                "rate_limit": {},
                "scope": {},
                "sensitive_data": {},
            }
        }
    )
    assert len(engine.guards) == 6
