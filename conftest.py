"""
Root conftest.py — Project-wide pytest fixtures for DFIR-Guardrail test suite.

Provides:
- Automatic HuggingFace hub reachability patching (marks offline) so that
  BlueTeamGuardrail instantiation never hangs waiting for a network socket check.
- A global autouse session fixture to prevent any accidental outbound connections
  during CI / sandboxed execution.
"""

import pytest


@pytest.fixture(autouse=True, scope="session")
def patch_hub_reachability():
    """
    Patch _is_hub_reachable to always return False in all tests.

    Rationale: The production code does a 0.5-second TCP probe to
    huggingface.co on every BlueTeamGuardrail instantiation.  In a sandboxed
    CI/test environment that probe either hangs or fails slowly, causing the
    entire test collection phase to stall.  By marking the environment as
    offline/air-gapped from session start we guarantee:
      - BlueTeamGuardrail always falls back to heuristic mode (no network I/O).
      - Tests run in O(milliseconds) rather than O(seconds * test_count).
      - All defence logic is still exercised through the pure-Python heuristic
        and cognitive-load / roleplay regex paths.
    """
    import src.blue_team as bt_module

    original = bt_module._CAN_REACH_HUB
    # Force offline immediately — skip the TCP probe entirely
    bt_module._CAN_REACH_HUB = False
    yield
    bt_module._CAN_REACH_HUB = original
