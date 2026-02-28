"""AgentHalt — YAML Config Example

Shows how to load guards from a YAML configuration file.
"""

import asyncio
from pathlib import Path

from agenthalt import CallContext
from agenthalt.config import load_config


async def main() -> None:
    # Load engine from YAML config
    config_path = Path(__file__).parent / "agenthalt.yaml"
    engine = load_config(config_path)

    print(f"Loaded engine: {engine}")
    print(f"Guards: {[g.name for g in engine.guards]}\n")

    # Test a few calls
    calls = [
        CallContext(function_name="gpt4_call", arguments={"prompt": "Hi"}, session_id="s1"),
        CallContext(
            function_name="delete_email", arguments={"resource_id": "inbox"}, session_id="s1"
        ),
        CallContext(
            function_name="delete_file", arguments={"resource_id": "temp_log"}, session_id="s1"
        ),
        CallContext(function_name="purchase_item", arguments={"amount": 200.0}, session_id="s1"),
        CallContext(function_name="drop_table", arguments={"table": "users"}, session_id="s1"),
    ]

    for ctx in calls:
        result = await engine.evaluate(ctx)
        final = result.final_decision
        print(f"{ctx.function_name}: {final.decision.value} — {final.reason}")


if __name__ == "__main__":
    asyncio.run(main())
