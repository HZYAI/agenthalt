"""
AgentHalt CLI — run with `python -m agenthalt`

Commands:
  python -m agenthalt              Show help and quickstart guide
  python -m agenthalt --version    Show version
  python -m agenthalt demo         Run a live demo (requires dashboard extras)
  python -m agenthalt check        Validate a YAML config file
  python -m agenthalt quickstart   Print a copy-paste ready quickstart script
"""

import sys


def print_banner() -> None:
    from agenthalt import __version__

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  🛡️  AgentHalt v{__version__:<10s}                                  ║
║  Production-grade guardrails for AI agent function calls    ║
║  https://github.com/HZYAI/agenthalt                        ║
╚══════════════════════════════════════════════════════════════╝
""")


def print_help() -> None:
    print_banner()
    print("""\
USAGE:
  python -m agenthalt [command]

COMMANDS:
  (no command)    Show this help message
  --version       Show version number
  quickstart      Print a copy-paste ready example to get started
  demo            Run the live demo with real-time dashboard
  check <file>    Validate a YAML configuration file

QUICK START:
  pip install agenthalt
  python -m agenthalt quickstart    # prints a working example

  # Or in Python:
  from agenthalt import PolicyEngine, BudgetGuard, BudgetConfig, CallContext

  engine = PolicyEngine()
  engine.add_guard(BudgetGuard(BudgetConfig(max_daily_spend=10.0)))

  result = engine.evaluate_sync(CallContext(
      function_name="gpt4_call",
      arguments={"prompt": "Hello"},
  ))
  print(result.final_decision)  # DecisionType.ALLOW

GUARDS:
  BudgetGuard         Prevent overspending on API calls
  PurchaseGuard       Block unauthorized purchases
  DeletionGuard       Protect resources from deletion
  RateLimitGuard      Stop runaway loops and burst calls
  ScopeGuard          Restrict which functions agents can call
  SensitiveDataGuard  Block PII and credential leakage

DOCS:
  https://github.com/HZYAI/agenthalt
  https://pypi.org/project/agenthalt/
""")


QUICKSTART_CODE = '''\
"""AgentHalt — Minimal Quickstart (copy-paste this!)"""
import asyncio
from agenthalt import (
    PolicyEngine, CallContext,
    BudgetGuard, BudgetConfig,
    RateLimitGuard, RateLimitConfig,
    ScopeGuard, ScopeConfig,
)

async def main():
    # 1. Create engine and add guards
    engine = PolicyEngine()
    engine.add_guard(BudgetGuard(BudgetConfig(
        max_daily_spend=10.0,
        cost_estimator={"gpt4_call": 0.03, "web_search": 0.01},
    )))
    engine.add_guard(RateLimitGuard(RateLimitConfig(
        max_calls_per_minute=30,
        max_identical_calls=3,
    )))
    engine.add_guard(ScopeGuard(ScopeConfig(
        deny_functions=["drop_*", "format_*", "shutdown_*"],
    )))

    # 2. Evaluate a function call
    result = await engine.evaluate(CallContext(
        function_name="gpt4_call",
        arguments={"prompt": "Summarize this document"},
        agent_id="my_agent",
        session_id="session_1",
    ))

    if result.is_allowed:
        print(f"✅ Allowed: {result.final_decision.reason}")
    elif result.is_denied:
        print(f"❌ Denied: {result.denial_reasons}")
    elif result.needs_approval:
        print(f"⏳ Needs approval: {result.final_decision.reason}")

    # 3. Try a blocked call
    result = await engine.evaluate(CallContext(
        function_name="drop_table",
        arguments={"table": "users"},
    ))
    print(f"❌ drop_table: {result.final_decision.reason}")

asyncio.run(main())
'''


def cmd_quickstart() -> None:
    print_banner()
    print("# Copy-paste this into a Python file and run it:\n")
    print(QUICKSTART_CODE)


def cmd_version() -> None:
    from agenthalt import __version__

    print(f"agenthalt {__version__}")


def cmd_demo() -> None:
    print_banner()
    try:
        import importlib

        importlib.import_module("fastapi")
        importlib.import_module("uvicorn")
    except ImportError:
        print("Dashboard extras required. Install with:")
        print("  pip install agenthalt[dashboard]")
        print("\nOr run without dashboard:")
        print("  pip install agenthalt")
        print("  python -m agenthalt quickstart")
        sys.exit(1)

    print("Starting live demo with dashboard at http://localhost:8550 ...")
    print("Press Ctrl+C to stop.\n")

    import os
    import subprocess

    # Find the examples/live_demo.py relative to the package
    pkg_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    demo_path = os.path.join(pkg_dir, "examples", "live_demo.py")

    if os.path.exists(demo_path):
        subprocess.run([sys.executable, demo_path])
    else:
        print("Demo script not found. If installed from PyPI, clone the repo:")
        print("  git clone https://github.com/HZYAI/agenthalt.git")
        print("  cd agenthalt")
        print("  pip install -e '.[dashboard]'")
        print("  python examples/live_demo.py")


def cmd_check(filepath: str) -> None:
    print_banner()
    try:
        from agenthalt.config import load_config

        engine = load_config(filepath)
        guards = engine.guards
        print(f"✅ Config valid: {filepath}")
        print(f"   Guards loaded: {len(guards)}")
        for g in guards:
            status = "enabled" if g.enabled else "disabled"
            print(f"   - {g.name} ({status})")
    except FileNotFoundError:
        print(f"❌ File not found: {filepath}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Config error: {e}")
        sys.exit(1)


def main() -> None:
    args = sys.argv[1:]

    if not args:
        print_help()
    elif args[0] == "--version":
        cmd_version()
    elif args[0] == "--help" or args[0] == "-h":
        print_help()
    elif args[0] == "quickstart":
        cmd_quickstart()
    elif args[0] == "demo":
        cmd_demo()
    elif args[0] == "check":
        if len(args) < 2:
            print("Usage: python -m agenthalt check <config.yaml>")
            sys.exit(1)
        cmd_check(args[1])
    else:
        print(f"Unknown command: {args[0]}")
        print("Run 'python -m agenthalt --help' for usage.")
        sys.exit(1)


if __name__ == "__main__":
    main()
