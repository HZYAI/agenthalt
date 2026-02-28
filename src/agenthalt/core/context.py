"""Call context — carries metadata about the function call being evaluated."""

from __future__ import annotations

import time
import uuid
from typing import Any

from pydantic import BaseModel, Field


class CallContext(BaseModel):
    """Immutable snapshot of an agent function call to be evaluated by guards.

    Attributes:
        call_id: Unique identifier for this call.
        function_name: Name of the function/tool being invoked.
        arguments: Dictionary of arguments passed to the function.
        agent_id: Optional identifier for the calling agent.
        session_id: Optional session/conversation identifier.
        timestamp: Unix timestamp of when the call was initiated.
        metadata: Arbitrary extra metadata for custom guards.
    """

    call_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    function_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    agent_id: str | None = None
    session_id: str | None = None
    timestamp: float = Field(default_factory=time.time)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}
