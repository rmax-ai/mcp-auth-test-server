"""Policy enforcement for MCP tool dispatch.

Provides scope-based access control and argument validation
that runs before tool handlers are invoked.
"""

from __future__ import annotations

from typing import Any

# NOTE: base.py is imported lazily inside functions to avoid a
# circular dependency: base → policy → base.


def parse_scope_set(scope: str) -> set[str]:
    """Split a space-delimited scope string into a set of individual scopes."""
    return set(scope.split())


def check_tool_scope(
    tool: Any,  # ToolDefinition — lazy import avoids circular dep
    token_scope: str | None,
    *,
    method: str = "tools/call",
) -> None:
    """Raise JsonRpcError if the token lacks the scope required for a tool.

    When *token_scope* is ``None`` the check is skipped (unauthenticated
    endpoints such as ``/mcp/no-auth`` are allowed through).
    """
    from mcp_auth_test_server.mcp.base import JsonRpcError

    if token_scope is None:
        return
    if not tool.required_scope:
        return

    token_scopes = parse_scope_set(token_scope)
    if tool.required_scope not in token_scopes:
        raise JsonRpcError(
            code=-32001,
            message="Insufficient scope",
            data={
                "required_scope": tool.required_scope,
                "token_scope": token_scope,
                "tool": tool.name,
                "method": method,
            },
        )


def check_argument_policy(
    policy: Any,  # ToolArgumentPolicy — lazy import avoids circular dep
    arguments: dict[str, object],
    *,
    tool_name: str,
) -> None:
    """Raise JsonRpcError when argument validation rules are violated."""
    from mcp_auth_test_server.mcp.base import JsonRpcError

    # ── Required parameters ──────────────────────────────────────────────
    for param in policy.required_params:
        if param not in arguments:
            raise JsonRpcError(
                code=-32002,
                message="Policy denied",
                data={
                    "reason": f"required parameter '{param}' is missing",
                    "tool": tool_name,
                },
            )

    # ── Constraint checks ────────────────────────────────────────────────
    for constraint in policy.constraints:
        value = arguments.get(constraint.param)
        if value is None:
            continue

        if constraint.constraint_type == "max_length":
            if isinstance(value, str) and len(value) > constraint.value:
                raise JsonRpcError(
                    code=-32002,
                    message="Policy denied",
                    data={
                        "reason": (
                            f"parameter '{constraint.param}' exceeds "
                            f"max length {constraint.value}"
                        ),
                        "tool": tool_name,
                    },
                )

        elif constraint.constraint_type == "min_length":
            if isinstance(value, str) and len(value) < constraint.value:
                raise JsonRpcError(
                    code=-32002,
                    message="Policy denied",
                    data={
                        "reason": (
                            f"parameter '{constraint.param}' is below "
                            f"min length {constraint.value}"
                        ),
                        "tool": tool_name,
                    },
                )

        elif constraint.constraint_type == "equals":
            if value != constraint.value:
                raise JsonRpcError(
                    code=-32002,
                    message="Policy denied",
                    data={
                        "reason": (
                            f"parameter '{constraint.param}' must equal "
                            f"{constraint.value!r}"
                        ),
                        "tool": tool_name,
                    },
                )

        elif constraint.constraint_type == "pattern":
            if isinstance(value, str) and constraint.value not in value:
                raise JsonRpcError(
                    code=-32002,
                    message="Policy denied",
                    data={
                        "reason": (
                            f"parameter '{constraint.param}' must match "
                            f"pattern {constraint.value!r}"
                        ),
                        "tool": tool_name,
                    },
                )

    # ── Blocked content patterns ─────────────────────────────────────────
    for param, value in arguments.items():
        if isinstance(value, str):
            for pattern in policy.blocked_patterns:
                if pattern in value:
                    raise JsonRpcError(
                        code=-32002,
                        message="Policy denied",
                        data={
                            "reason": (
                                f"parameter '{param}' contains blocked "
                                f"pattern {pattern!r}"
                            ),
                            "tool": tool_name,
                        },
                    )

    # ── Environment flag ─────────────────────────────────────────────────
    if policy.environment_flag is not None:
        import os  # noqa: PLC0415 — lazy import for env-flag-only check

        if not os.environ.get(policy.environment_flag):
            raise JsonRpcError(
                code=-32002,
                message="Policy denied",
                data={
                    "reason": (
                        f"environment variable {policy.environment_flag} "
                        "must be set"
                    ),
                    "tool": tool_name,
                },
            )


def filter_tools_by_scope(
    tools: dict[str, Any],  # dict[str, ToolDefinition]
    token_scope: str | None,
) -> list[Any]:  # list[ToolDefinition]
    """Return only the tools that the given token scope permits.

    When *token_scope* is ``None`` all tools are returned
    (unauthenticated bypass).
    """
    if token_scope is None:
        return list(tools.values())

    token_scopes = parse_scope_set(token_scope)
    return [
        tool
        for tool in tools.values()
        if not tool.required_scope or tool.required_scope in token_scopes
    ]
