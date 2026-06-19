"""Guardrails: human-in-the-loop gates, no legal/strategic decisions."""

def require_human_approval(action: str) -> bool:
    # In real impl this would prompt/block
    print(f"Human approval required for: {action}")
    return True  # simulated
