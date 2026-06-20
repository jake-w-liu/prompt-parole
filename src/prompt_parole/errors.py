class PromptParoleError(Exception):
    """Base exception for user-facing Prompt Parole failures."""


class NotConfiguredError(PromptParoleError):
    """Raised when setup has not been completed."""


class PasswordError(PromptParoleError):
    """Raised when password validation fails."""


class ConfigError(PromptParoleError):
    """Raised for invalid configuration."""
