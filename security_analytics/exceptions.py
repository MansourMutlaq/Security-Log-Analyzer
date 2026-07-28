"""Project-specific exception hierarchy."""


class SecurityAnalyticsError(Exception):
    """Base exception for the security analytics platform."""


class LogParseError(SecurityAnalyticsError):
    """Raised when a raw log entry cannot be parsed safely."""


class ConfigurationError(SecurityAnalyticsError):
    """Raised when project configuration is missing or invalid."""


class DetectionError(SecurityAnalyticsError):
    """Raised when detection or correlation processing fails."""


class ExportError(SecurityAnalyticsError):
    """Raised when reports or external exports cannot be generated."""