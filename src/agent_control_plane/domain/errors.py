"""Domain errors mapped to HTTP status codes and OAuth-style bodies by the API layer."""

from __future__ import annotations


class ControlPlaneError(Exception):
    code = "invalid_request"
    status = 400

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NotFoundError(ControlPlaneError):
    code = "not_found"
    status = 404


class ConflictError(ControlPlaneError):
    code = "conflict"
    status = 409


class InvalidStateError(ControlPlaneError):
    code = "invalid_state"
    status = 409


class UnauthorizedError(ControlPlaneError):
    code = "unauthorized"
    status = 401


class ForbiddenError(ControlPlaneError):
    code = "forbidden"
    status = 403


class UnsafeContentError(ControlPlaneError):
    code = "unsafe_content"
    status = 422


class DependencyError(ControlPlaneError):
    """A downstream system (identity fabric, Kubernetes API) failed; the caller may retry."""

    code = "dependency_unavailable"
    status = 503


class ApprovalRequiredError(ForbiddenError):
    """Policy requires a human approval this action has no workflow for; nothing was done."""

    code = "approval_required"
