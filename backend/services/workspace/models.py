"""Exceptions and domain constants for Workspace and Analytics services."""

from __future__ import annotations


class WorkspaceError(Exception):
    """Base exception for workspace operations."""


class WorkspaceNotFoundError(WorkspaceError):
    """Raised when a requested workspace does not exist."""


class WorkspacePermissionError(WorkspaceError):
    """Raised when an analyst attempts an unauthorized operation on a workspace."""


class TagError(Exception):
    """Base exception for evidence tag operations."""


class TagNotFoundError(TagError):
    """Raised when an evidence tag is not found."""


class TagDuplicateError(TagError):
    """Raised when attempting to create a tag with an already existing name."""


class TagAssociationDuplicateError(TagError):
    """Raised when an evidence item is already tagged with the specified tag."""


class AnnotationNotFoundError(Exception):
    """Raised when an evidence annotation note is not found."""


class HostIsolationError(Exception):
    """Raised when an entity or evidence violates host boundary isolation."""
