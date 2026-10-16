"""OSIRIS primary view widgets package."""

from __future__ import annotations

from desktop.ui.views.events_view import (
    STATE_EMPTY,
    STATE_FAILED,
    STATE_LOADED,
    STATE_LOADING,
    STATE_NOT_LOADED,
    EventsQuery,
    EventsView,
)
from desktop.ui.views.files_view import FilesQuery, FilesView
from desktop.ui.views.processes_view import ProcessesQuery, ProcessesView
from desktop.ui.views.resources_view import (
    ResourcesFilterBar,
    ResourcesPaginationBar,
    ResourcesQuery,
    ResourcesView,
)

__all__ = [
    "EventsQuery",
    "EventsView",
    "FilesQuery",
    "FilesView",
    "ProcessesQuery",
    "ProcessesView",
    "ResourcesFilterBar",
    "ResourcesPaginationBar",
    "ResourcesQuery",
    "ResourcesView",
    "STATE_EMPTY",
    "STATE_FAILED",
    "STATE_LOADED",
    "STATE_LOADING",
    "STATE_NOT_LOADED",
]
