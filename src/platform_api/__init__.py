"""Platform / Integration thin boundary for the P0 demo."""

from .app import create_app
from .container import PlatformContainer

__all__ = ["PlatformContainer", "create_app"]
