"""Command-line interface and argument parsing for fivenines agent."""

import argparse
from importlib.metadata import PackageNotFoundError, version

# Single source of truth for the version is pyproject.toml; importlib.metadata
# reads it back from the installed distribution's metadata so this stays in sync
# automatically. The PyInstaller binary bundles that metadata via
# `--copy-metadata fivenines_agent` in py2exe.sh (whose --version smoke check
# aborts the build if it is missing). The fallback only applies when running
# from a source tree with no installed distribution metadata.
try:
    VERSION = version('fivenines_agent')
except PackageNotFoundError:  # pragma: no cover - only hit in uninstalled source trees
    VERSION = '0.0.0+unknown'

# Global args storage (set by parse_args)
_args = None


def parse_args():
    """Parse command-line arguments. Handles --version and --dry-run."""
    global _args
    parser = argparse.ArgumentParser(description='Fivenines monitoring agent')
    parser.add_argument('--version', action='version', version=f'fivenines-agent {VERSION}')
    parser.add_argument('--dry-run', action='store_true', help='Run once and print output without sending data')
    _args = parser.parse_args()
    return _args


def get_args():
    """Get parsed arguments. Returns None if parse_args() hasn't been called."""
    return _args
