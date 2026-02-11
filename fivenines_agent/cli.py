"""Command-line interface and argument parsing for fivenines agent."""

import argparse

VERSION = '1.5.3'

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
