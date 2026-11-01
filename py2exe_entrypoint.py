# PyInstaller entry script. It runs the same start() as the `fivenines_agent`
# console script and `python -m fivenines_agent`, so --version stays fast in the
# frozen binary too (start() imports the agent only after parsing the command
# line). PyInstaller still collects the agent: its import analysis follows the
# function-level import, and the build's --check-imports smoke check fails the
# build if it ever does not.
from fivenines_agent.__main__ import start

start()
