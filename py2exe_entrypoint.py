from fivenines_agent.cli import parse_args
from fivenines_agent.agent import Agent

# Parse args first (handles --version and exits)
parse_args()

agent = Agent()
agent.run()
