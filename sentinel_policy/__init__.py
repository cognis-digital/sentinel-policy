"""sentinel-policy — an open governance doctrine and a policy-gate engine for AI agents.

Two things ship here:

  1. The SENTINEL doctrine: seven plainly-stated rules for governing what an
     autonomous agent is allowed to do in a high-stakes environment. The
     doctrine is published openly (Apache-2.0) so a buyer can argue with the
     rules on their merits rather than guess what "responsible AI" means.

  2. A reference engine that turns a file-backed policy into allow / deny /
     require-approval decisions, each tagged with the doctrine rule it serves.
     The engine is decision-only and dependency-free, and its Decision objects
     are drop-in for agentledger's policy-gate hook.
"""

from .doctrine import DOCTRINE, Rule, rule
from .policy import Decision, Effect, Policy, PolicyError, load_policy

__version__ = "0.1.0"
__all__ = [
    "DOCTRINE", "Rule", "rule",
    "Policy", "Decision", "Effect", "PolicyError", "load_policy",
    "__version__",
]
