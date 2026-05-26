import sys
import traceback

from threat_actor_enrichment import ThreatActorEnrichment

if __name__ == "__main__":
    """
    Entry point of the script

    - traceback.print_exc(): prints the traceback of the exception to stderr.
      The traceback includes the program location where the exception
      occurred, which is useful for debugging.
    - sys.exit(1): terminates the program with a non-zero exit code so the
      orchestrator (Docker / systemd / Kubernetes) can detect the failure
      and restart the container. ``sys.exit`` is preferred over the builtin
      ``exit`` because the builtin is injected by ``site`` and is intended
      mainly for interactive use; ``sys.exit`` is guaranteed to be present
      in any runtime environment.
    """
    try:
        connector = ThreatActorEnrichment()
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
