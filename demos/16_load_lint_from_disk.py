"""Scenario 16 - ops: author, write, load, and lint a policy from disk.

The whole point of "policy as data" is that the file is the source of truth.
This demo writes a policy to a temp file, loads it with `load_policy`, lints it,
evaluates a directive against it - then writes a *broken* version and shows
`load_policy` raising a clear `PolicyError` instead of a traceback. No fixtures,
no network; cleans up after itself.
"""
import json
import os
import tempfile

from _common import banner
from sentinel_policy import Effect, PolicyError, load_policy


GOOD = {
    "version": 1, "name": "disk-policy", "default": "deny",
    "rules": [
        {"id": "allow-read", "doctrine": "S2", "effect": "allow",
         "match": {"action": "read.*"}},
        {"id": "gate-prod-deploy", "doctrine": "S3", "effect": "require_approval",
         "tier": "high", "match": {"action": "deploy", "params.env": "prod"}},
    ],
}


def main() -> None:
    banner("LOAD & LINT FROM DISK  -  the file is the source of truth")

    tmp = tempfile.mkdtemp(prefix="sentinel-demo-")
    good_path = os.path.join(tmp, "policy.json")
    bad_path = os.path.join(tmp, "broken.json")
    try:
        with open(good_path, "w", encoding="utf-8") as fh:
            json.dump(GOOD, fh, indent=2)

        policy = load_policy(good_path)
        print(f"\nLoaded '{policy.name}' from {os.path.basename(good_path)}: "
              f"{len(policy.rules)} rules.")
        print(f"Lint: {'OK (clean)' if policy.validate() == [] else 'INVALID'}")

        d = policy.evaluate({"action": "deploy", "params": {"env": "prod"}})
        print(f"Eval deploy/prod -> {d.effect.value} [{d.doctrine}] rule={d.rule}")
        assert d.effect is Effect.REQUIRE_APPROVAL

        # now corrupt the file and show a clean load-time failure
        with open(bad_path, "w", encoding="utf-8") as fh:
            fh.write('{ "name": "broken", "rules": [ { "id": "x" } ] }')
        try:
            load_policy(bad_path)
        except PolicyError as exc:
            print(f"\nLoading the broken file failed cleanly:\n  PolicyError: {exc}")
        else:
            raise AssertionError("broken policy should not load")
    finally:
        for p in (good_path, bad_path):
            if os.path.exists(p):
                os.remove(p)
        os.rmdir(tmp)

    print("\nThe good policy round-tripped through disk; the broken one was")
    print("rejected at load time with a message you can fix from.")


if __name__ == "__main__":
    main()
