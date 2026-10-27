#!/usr/bin/env python3
"""Administrator CLI contract in a fresh private state; issues no OAuth code/token."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    binary = os.path.abspath(sys.argv[1])
    environment = "11111111-1111-4111-8111-111111111111"
    with tempfile.TemporaryDirectory(prefix="omabridge-managed-cli-") as root:
        os.chmod(root, 0o700)

        def call(*args, success=True):
            result = subprocess.run([binary, "--state-dir", root, "mcp", *args],
                                    capture_output=True, text=True)
            assert (result.returncode == 0) == success, (args, result.stderr)
            return json.loads(result.stdout) if success else None

        call("policy-create", "--policy", "selection", "--access", "operate")
        before = call("policy-show", "--policy", "selection")["selection"]
        assert before["environments"] == {}
        # No implicit whole-project/session grant from an omitted option.
        call("policy-allow", "--policy", "selection", "--environment", environment,
             "--project", "p1", success=False)
        call("policy-allow", "--policy", "selection", "--environment", environment,
             "--project", "p1", "--session", "s1", "--all-sessions", success=False)
        call("policy-allow", "--policy", "selection", "--environment", environment,
             "--project", "p1", "--session", "s1", "--session", "s2")
        first = call("policy-show", "--policy", "selection")["selection"]
        assert first["environments"][environment]["p1"] == ["s1", "s2"]
        assert first["revision"] != before["revision"]
        call("policy-allow", "--policy", "selection", "--environment", environment,
             "--project", "p2", "--all-sessions")
        assert call("policy-show", "--policy", "selection")["selection"]["environments"][environment]["p2"] is None
        call("policy-remove", "--policy", "selection", "--environment", environment,
             "--project", "p1")
        assert list(call("policy-show", "--policy", "selection")["selection"]["environments"][environment]) == ["p2"]
        call("policy-remove", "--policy", "selection", "--environment", environment)
        assert call("policy-show", "--policy", "selection")["selection"]["environments"] == {}
        # Invalid consent combinations fail before any code can be issued.
        call("grant", "--managed-catalog", "selection", "--project", "p1", success=False)
        call("grant", "--managed-catalog", "selection", "--environment", environment, success=False)
        call("grant", "--managed-catalog", "missing-policy", success=False)
        assert call("grants")["grants"] == []
        assert (Path(root) / "mcp/managed-policies.json").stat().st_mode & 0o777 == 0o600
    print(json.dumps({"managed_policy_cli": "passed", "oauth_codes_issued": 0,
                      "production_state_used": False}))


if __name__ == "__main__":
    main()
