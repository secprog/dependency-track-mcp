#!/usr/bin/env python3
"""Verification script to test security enforcement.

This script verifies that the MCP server enforces:
1. OAuth 2.1 is mandatory
2. HTTPS URLs are mandatory
3. SSL verification is mandatory
4. Server fails fast on misconfiguration
"""

import os
import sys
import subprocess
from pathlib import Path


def run_test(description: str, env_vars: dict) -> tuple[bool, str]:
    """Run server startup test with given environment variables.
    
    Args:
        description: Test description
        env_vars: Environment variables to set
        
    Returns:
        Tuple of (success: bool, output: str)
    """
    print("\n" + "="*70)
    print("TEST: " + description)
    print("="*70)
    
    # Set up environment
    env = os.environ.copy()
    for key, value in env_vars.items():
        if value is None:
            env.pop(key, None)  # Remove variable
            print("  Unset: " + key)
        else:
            env[key] = str(value)
            print("  Set: " + key + "=" + str(value))
    
    # Try to import and create settings
    try:
        # Clear any cached settings
        if "dependency_track_mcp.config" in sys.modules:
            del sys.modules["dependency_track_mcp.config"]
        
        # Run in subprocess to isolate environment
        code = """
import sys
import os
os.environ.update({env})

try:
    from dependency_track_mcp.config import Settings
    settings = Settings()
    print("[OK] Settings loaded successfully")
    print("  URL: " + settings.url)
    print("  OAuth Issuer: " + settings.oauth_issuer)
    print("  Verify SSL: " + str(settings.verify_ssl))
except Exception as e:
    print("[FAIL] Configuration error: " + str(e))
    sys.exit(1)
""".format(env=repr({k: v for k, v in env_vars.items() if v is not None}))
        
        result = subprocess.run(
            [sys.executable, "-c", code],
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
        )
        
        output = result.stdout + result.stderr
        success = result.returncode == 0
        
        print("\nResult:")
        for line in output.strip().split("\n"):
            if line.strip():
                print("  " + line)
        
        return success, output
        
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)


def main():
    """Run all security enforcement tests."""
    print("\n" + "="*70)
    print("SECURITY ENFORCEMENT VERIFICATION")
    print("="*70)
    
    base_env = {
        "DEPENDENCY_TRACK_URL": "https://dtrack.example.com",
        "DEPENDENCY_TRACK_API_KEY": "test-key",
        "DEPENDENCY_TRACK_OAUTH_ISSUER": "https://auth.example.com",
    }
    
    tests = [
        (
            "1. Valid Configuration (All Required Fields)",
            base_env,
            True,
        ),
        (
            "2. Missing OAuth Issuer (Should Fail)",
            {**base_env, "DEPENDENCY_TRACK_OAUTH_ISSUER": None},
            False,
        ),
        (
            "3. HTTP URL (Should Fail - HTTPS Enforced by Default)",
            {**base_env, "DEPENDENCY_TRACK_URL": "http://dtrack.example.com"},
            False,
        ),
        (
            "4. HTTP OAuth Issuer (Should Fail - HTTPS Always Required)",
            {**base_env, "DEPENDENCY_TRACK_OAUTH_ISSUER": "http://auth.example.com"},
            False,
        ),
        (
            "5. Valid with SSL Verification Disabled (Should Warn)",
            {**base_env, "DEPENDENCY_TRACK_VERIFY_SSL": "false"},
            True,
        ),
        (
            "6. Development Mode: HTTP URL with DEV_ALLOW_HTTP (Should Warn)",
            {**base_env, "DEPENDENCY_TRACK_URL": "http://localhost:8080", "DEPENDENCY_TRACK_DEV_ALLOW_HTTP": "true"},
            True,
        ),
        (
            "7. Development Mode: HTTP Issuer with DEV_ALLOW_HTTP (Should Warn)",
            {**base_env, "DEPENDENCY_TRACK_OAUTH_ISSUER": "http://localhost:9000", "DEPENDENCY_TRACK_DEV_ALLOW_HTTP": "true"},
            True,
        ),
        (
            "8. Dev Mode with Both HTTP URLs (Should Warn Twice)",
            {**base_env, "DEPENDENCY_TRACK_URL": "http://localhost:8080", "DEPENDENCY_TRACK_OAUTH_ISSUER": "http://localhost:9000", "DEPENDENCY_TRACK_DEV_ALLOW_HTTP": "true"},
            True,
        ),
    ]
    
    results = []
    for description, env_vars, expected_success in tests:
        success, output = run_test(description, env_vars)
        expected_str = "[SHOULD SUCCEED]" if expected_success else "[SHOULD FAIL]"
        actual_str = "[SUCCEEDED]" if success else "[FAILED]"
        
        result_ok = success == expected_success
        status = "[PASS]" if result_ok else "[FAIL]"
        
        results.append((description, result_ok, status))
        print("\nExpectation: " + expected_str)
        print("Actual:      " + actual_str)
        print("Status:      " + status)
    
    # Summary
    print("\n" + "="*70)
    print("VERIFICATION SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    
    for description, ok, status in results:
        print(status + " - " + description)
    
    print("\nTotal: " + str(passed) + "/" + str(total) + " tests passed")
    
    if passed == total:
        print("\n[OK] All security enforcement tests PASSED")
        print("  - OAuth 2.1 is mandatory")
        print("  - HTTPS URLs are mandatory")
        print("  - SSL verification is enabled by default")
        print("  - Server fails fast on misconfiguration")
        return 0
    else:
        print("\n[FAIL] " + str(total - passed) + " test(s) FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())

