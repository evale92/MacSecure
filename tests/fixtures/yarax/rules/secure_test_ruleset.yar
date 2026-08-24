/*
 * secure_test_ruleset.yar — synthetic, deterministic fixture ruleset
 * for Secure's own test suite (tests/test_integrations_yarax.py).
 *
 * NOT a real detection rule and NOT bundled with the application at
 * runtime (see secure/integrations/yarax/rulesets.py's module
 * docstring — Secure ships no default rulesets). Deliberately matches
 * synthetic marker strings that will never appear in a real file,
 * rather than any real malware signature (e.g. EICAR), so this fixture
 * is safe to keep on disk without tripping any real antivirus/security
 * tooling on a machine that checks out this repository.
 */

rule secure_test_marker_high
{
    meta:
        description = "Secure test fixture rule — deliberately declares severity=high"
        author = "Secure test suite"
        severity = "high"
    strings:
        $marker = "SECURE_TEST_MARKER_HIGH"
    condition:
        $marker
}

rule secure_test_marker_default
{
    meta:
        description = "Secure test fixture rule — deliberately declares no severity metadata"
    strings:
        $marker = "SECURE_TEST_MARKER_DEFAULT"
    condition:
        $marker
}
