import unittest
from datetime import datetime, timezone

from src.identity_risk import AuthEvent, assess_identity_events, portfolio_metrics


class IdentityRiskTests(unittest.TestCase):
    def event(self, **overrides):
        base = dict(event_id="1", timestamp=datetime(2026, 9, 10, tzinfo=timezone.utc), principal="user1",
                    event_type="logon_success", source="10.0.0.1", success=True)
        base.update(overrides)
        return AuthEvent(**base)

    def test_repeated_failures_create_finding(self):
        events = [self.event(event_id=str(i), event_type="logon_failure", success=False) for i in range(5)]
        self.assertEqual(assess_identity_events(events)[0].rule_id, "ID-101")

    def test_unknown_context_success_is_high_risk(self):
        findings = assess_identity_events([self.event(known_device=False)])
        self.assertEqual(findings[0].rule_id, "ID-102")

    def test_privileged_without_mfa_is_critical(self):
        findings = assess_identity_events([self.event(privileged=True, mfa_satisfied=False)])
        self.assertEqual(findings[0].risk_level, "critical")

    def test_compliant_success_has_no_findings(self):
        self.assertEqual(assess_identity_events([self.event(mfa_satisfied=True)]), [])

    def test_duplicate_event_ids_fail_closed(self):
        with self.assertRaises(ValueError):
            assess_identity_events([self.event(), self.event()])

    def test_from_dict_requires_timezone(self):
        with self.assertRaises(ValueError):
            AuthEvent.from_dict({"event_id":"x","timestamp":"2026-09-10T10:00:00","principal":"u","event_type":"logon_success","source":"s","success":True})

    def test_from_dict_rejects_unknown_event_type(self):
        with self.assertRaises(ValueError):
            AuthEvent.from_dict({"event_id":"x","timestamp":"2026-09-10T10:00:00Z","principal":"u","event_type":"other","source":"s","success":True})

    def test_finding_ids_are_deterministic(self):
        events = [self.event(event_id=str(i), event_type="logon_failure", success=False) for i in range(5)]
        self.assertEqual(assess_identity_events(events)[0].finding_id, assess_identity_events(events)[0].finding_id)

    def test_metrics_count_principals(self):
        findings = assess_identity_events([self.event(privileged=True, mfa_satisfied=False)])
        self.assertEqual(portfolio_metrics(findings)["principals_at_risk"], 1)

    def test_score_is_bounded(self):
        events = [self.event(event_id=str(i), event_type="logon_failure", success=False) for i in range(100)]
        self.assertLessEqual(assess_identity_events(events)[0].score, 100)


if __name__ == "__main__":
    unittest.main()
