import unittest

from src.remediation_validator import RemediationEvidence, validate_batch, validate_remediation


class RemediationValidatorTests(unittest.TestCase):
    def evidence(self, **overrides):
        base = dict(
            finding_id="AD-001-demo", state="ready_for_validation", owner="Identity Engineering",
            change_reference="CHG-SYN-1001", before_value="MFA optional", after_value="MFA required",
            validation_method="fresh authentication telemetry", evidence_complete=True, control_effective=True,
        )
        base.update(overrides)
        return RemediationEvidence(**base)

    def test_complete_evidence_validates(self):
        self.assertEqual(validate_remediation(self.evidence()).status, "validated")

    def test_closed_unchanged_control_is_invalid(self):
        result = validate_remediation(self.evidence(state="closed", after_value="MFA optional"))
        self.assertEqual(result.status, "invalid_closure")

    def test_incomplete_evidence_needs_evidence(self):
        self.assertEqual(validate_remediation(self.evidence(evidence_complete=False)).status, "needs_evidence")

    def test_ineffective_control_needs_evidence(self):
        self.assertEqual(validate_remediation(self.evidence(control_effective=False)).status, "needs_evidence")

    def test_missing_owner_is_rejected_for_closure(self):
        self.assertEqual(validate_remediation(self.evidence(state="closed", owner="")).status, "invalid_closure")

    def test_missing_change_reference_blocks_validation(self):
        self.assertNotEqual(validate_remediation(self.evidence(change_reference="")).status, "validated")

    def test_open_complete_item_is_ready_not_closed(self):
        self.assertEqual(validate_remediation(self.evidence(state="open")).status, "ready_for_validation")

    def test_duplicate_findings_fail_closed(self):
        with self.assertRaises(ValueError):
            validate_batch([self.evidence(), self.evidence()])

    def test_from_dict_rejects_unknown_state(self):
        raw = self.evidence().__dict__.copy()
        raw["state"] = "waived"
        with self.assertRaises(ValueError):
            RemediationEvidence.from_dict(raw)

    def test_validation_id_is_deterministic(self):
        a = validate_remediation(self.evidence())
        b = validate_remediation(self.evidence())
        self.assertEqual(a.validation_id, b.validation_id)


if __name__ == "__main__":
    unittest.main()
