import unittest

from src.ad_posture import DirectoryObject, assess_directory, assess_object, posture_score


class ADPostureTests(unittest.TestCase):
    def test_privileged_without_mfa_is_critical(self):
        obj = DirectoryObject("adm-test", "user", privileged=True, mfa_required=False, owner="IAM")
        findings = assess_object(obj)
        self.assertTrue(any(f.control_id == "AD-001" and f.severity == "critical" for f in findings))

    def test_unconstrained_delegation_is_critical(self):
        obj = DirectoryObject("APP01$", "computer", unconstrained_delegation=True, owner="Platform")
        findings = assess_object(obj)
        self.assertTrue(any(f.control_id == "AD-003" for f in findings))

    def test_stale_non_privileged_object_is_medium(self):
        obj = DirectoryObject("legacy-user", "user", stale_days=120, owner="HR")
        finding = next(f for f in assess_object(obj) if f.control_id == "AD-005")
        self.assertEqual(finding.severity, "medium")

    def test_stale_privileged_object_is_high(self):
        obj = DirectoryObject("old-admin", "user", privileged=True, stale_days=120, owner="IAM")
        finding = next(f for f in assess_object(obj) if f.control_id == "AD-005")
        self.assertEqual(finding.severity, "high")

    def test_missing_owner_is_low(self):
        obj = DirectoryObject("svc-orphan", "service_account")
        self.assertTrue(any(f.control_id == "AD-006" for f in assess_object(obj)))

    def test_duplicate_names_are_rejected_case_insensitively(self):
        objects = [DirectoryObject("Alice", "user"), DirectoryObject("alice", "user")]
        with self.assertRaises(ValueError):
            assess_directory(objects)

    def test_negative_stale_days_is_invalid(self):
        with self.assertRaises(ValueError):
            DirectoryObject("bad", "user", stale_days=-1)

    def test_posture_score_is_bounded(self):
        objects = [
            DirectoryObject(f"admin-{i}", "user", privileged=True, mfa_required=False, unconstrained_delegation=True)
            for i in range(4)
        ]
        score = posture_score(assess_directory(objects))
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)


if __name__ == "__main__":
    unittest.main()
