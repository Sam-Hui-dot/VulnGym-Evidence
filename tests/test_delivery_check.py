from __future__ import annotations

import unittest

from scripts.verify_delivery import (
    check_blind_v3_result,
    check_blind_v6_result,
    check_demo_artifact,
    check_post_v3_targeted_result,
    check_post_v6_provenance_result,
    check_required_paths,
    check_systemic_analysis_artifact,
)


class DeliveryCheckTests(unittest.TestCase):
    def test_required_delivery_files_exist(self) -> None:
        self.assertEqual(check_required_paths(), [])

    def test_blind_v3_result_is_retained(self) -> None:
        self.assertEqual(check_blind_v3_result(), [])

    def test_post_v3_targeted_result_is_disclosed(self) -> None:
        self.assertEqual(check_post_v3_targeted_result(), [])

    def test_fixed_demo_artifact_is_valid(self) -> None:
        self.assertEqual(check_demo_artifact(), [])

    def test_systemic_analysis_is_reproducible(self) -> None:
        self.assertEqual(check_systemic_analysis_artifact(), [])

    def test_blind_v6_result_and_repro_are_verified(self) -> None:
        self.assertEqual(check_blind_v6_result(), [])

    def test_post_v6_provenance_replay_is_reproducible(self) -> None:
        self.assertEqual(check_post_v6_provenance_result(), [])


if __name__ == "__main__":
    unittest.main()
