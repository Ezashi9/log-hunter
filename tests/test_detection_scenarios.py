import unittest

from detection_tests.run import evaluate


class DetectionScenarioTests(unittest.TestCase):
    def test_every_scenario_raises_exactly_the_expected_alerts(self):
        for r in evaluate():
            with self.subTest(scenario=r["scenario"].name):
                self.assertTrue(r["events"] > 0, "scenario lines must parse")
                self.assertEqual(r["missed"], set(), "missed detections")
                self.assertEqual(r["false_positives"], set(), "false alarms")


if __name__ == "__main__":
    unittest.main()
