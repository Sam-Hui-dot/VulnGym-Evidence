import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('claim_evaluation', Path(__file__).resolve().parents[1] / 'scripts/evaluate_claims.py')
evaluation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluation)


class EvaluationMetricsTests(unittest.TestCase):
    def test_abstaining_on_everything_does_not_count_as_coverage(self):
        rows = [{'expected': value, 'prediction': 'uncertain'} for value in ('supported', 'contradicted', 'uncertain')]
        result = evaluation.metrics(rows)
        self.assertEqual(result['n'], 3)
        self.assertEqual(result['correct'], 1)
        self.assertEqual(result['decisive'], 0)
        self.assertEqual(result['abstentions'], 3)

    def test_model_failure_is_not_a_correct_uncertain(self):
        result = evaluation.metrics([{'expected':'uncertain','prediction':'error'}])
        self.assertEqual(result['n'], 1)
        self.assertEqual(result['correct'], 0)
        self.assertEqual(result['errors'], 1)
        self.assertEqual(result['abstentions'], 0)

    def test_false_accept_denominator_and_unknown_overreach_are_separate(self):
        rows = [{'expected':'contradicted','prediction':'supported'},
                {'expected':'contradicted','prediction':'uncertain'},
                {'expected':'uncertain','prediction':'supported'},
                {'expected':'supported','prediction':'contradicted'}]
        result = evaluation.metrics(rows)
        self.assertEqual(result['false_accepts'], 1)
        self.assertEqual(result['contradicted_references'], 2)
        self.assertEqual(result['unsupported_decisions'], 1)
        self.assertEqual(result['wrong_rejections'], 1)


if __name__ == '__main__':
    unittest.main()
