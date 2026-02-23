"""
test_ml_classifier.py - Unit tests for the ML exploitability classifier.
"""

import sys
import json
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "ml"))

from exploitability_classifier import (
    generate_synthetic_dataset,
    engineer_features,
    train_and_evaluate,
)


class TestDataGeneration(unittest.TestCase):
    def test_generates_correct_number_of_samples(self):
        df = generate_synthetic_dataset(n_samples=100)
        self.assertEqual(len(df), 100)

    def test_has_required_columns(self):
        df = generate_synthetic_dataset(n_samples=50)
        required = [
            "cvss_base_score", "attack_vector", "attack_complexity",
            "privileges_required", "user_interaction", "scope",
            "confidentiality_impact", "integrity_impact", "availability_impact",
            "has_public_exploit", "days_since_publish", "exploitable",
        ]
        for col in required:
            self.assertIn(col, df.columns)

    def test_cvss_score_range(self):
        df = generate_synthetic_dataset(n_samples=200)
        self.assertTrue((df["cvss_base_score"] >= 0).all())
        self.assertTrue((df["cvss_base_score"] <= 10).all())

    def test_binary_exploitable_column(self):
        df = generate_synthetic_dataset(n_samples=200)
        self.assertTrue(set(df["exploitable"].unique()).issubset({0, 1}))

    def test_positive_class_exists(self):
        df = generate_synthetic_dataset(n_samples=500)
        self.assertGreater(df["exploitable"].sum(), 0)


class TestFeatureEngineering(unittest.TestCase):
    def setUp(self):
        self.df = generate_synthetic_dataset(n_samples=100)

    def test_returns_correct_shapes(self):
        X, y, features = engineer_features(self.df)
        self.assertEqual(X.shape[0], len(self.df))
        self.assertEqual(len(y), len(self.df))
        self.assertEqual(X.shape[1], len(features))

    def test_no_nan_in_features(self):
        X, y, _ = engineer_features(self.df)
        self.assertFalse(np.isnan(X).any())

    def test_feature_names_list(self):
        _, _, features = engineer_features(self.df)
        self.assertIsInstance(features, list)
        self.assertGreater(len(features), 0)


class TestTrainAndEvaluate(unittest.TestCase):
    def setUp(self):
        # Use small dataset for speed
        self.df = generate_synthetic_dataset(n_samples=300)

    def test_returns_all_model_results(self):
        results = train_and_evaluate(self.df)
        self.assertIn("random_forest", results)
        self.assertIn("logistic_regression", results)
        self.assertIn("cvss_threshold_baseline", results)

    def test_metrics_in_valid_range(self):
        results = train_and_evaluate(self.df)
        for model_name, metrics in results.items():
            for metric in ["precision", "recall", "f1_score", "roc_auc"]:
                self.assertGreaterEqual(metrics[metric], 0.0, f"{model_name}.{metric}")
                self.assertLessEqual(metrics[metric], 1.0, f"{model_name}.{metric}")

    def test_random_forest_has_cv_scores(self):
        results = train_and_evaluate(self.df)
        self.assertIn("cv_f1_mean", results["random_forest"])
        self.assertIn("cv_f1_std", results["random_forest"])

    def test_confusion_matrix_shape(self):
        results = train_and_evaluate(self.df)
        cm = results["random_forest"]["confusion_matrix"]
        self.assertEqual(len(cm), 2)
        self.assertEqual(len(cm[0]), 2)

    def test_feature_importances_present(self):
        results = train_and_evaluate(self.df)
        fi = results["random_forest"]["feature_importances"]
        self.assertIsInstance(fi, dict)
        self.assertGreater(len(fi), 0)
        # All importance values should sum to approximately 1
        total = sum(fi.values())
        self.assertAlmostEqual(total, 1.0, places=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
