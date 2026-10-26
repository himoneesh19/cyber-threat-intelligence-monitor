from __future__ import annotations

import unittest
from src.engine.classifier import classify_threat


class TestThreatClassifier(unittest.TestCase):
    def test_classify_nextjs_web_threat(self):
        record = {
            "title": "Server Actions Remote Code Execution in Next.js",
            "summary": "An input validation flaw in Next.js Server Actions allowed arbitrary execution on Node.js runtime.",
            "vendor": "Vercel",
            "product": "Next.js",
            "packages": [{"name": "next", "ecosystem": "npm"}]
        }
        category, techs = classify_threat(record)
        self.assertEqual(category, "Web & Application Frameworks")
        self.assertIn("Next.js", techs)
        self.assertIn("Node.js", techs)

    def test_classify_aws_cloud_threat(self):
        record = {
            "title": "Privilege escalation vulnerability in AWS IAM Identity Center",
            "summary": "Allows unauthorized access to Amazon S3 buckets through misconfigured IAM roles.",
            "vendor": "Amazon",
            "product": "AWS IAM"
        }
        category, techs = classify_threat(record)
        self.assertEqual(category, "Cloud & Infrastructure")
        self.assertIn("AWS", techs)

    def test_classify_postgresql_database_threat(self):
        record = {
            "title": "PostgreSQL SQL Injection in pg_dump utility",
            "summary": "Flaw in postgresql command line tool allows executing arbitrary SQL statements.",
            "vendor": "PostgreSQL Global Development Group",
            "product": "PostgreSQL"
        }
        category, techs = classify_threat(record)
        self.assertEqual(category, "Databases & Storage")
        self.assertIn("PostgreSQL", techs)

    def test_classify_ai_threat(self):
        record = {
            "title": "Arbitrary Code Execution in PyTorch TorchScript model loader",
            "summary": "Untrusted serialization in PyTorch torch.load allows executing system commands.",
            "vendor": "PyTorch",
            "product": "PyTorch"
        }
        category, techs = classify_threat(record)
        self.assertEqual(category, "AI & Emerging Technologies")


if __name__ == "__main__":
    unittest.main()
