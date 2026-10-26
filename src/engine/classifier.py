from __future__ import annotations

import re
from typing import Any
from src.config import load_taxonomy

_TAXONOMY = load_taxonomy()


class ThreatClassifier:
    """
    Classifies threat records into standardized Categories and Technology tags
    using regex keyword matching, package ecosystem tagging, and vendor correlation.
    """

    def __init__(self, taxonomy: dict[str, Any] | None = None) -> None:
        self.taxonomy = taxonomy or _TAXONOMY
        self.categories: dict[str, list[re.Pattern[str]]] = {}
        self.tech_aliases: dict[str, list[re.Pattern[str]]] = {}

        # Compile regexes for categories
        for cat_name, cat_data in self.taxonomy.get("categories", {}).items():
            patterns = []
            for kw in cat_data.get("keywords", []):
                escaped = re.escape(kw)
                patterns.append(re.compile(rf"(?:\b|_){escaped}(?:\b|_)", re.IGNORECASE))
            self.categories[cat_name] = patterns

        # Compile regexes for technology aliases
        for tech_name, aliases in self.taxonomy.get("technology_aliases", {}).items():
            patterns = []
            for alias in aliases:
                escaped = re.escape(alias)
                patterns.append(re.compile(rf"(?:\b|_){escaped}(?:\b|_)", re.IGNORECASE))
            self.tech_aliases[tech_name] = patterns

    def classify(self, record: dict[str, Any]) -> tuple[str, list[str]]:
        """
        Analyzes a threat record and returns:
        (primary_category, list_of_detected_technologies)
        """
        search_corpus = " ".join([
            str(record.get("title") or ""),
            str(record.get("summary") or ""),
            str(record.get("vendor") or ""),
            str(record.get("product") or "")
        ])

        # Also include package names if present
        for pkg in record.get("packages") or []:
            if isinstance(pkg, dict):
                search_corpus += f" {pkg.get('name', '')} {pkg.get('ecosystem', '')}"

        # Detect technologies
        detected_techs: set[str] = set()
        for tech_name, patterns in self.tech_aliases.items():
            for pat in patterns:
                if pat.search(search_corpus):
                    detected_techs.add(tech_name)
                    break

        # Detect categories with score counts
        category_scores: dict[str, int] = {}
        for cat_name, patterns in self.categories.items():
            score = sum(1 for pat in patterns if pat.search(search_corpus))
            if score > 0:
                category_scores[cat_name] = score

        if category_scores:
            # Category with highest keyword matches
            primary_category = max(category_scores.items(), key=lambda x: x[1])[0]
        else:
            primary_category = "General Security & Vulnerabilities"

        # Format technology display names nicely (e.g. "next.js" -> "Next.js", "postgresql" -> "PostgreSQL")
        display_techs = [self._format_tech_name(t) for t in sorted(detected_techs)]
        return primary_category, display_techs

    @staticmethod
    def _format_tech_name(tech: str) -> str:
        name_map = {
            "next.js": "Next.js",
            "react": "React",
            "node.js": "Node.js",
            "php": "PHP",
            "postgresql": "PostgreSQL",
            "mysql": "MySQL",
            "aws": "AWS",
            "docker": "Docker",
            "kubernetes": "Kubernetes",
            "linux": "Linux",
            "redis": "Redis",
            "mongodb": "MongoDB",
            "python": "Python",
            "openssl": "OpenSSL",
        }
        return name_map.get(tech.lower(), tech.capitalize())


_DEFAULT_CLASSIFIER = ThreatClassifier()


def classify_threat(record: dict[str, Any]) -> tuple[str, list[str]]:
    return _DEFAULT_CLASSIFIER.classify(record)
