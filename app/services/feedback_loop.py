"""
Feedback loop service for continuous learning and model improvement.

This service collects detection decisions, human feedback, and patterns
to enable continuous learning and system improvement.
"""

import logging
import json
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class FeedbackLoopService:
    """
    Service for collecting and managing feedback data for continuous learning.

    Features:
    - Log all detection decisions with full context
    - Track false positives and false negatives
    - Collect human review feedback
    - Export data for model retraining
    - Analyze detection patterns and edge cases
    """

    def __init__(self, feedback_dir: str = "feedback_data"):
        """
        Initialize feedback loop service.

        Args:
            feedback_dir: Directory to store feedback data
        """
        self.feedback_dir = Path(feedback_dir)
        self.feedback_dir.mkdir(exist_ok=True)

        # In-memory feedback buffer
        self.decision_log: List[Dict] = []
        self.feedback_buffer: List[Dict] = []

        logger.info(f"FeedbackLoopService initialized with dir={feedback_dir}")

    def log_decision(
        self,
        session_id: str,
        message_text: str,
        risk_level: str,
        aggregated_score: float,
        ml_confidence_level: str,
        explanation: Dict,
        contextual_signals: Optional[Dict] = None,
    ) -> None:
        """
        Log a detection decision with full context.

        Args:
            session_id: Session identifier
            message_text: Original message text
            risk_level: Final risk assessment
            aggregated_score: Aggregated risk score
            ml_confidence_level: ML confidence level
            explanation: Detailed decision explanation
            contextual_signals: Optional contextual signals
        """
        decision_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": session_id,
            "message_text": message_text,
            "risk_level": risk_level,
            "aggregated_score": round(aggregated_score, 4),
            "ml_confidence_level": ml_confidence_level,
            "ml_score": explanation["signals"]["ml"]["score"],
            "rule_score": explanation["signals"]["rules"]["score"],
            "intent_score": explanation["signals"]["intent"]["score"],
            "ml_weight": explanation["signals"]["ml"]["weight"],
            "rule_keywords": explanation["signals"]["rules"].get("keywords", []),
            "intent_components": explanation["signals"]["intent"]["details"].get("components", {}),
            "decision_logic": explanation.get("decision_logic", ""),
            "contextual_signals": contextual_signals or {},
        }

        self.decision_log.append(decision_record)

        # Periodically flush to disk (every 100 decisions)
        if len(self.decision_log) >= 100:
            self._flush_decisions()

        logger.debug(
            f"Logged decision: session={session_id} "
            f"risk={risk_level} score={aggregated_score:.2f}"
        )

    def add_feedback(
        self,
        session_id: str,
        ground_truth_label: str,
        feedback_source: str = "human_review",
        notes: Optional[str] = None,
    ) -> None:
        """
        Add feedback for a previous decision (ground truth).

        Args:
            session_id: Session identifier
            ground_truth_label: Correct label (safe/suspicious/scam)
            feedback_source: Source of feedback (human_review/user_report/etc)
            notes: Optional feedback notes
        """
        # Find the corresponding decision
        decision = None
        for record in reversed(self.decision_log):
            if record["session_id"] == session_id:
                decision = record
                break

        if not decision:
            logger.warning(f"No decision found for session={session_id}")
            return

        feedback_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": session_id,
            "predicted_label": decision["risk_level"],
            "predicted_score": decision["aggregated_score"],
            "ground_truth_label": ground_truth_label,
            "feedback_source": feedback_source,
            "notes": notes,
            "ml_confidence_level": decision["ml_confidence_level"],
            "was_correct": decision["risk_level"] == ground_truth_label,
            "original_decision": decision,
        }

        self.feedback_buffer.append(feedback_record)

        # Log error type
        if not feedback_record["was_correct"]:
            if ground_truth_label == "scam" and decision["risk_level"] != "scam":
                error_type = "false_negative"
            elif ground_truth_label != "scam" and decision["risk_level"] == "scam":
                error_type = "false_positive"
            else:
                error_type = "misclassification"

            logger.info(
                f"Feedback recorded: session={session_id} "
                f"error_type={error_type} "
                f"predicted={decision['risk_level']} "
                f"actual={ground_truth_label}"
            )

        # Flush feedback periodically
        if len(self.feedback_buffer) >= 50:
            self._flush_feedback()

    def _flush_decisions(self) -> None:
        """Flush decision log to disk."""
        if not self.decision_log:
            return

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filepath = self.feedback_dir / f"decisions_{timestamp}.jsonl"

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                for record in self.decision_log:
                    f.write(json.dumps(record) + '\n')

            logger.info(f"Flushed {len(self.decision_log)} decisions to {filepath}")
            self.decision_log = []
        except Exception as e:
            logger.error(f"Failed to flush decisions: {e}")

    def _flush_feedback(self) -> None:
        """Flush feedback buffer to disk."""
        if not self.feedback_buffer:
            return

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filepath = self.feedback_dir / f"feedback_{timestamp}.jsonl"

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                for record in self.feedback_buffer:
                    f.write(json.dumps(record) + '\n')

            logger.info(f"Flushed {len(self.feedback_buffer)} feedback items to {filepath}")
            self.feedback_buffer = []
        except Exception as e:
            logger.error(f"Failed to flush feedback: {e}")

    def get_retraining_data(
        self,
        include_correct: bool = False,
        min_score_threshold: float = 0.0,
    ) -> List[Dict]:
        """
        Get data for model retraining.

        Args:
            include_correct: Include correctly predicted samples
            min_score_threshold: Minimum score threshold

        Returns:
            List of training samples with ground truth
        """
        training_data = []

        for feedback in self.feedback_buffer:
            # Filter based on criteria
            if not include_correct and feedback["was_correct"]:
                continue

            if feedback["predicted_score"] < min_score_threshold:
                continue

            training_sample = {
                "text": feedback["original_decision"]["message_text"],
                "label": feedback["ground_truth_label"],
                "predicted_label": feedback["predicted_label"],
                "ml_confidence": feedback["ml_confidence_level"],
                "ml_score": feedback["original_decision"]["ml_score"],
                "rule_score": feedback["original_decision"]["rule_score"],
                "intent_score": feedback["original_decision"]["intent_score"],
                "was_error": not feedback["was_correct"],
            }

            training_data.append(training_sample)

        return training_data

    def get_stats(self) -> Dict:
        """Get feedback loop statistics."""
        total_decisions = len(self.decision_log)
        total_feedback = len(self.feedback_buffer)

        # Calculate error rates
        false_positives = sum(
            1 for f in self.feedback_buffer
            if not f["was_correct"] and f["predicted_label"] == "scam"
        )
        false_negatives = sum(
            1 for f in self.feedback_buffer
            if not f["was_correct"] and f["ground_truth_label"] == "scam"
        )

        accuracy = 0.0
        if total_feedback > 0:
            correct = sum(1 for f in self.feedback_buffer if f["was_correct"])
            accuracy = correct / total_feedback

        return {
            "total_decisions_logged": total_decisions,
            "total_feedback_received": total_feedback,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "accuracy": round(accuracy, 4) if total_feedback > 0 else None,
            "feedback_dir": str(self.feedback_dir),
        }

    def analyze_patterns(self) -> Dict:
        """
        Analyze detection patterns for insights.

        Returns:
            Analysis of common patterns, edge cases, and trends
        """
        if not self.decision_log:
            return {"error": "no_data"}

        # Analyze risk level distribution
        risk_distribution = {}
        for decision in self.decision_log:
            level = decision["risk_level"]
            risk_distribution[level] = risk_distribution.get(level, 0) + 1

        # Analyze ML confidence distribution
        confidence_distribution = {}
        for decision in self.decision_log:
            level = decision["ml_confidence_level"]
            confidence_distribution[level] = confidence_distribution.get(level, 0) + 1

        # Find low-confidence high-risk cases (edge cases)
        edge_cases = [
            d for d in self.decision_log
            if d["ml_confidence_level"] == "low" and d["risk_level"] == "scam"
        ]

        # Analyze common keywords in scams
        scam_keywords = {}
        for decision in self.decision_log:
            if decision["risk_level"] == "scam":
                for keyword in decision["rule_keywords"]:
                    scam_keywords[keyword] = scam_keywords.get(keyword, 0) + 1

        top_keywords = sorted(
            scam_keywords.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        return {
            "total_samples": len(self.decision_log),
            "risk_distribution": risk_distribution,
            "confidence_distribution": confidence_distribution,
            "edge_cases_count": len(edge_cases),
            "top_scam_keywords": top_keywords,
        }
