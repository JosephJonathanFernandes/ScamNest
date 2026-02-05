"""
Review queue service for flagging suspicious cases for human review.

This service manages cases that need manual review, typically:
- Medium risk scores (SUSPICIOUS level)
- Low-confidence ML predictions with conflicting signals
- Edge cases that automation cannot confidently classify
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime
from collections import deque

logger = logging.getLogger(__name__)


class ReviewQueueItem:
    """Single item in the review queue."""

    def __init__(
        self,
        session_id: str,
        message_text: str,
        risk_level: str,
        aggregated_score: float,
        explanation: Dict,
        timestamp: str = None
    ):
        self.session_id = session_id
        self.message_text = message_text
        self.risk_level = risk_level
        self.aggregated_score = aggregated_score
        self.explanation = explanation
        self.timestamp = timestamp or datetime.utcnow().isoformat()
        self.reviewed = False
        self.reviewer_notes = None
        self.final_decision = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "session_id": self.session_id,
            "message_text": self.message_text,
            "risk_level": self.risk_level,
            "aggregated_score": self.aggregated_score,
            "explanation": self.explanation,
            "timestamp": self.timestamp,
            "reviewed": self.reviewed,
            "reviewer_notes": self.reviewer_notes,
            "final_decision": self.final_decision,
        }


class ReviewQueueService:
    """
    Service for managing review queue for suspicious cases.

    Features:
    - Queue suspicious cases for human review
    - Track review status and decisions
    - Provide feedback for continuous learning
    - Maintain bounded queue size
    """

    def __init__(self, max_queue_size: int = 1000):
        """
        Initialize review queue service.

        Args:
            max_queue_size: Maximum queue size (FIFO when exceeded)
        """
        self.max_queue_size = max_queue_size
        self.queue: deque = deque(maxlen=max_queue_size)
        self.reviewed_items: List[ReviewQueueItem] = []

        logger.info(f"ReviewQueueService initialized with max_size={max_queue_size}")

    def add_to_queue(
        self,
        session_id: str,
        message_text: str,
        risk_level: str,
        aggregated_score: float,
        explanation: Dict,
        reason: str = "suspicious_classification"
    ) -> ReviewQueueItem:
        """
        Add an item to the review queue.

        Args:
            session_id: Session identifier
            message_text: Message content
            risk_level: Assessed risk level
            aggregated_score: Final risk score
            explanation: Detailed decision explanation
            reason: Reason for queuing

        Returns:
            ReviewQueueItem added to queue
        """
        item = ReviewQueueItem(
            session_id=session_id,
            message_text=message_text,
            risk_level=risk_level,
            aggregated_score=aggregated_score,
            explanation=explanation
        )

        self.queue.append(item)

        logger.info(
            f"Added to review queue: session={session_id} "
            f"risk={risk_level} score={aggregated_score:.2f} reason={reason}"
        )

        return item

    def should_queue(
        self,
        risk_level: str,
        aggregated_score: float,
        ml_confidence_level: str
    ) -> bool:
        """
        Determine if a case should be queued for review.

        Queue if:
        - Risk level is SUSPICIOUS (medium risk)
        - ML confidence is LOW and score near threshold
        - High score but conflicting signals

        Args:
            risk_level: Assessed risk level
            aggregated_score: Final risk score
            ml_confidence_level: ML confidence level

        Returns:
            True if should be queued for review
        """
        # Always queue SUSPICIOUS cases
        if risk_level == "suspicious":
            return True

        # Queue low-confidence high-risk cases
        if ml_confidence_level == "low" and aggregated_score >= 0.55:
            return True

        # Queue borderline scam cases (just above threshold)
        if risk_level == "scam" and 0.60 <= aggregated_score <= 0.70:
            return True

        return False

    def get_queue_size(self) -> int:
        """Get current queue size."""
        return len(self.queue)

    def get_pending_items(self, limit: int = 50) -> List[Dict]:
        """
        Get pending items for review.

        Args:
            limit: Maximum number of items to return

        Returns:
            List of unreviewed items as dicts
        """
        pending = [item for item in self.queue if not item.reviewed]
        return [item.to_dict() for item in pending[:limit]]

    def mark_reviewed(
        self,
        session_id: str,
        final_decision: str,
        reviewer_notes: Optional[str] = None
    ) -> bool:
        """
        Mark an item as reviewed with final decision.

        Args:
            session_id: Session identifier
            final_decision: Final decision (safe/scam/needs_more_data)
            reviewer_notes: Optional reviewer notes

        Returns:
            True if item found and marked, False otherwise
        """
        for item in self.queue:
            if item.session_id == session_id and not item.reviewed:
                item.reviewed = True
                item.final_decision = final_decision
                item.reviewer_notes = reviewer_notes

                # Move to reviewed items
                self.reviewed_items.append(item)

                logger.info(
                    f"Marked reviewed: session={session_id} "
                    f"decision={final_decision}"
                )

                return True

        return False

    def get_feedback_data(self, limit: int = 100) -> List[Dict]:
        """
        Get reviewed items as feedback data for retraining.

        Args:
            limit: Maximum number of items to return

        Returns:
            List of reviewed items with ground truth labels
        """
        feedback = []

        for item in self.reviewed_items[-limit:]:
            if item.reviewed and item.final_decision:
                feedback.append({
                    "text": item.message_text,
                    "predicted_label": item.risk_level,
                    "predicted_score": item.aggregated_score,
                    "ground_truth": item.final_decision,
                    "ml_confidence": item.explanation.get("confidence_level"),
                    "signals": item.explanation.get("signals"),
                    "timestamp": item.timestamp,
                })

        return feedback

    def get_stats(self) -> Dict:
        """Get queue statistics."""
        total = len(self.queue)
        reviewed = sum(1 for item in self.queue if item.reviewed)
        pending = total - reviewed

        return {
            "total_items": total,
            "pending_review": pending,
            "reviewed": reviewed,
            "reviewed_items_stored": len(self.reviewed_items),
            "max_queue_size": self.max_queue_size,
        }
