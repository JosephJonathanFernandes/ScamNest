"""
Test suite for confidence-aware scam detection enhancements.

This test suite validates:
1. Intent scoring for India-specific scam patterns
2. Confidence-aware risk aggregation
3. Enhanced rule detection for UPI scams
4. Backward compatibility with existing system
"""

import pytest
from app.models.schemas import Message
from app.services.intent_scorer import IntentScorer
from app.services.risk_aggregator import RiskAggregator, RiskLevel, ConfidenceLevel
from app.services.scam_detector_hybrid import ScamDetector


class TestIntentScorer:
    """Test cases for IntentScorer service."""

    def setup_method(self):
        """Initialize intent scorer before each test."""
        self.intent_scorer = IntentScorer()

    def test_upi_scam_detection(self):
        """Test detection of UPI-specific scam patterns."""
        # High-risk UPI scam message
        text = "Your UPI is blocked. Share your UPI ID immediately to reactivate."
        score, details = self.intent_scorer.calculate_intent_score(text)

        # Should detect high intent risk
        assert score > 0.5, f"Expected high risk for UPI scam, got {score}"
        assert details["pattern_counts"]["upi_scam"] > 0, "Should detect UPI scam pattern"
        assert details["pattern_counts"]["financial"] > 0, "Should detect financial entity"
        assert details["pattern_counts"]["coercion"] > 0, "Should detect coercion"

        print(f"✓ UPI scam detection: score={score:.4f}")
        print(f"  Details: {details['components']}")

    def test_financial_coercion(self):
        """Test detection of financial threats."""
        text = "Your bank account will be suspended today. Update KYC now to avoid blocking."
        score, details = self.intent_scorer.calculate_intent_score(text)

        assert score > 0.6, f"Expected high risk for financial threat, got {score}"
        assert details["pattern_counts"]["coercion"] > 0, "Should detect coercion"
        assert details["pattern_counts"]["urgency"] > 0, "Should detect urgency"

        print(f"✓ Financial coercion detection: score={score:.4f}")

    def test_safe_message(self):
        """Test that safe messages get low scores."""
        text = "Hello, how are you today? I hope you're doing well."
        score, details = self.intent_scorer.calculate_intent_score(text)

        assert score < 0.3, f"Expected low risk for safe message, got {score}"
        print(f"✓ Safe message detection: score={score:.4f}")

    def test_combination_bonus(self):
        """Test that combination of patterns increases risk."""
        text_single = "Your UPI ID is required."
        text_combined = "Your UPI ID is blocked. Share it immediately to reactivate your account."

        score_single, _ = self.intent_scorer.calculate_intent_score(text_single)
        score_combined, details = self.intent_scorer.calculate_intent_score(text_combined)

        # Combined should have higher score due to bonuses
        assert score_combined > score_single, "Combined patterns should increase risk"
        assert details["components"]["combination_bonus"] > 0, "Should apply combination bonus"

        print(f"✓ Combination bonus: single={score_single:.4f}, combined={score_combined:.4f}")


class TestRiskAggregator:
    """Test cases for confidence-aware risk aggregator."""

    def setup_method(self):
        """Initialize risk aggregator before each test."""
        self.risk_aggregator = RiskAggregator()

    def test_high_confidence_ml_trusted(self):
        """Test that high-confidence ML predictions are trusted."""
        message = Message(
            sender="scammer",
            text="Your account is blocked. Send OTP to verify.",
            timestamp="2025-01-01T00:00:00Z"
        )

        # High confidence ML prediction saying it's a scam
        ml_prediction = {"label": "possible_scam", "confidence": 0.85}

        risk_level, score, explanation = self.risk_aggregator.analyze_message(
            message, ml_prediction
        )

        # Should classify as scam
        assert risk_level in [RiskLevel.SCAM, RiskLevel.SUSPICIOUS], \
            f"High-confidence ML should detect scam, got {risk_level}"
        assert explanation["confidence_level"] == ConfidenceLevel.HIGH.value
        assert explanation["signals"]["ml"]["weight"] >= 0.8, \
            "ML should have high weight for high confidence"

        print(f"✓ High-confidence ML: risk={risk_level.value}, score={score:.4f}")
        print(f"  ML weight: {explanation['signals']['ml']['weight']}")

    def test_low_confidence_ml_fallback(self):
        """Test that low-confidence ML triggers fallback to rules/intent."""
        message = Message(
            sender="scammer",
            text="Urgent: Update your UPI PIN now or account will be blocked!",
            timestamp="2025-01-01T00:00:00Z"
        )

        # Low confidence ML prediction (uncertain)
        ml_prediction = {"label": "not_scam", "confidence": 0.45}

        risk_level, score, explanation = self.risk_aggregator.analyze_message(
            message, ml_prediction
        )

        # Despite low ML confidence saying "not_scam", rules and intent should catch it
        assert risk_level in [RiskLevel.SUSPICIOUS, RiskLevel.SCAM], \
            f"Low-confidence ML should be overridden by rules/intent, got {risk_level}"
        assert explanation["confidence_level"] == ConfidenceLevel.LOW.value

        # Rules and intent should have significant weight
        assert explanation["signals"]["rules"]["weight"] >= 0.3, \
            "Rules should have high weight for low confidence"
        assert explanation["signals"]["intent"]["weight"] >= 0.25, \
            "Intent should have high weight for low confidence"

        print(f"✓ Low-confidence ML fallback: risk={risk_level.value}, score={score:.4f}")
        print(f"  Weights: ML={explanation['signals']['ml']['weight']}, "
              f"Rules={explanation['signals']['rules']['weight']}, "
              f"Intent={explanation['signals']['intent']['weight']}")

    def test_india_specific_upi_scam(self):
        """Test detection of India-specific UPI scams."""
        message = Message(
            sender="scammer",
            text="Dear customer, your Paytm UPI is deactivated. Share your UPI ID to reactivate immediately.",
            timestamp="2025-01-01T00:00:00Z"
        )

        risk_level, score, explanation = self.risk_aggregator.analyze_message(message)

        # Should detect as scam due to UPI-specific patterns
        assert risk_level in [RiskLevel.SUSPICIOUS, RiskLevel.SCAM], \
            f"Should detect UPI scam, got {risk_level}"

        # Check that intent scoring caught UPI patterns
        intent_details = explanation["signals"]["intent"]["details"]
        assert intent_details["pattern_counts"]["upi_scam"] > 0, \
            "Should detect UPI scam patterns"

        print(f"✓ India-specific UPI scam: risk={risk_level.value}, score={score:.4f}")
        print(f"  Intent score: {explanation['signals']['intent']['score']}")

    def test_suspicious_vs_scam_threshold(self):
        """Test that thresholds properly distinguish suspicious from scam."""
        # Moderately risky message
        moderate_msg = Message(
            sender="scammer",
            text="Your account needs verification. Click here.",
            timestamp="2025-01-01T00:00:00Z"
        )

        # High-risk message
        high_risk_msg = Message(
            sender="scammer",
            text="URGENT: Your bank account is blocked! Send OTP and UPI PIN immediately to avoid legal action!",
            timestamp="2025-01-01T00:00:00Z"
        )

        moderate_risk, moderate_score, _ = self.risk_aggregator.analyze_message(moderate_msg)
        high_risk, high_score, _ = self.risk_aggregator.analyze_message(high_risk_msg)

        # High risk should have higher score
        assert high_score > moderate_score, "High-risk message should score higher"

        # High risk should be classified as scam
        assert high_risk == RiskLevel.SCAM, f"High-risk should be SCAM, got {high_risk}"

        print(f"✓ Risk thresholds: moderate={moderate_risk.value} ({moderate_score:.4f}), "
              f"high={high_risk.value} ({high_score:.4f})")

    def test_safe_message_classification(self):
        """Test that safe messages are classified correctly."""
        message = Message(
            sender="scammer",
            text="Hello, how can I help you with your query?",
            timestamp="2025-01-01T00:00:00Z"
        )

        risk_level, score, explanation = self.risk_aggregator.analyze_message(message)

        assert risk_level == RiskLevel.SAFE, f"Safe message should be SAFE, got {risk_level}"
        assert score < 0.35, f"Safe message should have low score, got {score}"

        print(f"✓ Safe message: risk={risk_level.value}, score={score:.4f}")


class TestEnhancedScamDetector:
    """Test enhanced rule-based scam detector with India-specific patterns."""

    def setup_method(self):
        """Initialize scam detector before each test."""
        self.detector = ScamDetector()

    def test_upi_scam_patterns(self):
        """Test new UPI scam pattern detection."""
        message = Message(
            sender="scammer",
            text="Share your UPI ID to reactivate your blocked account",
            timestamp="2025-01-01T00:00:00Z"
        )

        score, keywords = self.detector.analyze_message(message)

        # Should detect UPI scam patterns
        assert score > 0.4, f"Should detect UPI scam patterns, got score {score}"
        assert any('upi' in kw.lower() for kw in keywords), \
            "Should extract UPI-related keywords"

        print(f"✓ UPI scam patterns: score={score:.4f}, keywords={keywords[:5]}")

    def test_financial_coercion_patterns(self):
        """Test new financial coercion pattern detection."""
        message = Message(
            sender="scammer",
            text="Your account will be suspended. Update KYC immediately to prevent blocking.",
            timestamp="2025-01-01T00:00:00Z"
        )

        score, keywords = self.detector.analyze_message(message)

        # Should detect financial coercion
        assert score > 0.5, f"Should detect financial coercion, got score {score}"

        print(f"✓ Financial coercion: score={score:.4f}")

    def test_backward_compatibility(self):
        """Test that existing detection still works."""
        message = Message(
            sender="scammer",
            text="Congratulations! You won lottery prize of Rs 50000. Send your bank details.",
            timestamp="2025-01-01T00:00:00Z"
        )

        score, keywords = self.detector.analyze_message(message)

        # Should still detect classic scam patterns
        assert score > 0.5, f"Should detect classic scam, got score {score}"
        assert len(keywords) > 0, "Should extract keywords"

        print(f"✓ Backward compatibility: score={score:.4f}")


class TestSystemIntegration:
    """Integration tests for the complete enhanced system."""

    def test_complete_workflow(self):
        """Test complete workflow from message to risk assessment."""
        risk_aggregator = RiskAggregator()

        # Test message with India-specific scam
        message = Message(
            sender="scammer",
            text="URGENT: Your GPay UPI is blocked due to KYC pending. "
                 "Share your UPI ID and OTP immediately to reactivate within 24 hours. "
                 "Failure will result in permanent account suspension.",
            timestamp="2025-01-01T00:00:00Z"
        )

        # Run complete analysis
        risk_level, score, explanation = risk_aggregator.analyze_message(message)

        # Verify all components worked
        assert risk_level == RiskLevel.SCAM, f"Should detect as SCAM, got {risk_level}"
        assert score > 0.6, f"Score should be high, got {score}"

        # Verify explanation contains all signal types
        assert "ml" in explanation["signals"], "Should have ML signal"
        assert "rules" in explanation["signals"], "Should have rules signal"
        assert "intent" in explanation["signals"], "Should have intent signal"

        # Verify intent scoring worked
        intent_score = explanation["signals"]["intent"]["score"]
        assert intent_score > 0.5, f"Intent score should be high, got {intent_score}"

        # Verify decision logic is explainable
        assert "decision_logic" in explanation, "Should have decision explanation"
        assert len(explanation["decision_logic"]) > 0, "Decision logic should not be empty"

        print(f"✓ Complete workflow: risk={risk_level.value}, score={score:.4f}")
        print(f"  ML confidence: {explanation['confidence_level']}")
        print(f"  Component scores: ML={explanation['signals']['ml']['score']:.4f}, "
              f"Rules={explanation['signals']['rules']['score']:.4f}, "
              f"Intent={explanation['signals']['intent']['score']:.4f}")
        print(f"  Decision: {explanation['decision_logic'][:100]}...")

    def test_engagement_decisions(self):
        """Test engagement strategy recommendations."""
        risk_aggregator = RiskAggregator()

        test_cases = [
            (RiskLevel.SAFE, 0.2, False, "minimal_engagement"),
            (RiskLevel.SUSPICIOUS, 0.4, True, "probing_engagement"),
            (RiskLevel.SCAM, 0.7, True, "cautious_engagement"),
            (RiskLevel.SCAM, 0.9, True, "aggressive_engagement"),
        ]

        for risk_level, score, should_engage, expected_strategy in test_cases:
            actual_engage = risk_aggregator.should_engage(risk_level, score)
            actual_strategy = risk_aggregator.get_engagement_strategy(risk_level, score)

            assert actual_engage == should_engage, \
                f"Engagement decision mismatch for {risk_level.value}"
            assert actual_strategy == expected_strategy, \
                f"Strategy mismatch for {risk_level.value}: expected {expected_strategy}, got {actual_strategy}"

            print(f"✓ Engagement: {risk_level.value} ({score:.1f}) -> "
                  f"engage={actual_engage}, strategy={actual_strategy}")


def run_manual_tests():
    """Run manual tests with example messages."""
    print("\n" + "="*80)
    print("CONFIDENCE-AWARE SCAM DETECTION - MANUAL TESTS")
    print("="*80 + "\n")

    # Test messages
    test_messages = [
        {
            "text": "Your Paytm account is blocked. Share UPI ID immediately to reactivate.",
            "description": "India-specific UPI scam",
        },
        {
            "text": "Dear customer, update your bank KYC within 24 hours to avoid account suspension.",
            "description": "Financial coercion with urgency",
        },
        {
            "text": "Hello, how can we help you today?",
            "description": "Safe customer service message",
        },
        {
            "text": "Click here to claim your prize of Rs 50000 before it expires today!",
            "description": "Classic lottery scam",
        },
    ]

    risk_aggregator = RiskAggregator()

    for i, test in enumerate(test_messages, 1):
        print(f"\n--- Test {i}: {test['description']} ---")
        print(f"Message: \"{test['text']}\"")

        message = Message(
            sender="scammer",
            text=test["text"],
            timestamp="2025-01-01T00:00:00Z"
        )

        risk_level, score, explanation = risk_aggregator.analyze_message(message)

        print(f"\nRisk Assessment:")
        print(f"  Risk Level: {risk_level.value.upper()}")
        print(f"  Confidence Score: {score:.4f}")
        print(f"  ML Confidence: {explanation['confidence_level']}")

        print(f"\nSignal Breakdown:")
        for signal_type, signal_data in explanation["signals"].items():
            print(f"  {signal_type.upper()}: score={signal_data['score']:.4f}, "
                  f"weight={signal_data['weight']:.2f}, "
                  f"contribution={signal_data['weighted_contribution']:.4f}")

        print(f"\nDecision Logic:")
        print(f"  {explanation['decision_logic']}")

        engagement = risk_aggregator.should_engage(risk_level, score)
        strategy = risk_aggregator.get_engagement_strategy(risk_level, score)
        print(f"\nEngagement:")
        print(f"  Should Engage: {engagement}")
        print(f"  Strategy: {strategy}")
        print("\n" + "-"*80)


if __name__ == "__main__":
    # Run pytest tests
    print("Running pytest tests...\n")
    pytest.main([__file__, "-v", "--tb=short"])

    # Run manual tests
    run_manual_tests()
