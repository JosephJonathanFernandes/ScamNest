"""
Callback service for sending final results to GUVI endpoint.
"""

import httpx
import logging
from typing import Optional
from ..models.schemas import SessionState, CallbackPayload
from ..config import get_settings

logger = logging.getLogger(__name__)


class CallbackService:
    """
    Handles sending final results to the GUVI evaluation endpoint.
    """
    
    def __init__(self):
        """Initialize callback service."""
        self.settings = get_settings()
        self.callback_url = self.settings.guvi_callback_url
        self.timeout = self.settings.callback_timeout
    
    def _build_payload(self, session: SessionState, agent_notes: str) -> CallbackPayload:
        """Build callback payload from session state."""
        intel = session.extractedIntelligence
        
        return CallbackPayload(
            sessionId=session.sessionId,
            scamDetected=session.scamDetected,
            totalMessagesExchanged=session.totalMessages,
            extractedIntelligence={
                "bankAccounts": intel.bankAccounts,
                "upiIds": intel.upiIds,
                "phishingLinks": intel.phishingLinks,
                "phoneNumbers": intel.phoneNumbers,
                "suspiciousKeywords": intel.suspiciousKeywords,
            },
            agentNotes=agent_notes or session.agentNotes,
        )
    
    async def send_callback(
        self, 
        session: SessionState, 
        agent_notes: str = ""
    ) -> tuple[bool, Optional[str]]:
        """
        Send final result callback to GUVI endpoint.
        
        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        # Check if callback already sent
        if session.callbackSent:
            logger.warning(f"Callback already sent for session {session.sessionId}")
            return False, "Callback already sent for this session"
        
        # Check if scam is confirmed
        if not session.scamDetected:
            logger.warning(f"Scam not confirmed for session {session.sessionId}")
            return False, "Cannot send callback - scam not confirmed"
        
        # Build payload
        payload = self._build_payload(session, agent_notes)
        
        logger.info(f"Sending callback for session {session.sessionId}")
        logger.debug(f"Callback payload: {payload.model_dump_json()}")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.callback_url,
                    json=payload.model_dump(),
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout,
                )
                
                if response.status_code == 200:
                    logger.info(f"Callback successful for session {session.sessionId}")
                    return True, None
                else:
                    error_msg = f"Callback failed with status {response.status_code}: {response.text}"
                    logger.error(error_msg)
                    return False, error_msg
                    
        except httpx.TimeoutException:
            error_msg = f"Callback timeout for session {session.sessionId}"
            logger.error(error_msg)
            return False, error_msg
        except httpx.RequestError as e:
            error_msg = f"Callback request error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected callback error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def should_send_callback(self, session: SessionState) -> bool:
        """
        Determine if callback should be sent for this session.
        
        Conditions:
        1. Scam must be confirmed (scamDetected = True)
        2. Callback not already sent
        3. Minimum messages exchanged
        4. Some intelligence extracted (optional but recommended)
        """
        if session.callbackSent:
            return False
        
        if not session.scamDetected:
            return False
        
        if session.totalMessages < self.settings.min_messages_for_callback:
            return False
        
        # Additional check: prefer having some intelligence
        # but not strictly required
        if session.extractedIntelligence.is_empty():
            # Still allow callback but with lower confidence
            if session.scamConfidenceScore < 0.8:
                return False
        
        return True
