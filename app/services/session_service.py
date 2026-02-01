"""
Session management service using simple in-memory storage.
"""

from typing import Optional, Dict
from datetime import datetime

from ..models.schemas import SessionState, Message, Metadata, ExtractedIntelligence


# Global session store - simple dict
_sessions: Dict[str, SessionState] = {}


class SessionService:
    """Simple in-memory session management."""
    
    def get_session(self, session_id: str) -> Optional[SessionState]:
        """Get session by ID."""
        return _sessions.get(session_id)
    
    def create_session(self, session_id: str, metadata: Optional[Metadata] = None) -> SessionState:
        """Create a new session."""
        session = SessionState(sessionId=session_id, metadata=metadata)
        _sessions[session_id] = session
        return session
    
    def get_or_create_session(self, session_id: str, metadata: Optional[Metadata] = None) -> SessionState:
        """Get existing session or create new one."""
        return self.get_session(session_id) or self.create_session(session_id, metadata)
    
    def update_session(self, session: SessionState) -> SessionState:
        """Update session state."""
        session.updatedAt = datetime.utcnow().isoformat()
        _sessions[session.sessionId] = session
        return session
    
    def add_message(self, session_id: str, message: Message) -> SessionState:
        """Add a message to session history."""
        session = self.get_session(session_id)
        if session is None:
            raise ValueError(f"Session {session_id} not found")
        session.messages.append(message)
        session.totalMessages += 1
        return self.update_session(session)
    
    def update_scam_status(self, session_id: str, suspected: bool = False, detected: bool = False, confidence: float = 0.0) -> SessionState:
        """Update scam detection status."""
        session = self.get_session(session_id)
        if session is None:
            raise ValueError(f"Session {session_id} not found")
        session.scamSuspected = suspected or session.scamSuspected
        session.scamDetected = detected or session.scamDetected
        session.scamConfidenceScore = max(confidence, session.scamConfidenceScore)
        return self.update_session(session)
    
    def update_intelligence(self, session_id: str, intelligence: ExtractedIntelligence) -> SessionState:
        """Update extracted intelligence."""
        session = self.get_session(session_id)
        if session is None:
            raise ValueError(f"Session {session_id} not found")
        session.extractedIntelligence = session.extractedIntelligence.merge(intelligence)
        return self.update_session(session)
    
    def mark_callback_sent(self, session_id: str, notes: str = "") -> SessionState:
        """Mark callback as sent for session."""
        session = self.get_session(session_id)
        if session is None:
            raise ValueError(f"Session {session_id} not found")
        session.callbackSent = True
        if notes:
            session.agentNotes = notes
        return self.update_session(session)
    
    def delete_session(self, session_id: str) -> bool:
        """Delete a session."""
        if session_id in _sessions:
            del _sessions[session_id]
            return True
        return False
