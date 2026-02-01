"""
Intelligence extraction service for identifying scam-related data.
"""

import re
from typing import List
from ..models.schemas import Message, ExtractedIntelligence, SessionState


class IntelligenceExtractor:
    """
    Extracts scam intelligence (bank accounts, UPI IDs, phone numbers, etc.)
    from messages using pattern matching.
    """
    
    # Bank account patterns (Indian format)
    BANK_ACCOUNT_PATTERNS = [
        r'\b\d{9,18}\b',  # Generic account number (9-18 digits)
        r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # 16-digit format
    ]
    
    # UPI ID patterns
    UPI_PATTERNS = [
        r'\b[\w.-]+@[\w]+\b',  # Standard UPI format: name@bank
        r'\b[\w.-]+@(?:upi|ybl|paytm|okaxis|okhdfcbank|oksbi|apl|ibl)\b',
    ]
    
    # Phone number patterns (Indian format)
    PHONE_PATTERNS = [
        r'\+91[-\s]?\d{10}\b',  # +91 format
        r'\b91[-\s]?\d{10}\b',  # 91 format
        r'\b0\d{10}\b',  # 0 prefix
        r'\b[6-9]\d{9}\b',  # Direct 10 digit starting with 6-9
    ]
    
    # URL/Link patterns
    LINK_PATTERNS = [
        r'https?://[^\s<>"\']+',  # HTTP/HTTPS URLs
        r'www\.[^\s<>"\']+',  # www URLs
        r'\b[\w-]+\.(?:com|in|org|net|co\.in|xyz|tk|ml|ga|cf)/[^\s]*',  # Domain with path
        r'bit\.ly/[^\s]+',  # Shortened URLs
        r'tinyurl\.com/[^\s]+',
        r't\.co/[^\s]+',
    ]
    
    # Suspicious keywords for extraction
    SUSPICIOUS_KEYWORDS = [
        'urgent', 'immediately', 'blocked', 'suspended', 'verify',
        'confirm', 'update', 'otp', 'pin', 'password', 'cvv',
        'bank', 'account', 'upi', 'transfer', 'payment', 'kyc',
        'aadhaar', 'pan', 'prize', 'lottery', 'winner', 'reward',
        'cashback', 'refund', 'claim', 'expire', 'deadline',
        'legal action', 'police', 'arrest', 'court', 'penalty',
    ]
    
    def __init__(self):
        """Initialize extractor with compiled patterns."""
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for efficient matching."""
        self.bank_re = [re.compile(p, re.IGNORECASE) for p in self.BANK_ACCOUNT_PATTERNS]
        self.upi_re = [re.compile(p, re.IGNORECASE) for p in self.UPI_PATTERNS]
        self.phone_re = [re.compile(p, re.IGNORECASE) for p in self.PHONE_PATTERNS]
        self.link_re = [re.compile(p, re.IGNORECASE) for p in self.LINK_PATTERNS]
    
    def _extract_with_patterns(self, text: str, patterns: List[re.Pattern]) -> List[str]:
        """Extract all matches for given patterns."""
        matches = []
        for pattern in patterns:
            found = pattern.findall(text)
            matches.extend(found)
        return list(set(matches))
    
    def _filter_bank_accounts(self, matches: List[str]) -> List[str]:
        """Filter and validate bank account numbers."""
        valid_accounts = []
        for match in matches:
            # Remove separators
            clean = re.sub(r'[-\s]', '', match)
            # Check length (typical Indian bank accounts are 9-18 digits)
            if 9 <= len(clean) <= 18 and clean.isdigit():
                # Mask account number for privacy
                masked = f"XXXX-XXXX-{clean[-4:]}"
                if masked not in valid_accounts:
                    valid_accounts.append(masked)
        return valid_accounts
    
    def _filter_upi_ids(self, matches: List[str]) -> List[str]:
        """Filter and validate UPI IDs."""
        valid_upis = []
        # Known UPI handle suffixes
        upi_suffixes = ['upi', 'ybl', 'paytm', 'okaxis', 'okhdfcbank', 
                        'oksbi', 'apl', 'ibl', 'icici', 'sbi', 'hdfc']
        
        for match in matches:
            # Skip email addresses
            if '@' in match:
                parts = match.split('@')
                if len(parts) == 2:
                    suffix = parts[1].lower()
                    # Check if it looks like a UPI ID
                    if any(s in suffix for s in upi_suffixes) or len(suffix) <= 10:
                        # Skip common email domains
                        if suffix not in ['gmail.com', 'yahoo.com', 'hotmail.com', 
                                         'outlook.com', 'email.com']:
                            valid_upis.append(match.lower())
        return list(set(valid_upis))
    
    def _filter_phone_numbers(self, matches: List[str]) -> List[str]:
        """Filter and format phone numbers."""
        valid_phones = []
        for match in matches:
            # Clean the number
            clean = re.sub(r'[-\s+]', '', match)
            
            # Remove leading 0 or 91
            if clean.startswith('91') and len(clean) > 10:
                clean = clean[2:]
            elif clean.startswith('0') and len(clean) > 10:
                clean = clean[1:]
            
            # Validate Indian mobile number (starts with 6-9, 10 digits)
            if len(clean) == 10 and clean[0] in '6789':
                formatted = f"+91{clean}"
                if formatted not in valid_phones:
                    valid_phones.append(formatted)
        
        return valid_phones
    
    def _filter_links(self, matches: List[str]) -> List[str]:
        """Filter suspicious links."""
        suspicious_links = []
        
        # Known safe domains to exclude
        safe_domains = ['google.com', 'facebook.com', 'twitter.com', 
                       'instagram.com', 'youtube.com', 'linkedin.com']
        
        for match in matches:
            is_safe = False
            for domain in safe_domains:
                if domain in match.lower():
                    is_safe = True
                    break
            
            if not is_safe:
                # Normalize URL
                if not match.startswith('http'):
                    match = 'http://' + match
                suspicious_links.append(match)
        
        return list(set(suspicious_links))
    
    def _extract_keywords(self, text: str) -> List[str]:
        """Extract suspicious keywords from text."""
        text_lower = text.lower()
        found_keywords = []
        
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in text_lower:
                found_keywords.append(keyword)
        
        return list(set(found_keywords))
    
    def extract_from_message(self, message: Message) -> ExtractedIntelligence:
        """Extract intelligence from a single message."""
        text = message.text
        
        # Extract raw matches
        bank_matches = self._extract_with_patterns(text, self.bank_re)
        upi_matches = self._extract_with_patterns(text, self.upi_re)
        phone_matches = self._extract_with_patterns(text, self.phone_re)
        link_matches = self._extract_with_patterns(text, self.link_re)
        
        # Filter and validate
        return ExtractedIntelligence(
            bankAccounts=self._filter_bank_accounts(bank_matches),
            upiIds=self._filter_upi_ids(upi_matches),
            phoneNumbers=self._filter_phone_numbers(phone_matches),
            phishingLinks=self._filter_links(link_matches),
            suspiciousKeywords=self._extract_keywords(text),
        )
    
    def extract_from_session(self, session: SessionState) -> ExtractedIntelligence:
        """Extract intelligence from all messages in session."""
        combined = ExtractedIntelligence()
        
        for message in session.messages:
            # Only extract from scammer messages
            if message.sender.lower() == "scammer":
                msg_intel = self.extract_from_message(message)
                combined = combined.merge(msg_intel)
        
        return combined
    
    def generate_agent_notes(
        self, 
        session: SessionState, 
        scam_type: str
    ) -> str:
        """Generate summary notes about the scam attempt."""
        intel = session.extractedIntelligence
        
        notes_parts = [f"Scam Type: {scam_type}"]
        
        # Tactics used
        tactics = []
        keywords = intel.suspiciousKeywords
        
        if any(k in keywords for k in ['urgent', 'immediately', 'asap', 'now']):
            tactics.append("urgency tactics")
        if any(k in keywords for k in ['blocked', 'suspended', 'legal action', 'arrest']):
            tactics.append("fear/threat tactics")
        if any(k in keywords for k in ['prize', 'lottery', 'winner', 'reward', 'cashback']):
            tactics.append("reward bait")
        if any(k in keywords for k in ['bank', 'rbi', 'government', 'official']):
            tactics.append("authority impersonation")
        if any(k in keywords for k in ['otp', 'pin', 'password', 'cvv']):
            tactics.append("credential harvesting")
        if any(k in keywords for k in ['upi', 'transfer', 'payment']):
            tactics.append("payment redirection")
        
        if tactics:
            notes_parts.append(f"Tactics used: {', '.join(tactics)}")
        
        # Data requested/shared
        if intel.upiIds:
            notes_parts.append(f"UPI IDs shared: {len(intel.upiIds)}")
        if intel.phoneNumbers:
            notes_parts.append(f"Phone numbers: {len(intel.phoneNumbers)}")
        if intel.phishingLinks:
            notes_parts.append(f"Suspicious links: {len(intel.phishingLinks)}")
        if intel.bankAccounts:
            notes_parts.append(f"Bank accounts mentioned: {len(intel.bankAccounts)}")
        
        notes_parts.append(f"Total messages exchanged: {session.totalMessages}")
        
        return ". ".join(notes_parts)
