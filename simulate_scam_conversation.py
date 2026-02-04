"""
Simulation script to test scam detection and intelligence extraction.

This script simulates a realistic multi-turn scam conversation with:
- UPI IDs, bank accounts, phishing links, phone numbers
- Progressive revelation of scam artifacts across messages
- Server responses for each message
- Final payload inspection

Usage:
    python simulate_scam_conversation.py
"""

import requests
import json
import time
from datetime import datetime, timezone

# Configuration
API_URL = "http://localhost:8000/api/v1/honeypot"
API_KEY = "ABCD-1214-JJF"
SESSION_ID = f"sim-test-{int(time.time())}"

# Color codes for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"


def print_header(text):
    """Print formatted header."""
    print(f"\n{CYAN}{'='*80}{RESET}")
    print(f"{CYAN}{text.center(80)}{RESET}")
    print(f"{CYAN}{'='*80}{RESET}\n")


def print_message(sender, text, response_status=None):
    """Print formatted message."""
    color = RED if sender == "scammer" else GREEN
    print(f"{color}[{sender.upper()}]{RESET} {text}")
    if response_status:
        print(f"{YELLOW}  → Status: {response_status}{RESET}")


def send_message(session_id, sender, text, conversation_history=None):
    """Send a message to the honeypot API."""
    payload = {
        "sessionId": session_id,
        "message": {
            "sender": sender,
            "text": text,
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        "conversationHistory": conversation_history or [],
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }
    
    headers = {
        "x-api-key": API_KEY,
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(API_URL, json=payload, headers=headers, timeout=60)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"{RED}ERROR: {e}{RESET}")
        return None


def get_session_state(session_id):
    """Retrieve session state from API."""
    url = f"http://localhost:8000/api/v1/session/{session_id}"
    headers = {"x-api-key": API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"{RED}ERROR fetching session: {e}{RESET}")
        return None


def print_extracted_intelligence(session_data):
    """Print extracted intelligence in a formatted way."""
    if not session_data or session_data.get("status") != "success":
        print(f"{RED}Failed to retrieve session data{RESET}")
        return
    
    session = session_data.get("session", {})
    intel = session.get("extractedIntelligence", {})
    
    print_header("EXTRACTED INTELLIGENCE")
    
    print(f"{BLUE}UPI IDs:{RESET}")
    for upi in intel.get("upiIds", []):
        print(f"  ✓ {upi}")
    
    print(f"\n{BLUE}Bank Accounts:{RESET}")
    for acc in intel.get("bankAccounts", []):
        print(f"  ✓ {acc}")
    
    print(f"\n{BLUE}Phishing Links:{RESET}")
    for link in intel.get("phishingLinks", []):
        print(f"  ✓ {link}")
    
    print(f"\n{BLUE}Phone Numbers:{RESET}")
    for phone in intel.get("phoneNumbers", []):
        print(f"  ✓ {phone}")
    
    print(f"\n{BLUE}Suspicious Keywords:{RESET}")
    keywords = intel.get("suspiciousKeywords", [])
    if keywords:
        print(f"  {', '.join(keywords[:10])}{'...' if len(keywords) > 10 else ''}")
    
    print(f"\n{BLUE}Session Stats:{RESET}")
    print(f"  Total Messages: {session.get('totalMessages', 0)}")
    print(f"  Scam Detected: {session.get('scamDetected', False)}")
    print(f"  Scam Suspected: {session.get('scamSuspected', False)}")
    print(f"  Confidence Score: {session.get('scamConfidenceScore', 0):.2f}")
    print(f"  Callback Sent: {session.get('callbackSent', False)}")


def print_callback_payload(session_data):
    """Print what the callback payload would look like."""
    if not session_data or session_data.get("status") != "success":
        return
    
    session = session_data.get("session", {})
    intel = session.get("extractedIntelligence", {})
    
    callback_payload = {
        "sessionId": session.get("sessionId"),
        "scamDetected": session.get("scamDetected", False),
        "totalMessagesExchanged": session.get("totalMessages", 0),
        "extractedIntelligence": {
            "bankAccounts": intel.get("bankAccounts", []),
            "upiIds": intel.get("upiIds", []),
            "phishingLinks": intel.get("phishingLinks", []),
            "phoneNumbers": intel.get("phoneNumbers", []),
            "suspiciousKeywords": intel.get("suspiciousKeywords", [])
        },
        "agentNotes": session.get("agentNotes", "")
    }
    
    print_header("CALLBACK PAYLOAD (Would be sent to GUVI)")
    print(json.dumps(callback_payload, indent=2))


def main():
    """Run the simulation."""
    print_header("SCAM CONVERSATION SIMULATION")
    print(f"{YELLOW}Session ID: {SESSION_ID}{RESET}\n")
    
    # Simulated scam conversation with progressive artifact revelation
    scam_messages = [
        # Message 1: Initial urgency + threat
        "Your bank account will be BLOCKED in 24 hours! Verify your details immediately to avoid suspension.",
        
        # Message 3: First artifact - phone number
        "Call our customer care at +91-9876543210 NOW to unblock your account!",
        
        # Message 5: UPI ID revelation
        "Send Rs. 500 to scammer@paytm for verification. This is urgent!",
        
        # Message 7: Phishing link + more pressure
        "Click here to verify: http://fake-bank-login.com/verify?id=12345 or your account will be closed!",
        
        # Message 9: Bank account details
        "Transfer to account number 1234567890123456 IFSC: SBIN0001234 to restore your account immediately!",
    ]
    
    conversation_history = []
    message_count = 0
    max_messages = 10
    
    for i, scam_text in enumerate(scam_messages):
        if message_count >= max_messages:
            break
        
        # Scammer message
        print(f"\n{YELLOW}--- Message {message_count + 1} ---{RESET}")
        print_message("scammer", scam_text)
        
        result = send_message(SESSION_ID, "scammer", scam_text, conversation_history)
        
        if not result:
            print(f"{RED}Failed to send message. Stopping simulation.{RESET}")
            break
        
        # Update conversation history
        conversation_history.append({
            "sender": "scammer",
            "text": scam_text,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        message_count += 1
        
        # Check if message was ignored (not detected as scam)
        if result.get("status") == "ignored":
            print(f"{RED}⚠️  Message was IGNORED (not detected as scam){RESET}")
            print(f"{RED}   Reason: {result.get('reason', 'unknown')}{RESET}")
            print(f"\n{YELLOW}Stopping simulation - ML model did not classify as scam.{RESET}")
            break
        
        # Agent response
        agent_reply = result.get("reply", "")
        if agent_reply:
            print_message("user", agent_reply, result.get("status"))
            
            # Update conversation history with agent response
            conversation_history.append({
                "sender": "user",
                "text": agent_reply,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            message_count += 1
        
        # Small delay to simulate realistic timing
        time.sleep(0.5)
    
    # Final session state
    print_header("FINAL SESSION STATE")
    session_data = get_session_state(SESSION_ID)
    
    if session_data:
        print_extracted_intelligence(session_data)
        print()
        print_callback_payload(session_data)
    
    print(f"\n{GREEN}Simulation complete!{RESET}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Simulation interrupted by user{RESET}")
    except Exception as e:
        print(f"\n{RED}Unexpected error: {e}{RESET}")
        import traceback
        traceback.print_exc()
