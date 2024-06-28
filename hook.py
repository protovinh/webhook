import os.path
import pickle
import base64
import json
from email import message_from_bytes
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import requests

# If modifying these SCOPES, delete the file token.pickle.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def get_credentials():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    return creds

def fetch_emails():
    creds = get_credentials()
    service = build('gmail', 'v1', credentials=creds)
    
    results = service.users().messages().list(userId='me', labelIds=['INBOX'], q='is:unread').execute()
    messages = results.get('messages', [])
    
    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id'], format='raw').execute()
        msg_str = base64.urlsafe_b64decode(msg['raw'].encode('ASCII'))
        mime_msg = message_from_bytes(msg_str)
        
        # Extract necessary parts of the email
        email_data = {
            'subject': mime_msg['subject'],
            'from': mime_msg['from'],
            'to': mime_msg['to'],
            'date': mime_msg['date'],
            'body': extract_body(mime_msg)  # Extract body or content here
        }
        
        # Convert email_data to JSON-serializable format
        json_data = json.dumps(email_data, default=str)  # Use default=str to handle datetime objects
        
        # Send email data to webhook
        response = requests.post('http://localhost:5000/webhook', json=json.loads(json_data))
        if response.status_code == 200:
            print(f"Email sent to webhook successfully: {email_data['subject']}")
        else:
            print(f"Failed to send email to webhook: {email_data['subject']}")

def extract_body(message):
    """Extract the body or main content of the email."""
    payload = message.get_payload()
    if isinstance(payload, list):
        # If multipart email, return the first part (plaintext)
        return payload[0].get_payload()
    else:
        # If single part email, return the payload directly
        return payload

if __name__ == '__main__':
    fetch_emails()
