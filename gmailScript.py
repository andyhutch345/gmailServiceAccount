from googleapiclient.discovery import build
from oauth2client.service_account import ServiceAccountCredentials
from httplib2 import Http
import json
import base64
import email
import pyrebase
import re
from email.utils import parseaddr
from apiclient import errors

"""Email of the Service Account"""
SERVICE_ACCOUNT_EMAIL = '<enter service account email>'
"""Path to the Service Account's Private Key file"""
SERVICE_ACCOUNT_JSON_FILE_PATH = '<enter json file path>'
"""Scopes needed of the GSuite account. Must gave granted service account access to these scopes. """
SCOPES = ['https://www.googleapis.com/auth/admin.reports.audit.readonly', 'https://mail.google.com/']

config = {
  "apiKey": "<enter api key here>",
  "authDomain": "<enter auth domain here>",
  "databaseURL": "<enter db url>",
  "storageBucket": "<enter storageBucket>",
  "serviceAccount": "<enter service account json>"
}

firebase = pyrebase.initialize_app(config)

def pushToFirebase(b64email, sender, source, subject, date, msg_id):
    auth = firebase.auth()
    db = firebase.database()
    cleanSender = sender.replace('.', ',');
    if "fwd: " in subject:
      subject = subject.split("fwd: ")[1]
    if "Fwd: " in subject:
      subject = subject.split("Fwd: ")[1]
    emailData = {
        "date": date,
        "subject": subject,
        "content": b64email,
        "sourceName": source[0],
        "sourceAddress": source[1],
        "msg_id": msg_id,
    }
    db.child("emails").child(cleanSender).child(msg_id).set(emailData)

def deleteMessage(service, user_id, msg_id):
  """Delete a Message.

  Args:
    service: Authorized Gmail API service instance.
    user_id: User's email address. The special value "me"
    can be used to indicate the authenticated user.
    msg_id: ID of Message to delete.
  """
  try:
    service.users().messages().delete(userId=user_id, id=msg_id).execute()
    #print 'Message with id: %s deleted successfully.' % msg_id
  except errors.HttpError, error:
    print 'An error occurred: %s' % error

def getSource(message, forwarder):
  sections = message.split("From: ")
  EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")
  for section in sections:
    potentialSender = section.split(">")[0]
    emailSplit = parseaddr(potentialSender)
    if EMAIL_REGEX.match(emailSplit[1]):
      if not (emailSplit[1] == forwarder or emailSplit[1] == "<enter email here>"):
        #print(emailSplit[0], emailSplit[1])
        return emailSplit

def getMessage(service, user_id, msg_id):
  """Get a Message with given ID.

  Args:
    service: Authorized Gmail API service instance.
    user_id: User's email address. The special value "me"
    can be used to indicate the authenticated user.
    msg_id: The ID of the Message required.

  Returns:
    A Message.
  """
  try:
    message = service.users().messages().get(userId=user_id, id=msg_id,
                                             format='raw').execute()
    metadata = service.users().messages().get(userId=user_id, id=msg_id,
                                             format='metadata').execute()
    #print 'Message snippet: %s' % message['snippet']
    headers = metadata['payload']['headers']
    for value in headers:
        if value['name'] == 'Date':
            date = value['value']
        if value['name'] == 'Subject':
            subject = value['value']
        if value['name'] == 'From':
            sender = value['value']
            if "<" in sender:
              sender = sender.split('<')[1]
            if ">" in sender:
              sender = sender.split('>')[0]
    msg_str = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))
    source = getSource(msg_str, sender)
    pushToFirebase(message['raw'], sender, source, subject, date, msg_id)
    deleteMessage(service, "me", msg_id)
    #mime_msg = email.message_from_string(msg_str)

    #print(msg_str)
  except errors.HttpError, error:
    print 'An error occurred: %s' % error
  

def pullemails():
    """ 
    Pull the emails from the gsuite account. 
    """
    credentials = ServiceAccountCredentials.from_json_keyfile_name(
        SERVICE_ACCOUNT_JSON_FILE_PATH, SCOPES)
    credentials = credentials.create_delegated("<enter email here>")

    service = build('gmail', 'v1', credentials = credentials)
    results = service.users().messages().list(userId='me').execute()
    messages = results.get('messages', [])

    if not messages:
        print('No messages found.')
    else:
          #print('messages:')
          for message in messages:
            getMessage(service, "me", message['id'])

while(True):
  try:
    pullemails()
  except:
    print("Timeout error while reading email, restarting")
