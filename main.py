import base64  # msgs are encoded in base64 so we need to decode them
from email import message_from_bytes  # converts raw email bytes into a structured Python email.message object
import re

# selenium stuff
from selenium import webdriver  # selenium api to contorl browsers
from selenium.webdriver.common.by import By  # to find elements by id
from selenium.webdriver.common.keys import Keys  # simulate keyboard
from selenium.webdriver.chrome.options import Options  # browser options (like headless mode)
from selenium.webdriver.support.ui import WebDriverWait  # wait dynamically until elements appear
from selenium.webdriver.support import expected_conditions as EC


# for cred stuff
import os.path

# idk i guess why not
import os

# google API stuff
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from config import *


def get_credentials():
    # get creds from the json if it exists

    creds = None

    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    # If no valid credentials, do OAuth flow
    if creds == None or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # create new flow
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    return creds

def get_messages(service, query='is:unread'):

    # select users function, then messages functions, then lists msgs querrying by "me", then execute sends the request to google
    results = service.users().messages().list(userId='me', q=query).execute()

    # gets an object containing the messages, defaults to "[]"
    messages = results.get('messages', [])

    return messages


def get_message_detail(service, msg_id):

    # get the raw bytes from the specific email with the id 'msg_id'. this returns a json object
    msg = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()

    # decode the message from base64 using urlsafe (gmail's default i think), using UTF-8 encoding
    raw_msg = base64.urlsafe_b64decode(msg['raw'].encode('UTF-8'))

    # get the actual email from the raw message
    email_msg = message_from_bytes(raw_msg)

    return email_msg


def extract_urls(text):
    # anything with an http or https beginning is treated like a url
    url_pattern = r'https?://[^\s<>"\'()]+'
    return re.findall(url_pattern, text)

class Scanner:
    def __init__(self):

        creds = get_credentials()

        # builds the API object, version 1, using the creds from the token.json file
        self.service = build('gmail', 'v1', credentials=creds)

        self.options = Options()  # build browser object
        self.options.add_argument("--headless")
        self.options.add_argument("--no-sandbox")

        if os.name != 'nt':  # unix compatibility
            self.options.add_argument("--disable-dev-shm-usage")

        # get selenium driver
        self.driver = webdriver.Chrome(options=self.options)

        self.messages = get_messages(self.service)

    def update(self):
        self.messages = get_messages(self.service)

    def urlscanner(self, url):

        # send links to url scanner and return url results
        try:
            self.driver.get("https://urlscan.io/")
            input_box = self.driver.find_element(By.CSS_SELECTOR, "input[type='text']")
            input_box.send_keys(url)
            input_box.send_keys(Keys.RETURN)

            print("Scanning started, waiting for results...")

            wait = WebDriverWait(self.driver, 60)  # Wait up to 60 seconds

            verdict_element = wait.until(
                EC.presence_of_element_located((By.CLASS_NAME, "text-muted"))  # Based on html
            )

            verdict_text = verdict_element.text.strip()  # get the urlscan verdict

            return {
                'url': url,
                'verdict': verdict_text
                }
        
        except Exception as e:
            return {'url': url, 'error': str(e)}
        
        finally:
            self.driver.quit()

    def start(self):

        self.update()

        for m in self.messages:
            msg_obj = get_message_detail(self.service, m['id'])

            subject = msg_obj['subject']
            sender = msg_obj['from']
            body = None

            # check if email is multipart
            if msg_obj.is_multipart():
                # parse the email
                for part in msg_obj.walk():
                    if part.get_content_type() == 'text/plain':  # obvious
                        body = part.get_payload(decode=True).decode()  # decode the raw bytes
                        break
            else:
                body = msg_obj.get_payload(decode=True).decode()

            print(f"\nEmail from: {sender}")
            print(f"Subject: {subject}")

            # get urls
            urls = extract_urls(body)
            
            # scan urls
            for url in urls:
                result = self.urlscanner(url)
                print(f"Scanned {url}:")
                print(result)


        self.driver.quit()


def main():
    scanner = Scanner()
    scanner.start()


if __name__ == "__main__":
    main()