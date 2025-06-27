WILL UPDATE SOON

# Phishing-Email-URL-scanner
A simple scanner that uses OAuth2 to log into a Gmail account and scan URLs in each email using urlscan.io to determine whether or not it is a phishing scam.

----------------
Set up a Google Cloud Project with Gmail API access:
---
Go to https://console.cloud.google.com

Create a new project (or use an existing one).

Enable the Gmail API.

Go to OAuth consent screen → Choose "External" and fill it in.

Go to Credentials → Create credentials → OAuth client ID.

Choose Desktop app

Download the credentials.json file
---

Use OAuth 2.0 to get permission to access a Gmail account.

Use the Gmail API (via google-api-python-client) to fetch messages.

Parse them for URLs and send them to your urlscanner.io Selenium pipeline.

----
We’ll use Selenium to:

Load https://urlscanner.io/.

Paste the URL.

Wait for the scan.

Parse results (scam score, AI summary, etc.).


Download ChromeDriver from https://chromedriver.chromium.org/downloads and make sure it's in your PATH.
----

----------------
pip install --upgrade google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client
