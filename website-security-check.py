import requests
from bs4 import BeautifulSoup

# url to scrape
url = "Url"

# make a request to the url
response = requests.get(url)

# extract the source code
html = response.text

# create a BeautifulSoup object
soup = BeautifulSoup(html, "html.parser")

# search for common patterns that indicate potential bugs
if soup.find("script", {"src": "http://malicious-site.com/hack.js"}):
    print("Possible injection attack detected!")
if soup.find("form", {"action": "http://malicious-site.com/steal-data.php"}):
    print("Possible form-based attack detected!")
if soup.find("input", {"name": "password", "type": "hidden"}):
    print("Possible password-stealing attack detected!")

