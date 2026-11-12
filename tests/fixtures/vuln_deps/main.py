"""
Vulnerable dependency consumer app.
"""
import requests

def fetch_data(url: str):
    return requests.get(url).text
