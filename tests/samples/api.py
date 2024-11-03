import requests
import xml.etree.ElementTree as ET

def fetch_user_data(user_id):
    """Insecure API endpoint"""
    # Security Issue 1: No input validation
    # Security Issue 2: No SSL verification
    response = requests.get(f"http://api.example.com/users/{user_id}", verify=False)
    return response.json()

def parse_xml_data(xml_string):
    """Insecure XML parsing"""
    # Security Issue 3: XML External Entity (XXE) vulnerability
    parser = ET.XMLParser()
    tree = ET.fromstring(xml_string, parser=parser)
    return tree

def send_request(url, data):
    """Insecure request handling"""
    # Security Issue 4: No input sanitization
    # Security Issue 5: Unverified SSL
    response = requests.post(url, json=data, verify=False)
    return response.text

def process_response(response_data):
    """Insecure response handling"""
    # Security Issue 6: Unsafe deserialization
    # Security Issue 7: No content type validation
    return eval(response_data)
