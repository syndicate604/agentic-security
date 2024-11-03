import requests
from defusedxml import ElementTree as ET

def fetch_user_data(user_id):
    """Insecure API endpoint"""
    # Security Issue 1: No input validation
    # Security Issue 2: No SSL verification
    response = requests.get(f"http://api.example.com/users/{user_id}", verify=False)
    return response.json()

from defusedxml import ElementTree as ET

def parse_xml_data(xml_string):
    """Secure XML parsing with XXE protection"""
    tree = ET.parse(xml_string)
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
# Sample vulnerable API code
import requests
from defusedxml import ElementTree as ET

def make_request(url):
    # SSL verification disabled
    return requests.get(url, verify=False)

import defusedxml.ElementTree as ET

def parse_xml(xml_string):
    # Secure XML parsing
    parser = ET.XMLParser(resolve_entities=False)
    return ET.fromstring(xml_string, parser=parser)
import requests
import xml.etree.ElementTree as ET
import subprocess

def make_request(url):
    # Insecure request
    return requests.get(url, verify=False)

def parse_xml(xml_string):
    # Vulnerable to XXE
    return ET.fromstring(xml_string)

import shlex

def execute_command(cmd):
    # Secure command execution
    cmd_args = shlex.split(cmd)
    result = subprocess.run(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout
