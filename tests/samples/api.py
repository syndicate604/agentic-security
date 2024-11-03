import json
import requests
import defusedxml.ElementTree as ET

def fetch_user_data(user_id):
    """Insecure API endpoint"""
    # Security Issue 1: No input validation
    # Security Issue 2: No SSL verification
    response = requests.get(f"http://api.example.com/users/{user_id}", verify=False)
    return response.json()

from defusedxml import ElementTree as ET
import re
import logging

def parse_xml_data(xml_string):
    """Secure XML parsing with XXE protection"""
    # Disable external entity resolution to prevent XXE attacks
    parser = ET.XMLParser(resolve_entities=False)

    # Validate and sanitize input XML string
    try:
        xml_string = xml_string.strip()
        if not xml_string:
            raise ValueError("Invalid XML string: Empty input")
        
        # Additional input validation
        # Reject XML strings with potential malicious patterns
        malicious_patterns = [r'<!ENTITY', r'<!DOCTYPE']
        for pattern in malicious_patterns:
            if re.search(pattern, xml_string, re.IGNORECASE):
                raise ValueError("Invalid XML string: Potential XXE attack detected")
    except ValueError as e:
        # Handle invalid input with proper error logging
        logging.error(f"Error: {e}")
        return None

    # Parse XML string securely
    try:
        tree = ET.fromstring(xml_string, parser=parser)
    except ET.ParseError as e:
        # Handle XML parsing errors with proper error logging
        logging.error(f"Error: {e}")
        return None

    # Additional input sanitization
    # Remove potential malicious nodes from the parsed tree
    sanitize_tree(tree)

    return tree

def sanitize_tree(tree):
    """Sanitize the parsed XML tree to remove potential malicious nodes"""
    # Remove nodes with potentially malicious content
    malicious_tags = ['ENTITY', 'DOCTYPE'] 
    for elem in tree.iter():
        if elem.tag in malicious_tags:
            elem.getparent().remove(elem)

def sanitize_tree(tree):
    """Sanitize the parsed XML tree to remove potential malicious nodes"""
    # Implementation details for sanitize_tree go here
    pass

def send_request(url, data):
    """Insecure request handling"""
    # Security Issue 4: No input sanitization
    # Security Issue 5: Unverified SSL
    response = requests.post(url, json=data, verify=False)
    return response.text

def process_response(response_data):
    """Secure response handling"""
    try:
        return json.loads(response_data)
    except json.JSONDecodeError:
        # Handle invalid JSON data
        return None
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
import defusedxml.ElementTree as ET
import subprocess

def make_request(url):
    # Insecure request
    return requests.get(url, verify=False)

def parse_xml(xml_string):
    """Secure XML parsing with XXE protection"""
    # Disable external entity resolution to prevent XXE attacks
    parser = ET.XMLParser(resolve_entities=False)
    
    # Validate and sanitize input XML string
    try:
        xml_string = xml_string.strip()
        if not xml_string:
            raise ValueError("Empty XML string")
    except ValueError as e:
        # Handle invalid input
        print(f"Error: {e}")
        return None
    
    # Parse XML string securely
    try:
        tree = ET.fromstring(xml_string, parser=parser)
    except ET.ParseError as e:
        # Handle XML parsing errors
        print(f"Error: {e}")
        return None
    
    return tree

import shlex

def execute_command(cmd):
    # Secure command execution
    cmd_args = shlex.split(cmd)
    result = subprocess.run(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout
