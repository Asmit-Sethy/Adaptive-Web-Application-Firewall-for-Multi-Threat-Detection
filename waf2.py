#--------------ALTERNATE FILE FOR WAF, BUT FORWARDS REQUESTS TO DVWA (LOCALHOST)----------------------



from flask import Flask, request, abort, jsonify, make_response
import requests
import re
import time
from collections import defaultdict
import threading

app = Flask(__name__)

# Rate limiting configuration for DDoS protection
RATE_LIMIT_WINDOW = 60  # Time window in seconds (e.g., 60 seconds)
MAX_REQUESTS_PER_IP = 3  # Max allowed requests from the same IP in the time window
ALLOW_FIRST_REQUESTS = 1  # Allow the first N requests to succeed before DDoS detection

# Dictionary to track IP request timestamps and their corresponding request bodies
request_log = defaultdict(list)

csrf_protection_active = False  # Global flag for CSRF protection status

# Timer to activate CSRF protection after 2 minutes (120 seconds)
def activate_csrf_protection():
    global csrf_protection_active
    time.sleep(120)  # Wait for 2 minutes
    csrf_protection_active = True
    print("CSRF protection is now active.")

# Start the CSRF activation timer in a separate thread when the app starts
csrf_timer = threading.Thread(target=activate_csrf_protection)
csrf_timer.start()

# Read vulnerable SQL queries from a file and return them as a list
def load_vulnerable_sql_patterns(file_path):
    with open(file_path, 'r') as file:
        queries = file.readlines()  
        return [query.strip() for query in queries if query.strip()]

# Malicious SQLi detection function that uses the loaded vulnerable SQL patterns
def detect_malicious_sqli(input_data, vulnerable_sql_patterns):
    sqli_regex = re.compile('|'.join([re.escape(pattern) for pattern in vulnerable_sql_patterns]), re.IGNORECASE)
    
    # Check if any input data matches the SQLi patterns
    for value in input_data.values():
        if sqli_regex.search(value):
            return True  # SQLi found
    
    return False

# Directory traversal detection function using vulnerable traversal patterns
def detect_directory_traversal(input_data, traversal_patterns):
    traversal_regex = re.compile('|'.join([re.escape(pattern) for pattern in traversal_patterns]), re.IGNORECASE)
    
    # Check if any input data matches the directory traversal patterns
    for value in input_data.values():
        if traversal_regex.search(value):
            return True  # Directory traversal found
    
    return False

# Malicious XSS detection function
def detect_malicious_xss(input_data, xss_patterns):
    xss_regex = re.compile('|'.join([re.escape(pattern) for pattern in xss_patterns]), re.IGNORECASE)
    
    # Check if any input data matches the XSS patterns
    for value in input_data.values():
        if xss_regex.search(value):
            return True  # XSS found
    
    return False

# CSRF detection function
def detect_csrf():
    # Check if CSRF protection is active
    if csrf_protection_active:
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token or csrf_token != 'valid_csrf_token':
            return True  # CSRF attack detected
    return False

# Function to track and detect DDoS based on same request content
def detect_ddos(ip, request_body):
    current_time = time.time()
    
    # Clean up old requests beyond the window
    request_log[ip] = [(timestamp, body) for timestamp, body in request_log[ip] if current_time - timestamp <= RATE_LIMIT_WINDOW]
    
    # Allow the first N requests to succeed
    if len(request_log[ip]) < ALLOW_FIRST_REQUESTS:
        request_log[ip].append((current_time, request_body))
        return False  # Allow the request without detection
    
    # Count the requests with the same body
    same_request_count = sum(1 for _, body in request_log[ip] if body == request_body)

    # Check if current request exceeds the max allowed requests in the window
    if same_request_count >= MAX_REQUESTS_PER_IP:
        return True  # DDoS detected
    
    # Log the current request time and body
    request_log[ip].append((current_time, request_body))
    return False

# Function to forward the request to DVWA backend
def forward_request_to_backend():
    dvwa_url = "http://localhost:8081"  # DVWA running on port 8000
    # Forward the request to DVWA, including the headers and data
    response = requests.request(
        method=request.method, 
        url=dvwa_url + request.path,  # Forward the request path to DVWA
        headers={key: value for key, value in request.headers if key != 'Host'},  # Forward all headers except 'Host'
        data=request.get_data(),  # Forward the body of the request
        cookies=request.cookies,  # Forward cookies
        allow_redirects=False
    )
    
    # Forward the response from DVWA back to the client
    response_headers = [(name, value) for name, value in response.raw.headers.items()]
    return make_response(response.content, response.status_code, response_headers)

# Load directory traversal patterns from a file
def load_directory_traversal_patterns(file_path):
    with open(file_path, 'r') as file:
        patterns = file.readlines()
        return [pattern.strip() for pattern in patterns if pattern.strip()]

# Load XSS patterns from a file
def load_xss_patterns(file_path):
    with open(file_path, 'r') as file:
        patterns = file.readlines()
        return [pattern.strip() for pattern in patterns if pattern.strip()]

@app.route('/', methods=['POST', 'GET'])
def process_request():
    # Get the client's IP address
    client_ip = request.remote_addr
    
    # Load SQLi patterns from the file (this could be optimized to load once)
    vulnerable_sql_patterns = load_vulnerable_sql_patterns('vulnerable_queries.txt')
    
    # Load directory traversal patterns from the file
    traversal_patterns = load_directory_traversal_patterns('directory_traversal_patterns.txt')
    
    # Load XSS patterns from the file
    xss_patterns = load_xss_patterns('xss_patterns.txt')
    
    # Parse form data, query params, or JSON body
    form_data = request.form.to_dict() or request.args.to_dict() or request.get_json()
    
    # Check for malicious SQL Injection patterns
    if detect_malicious_sqli(form_data, vulnerable_sql_patterns):
        return abort(403, description="Malicious SQL Injection Detected")
    
    # Check for directory traversal patterns
    if detect_directory_traversal(form_data, traversal_patterns):
        return abort(403, description="Directory Traversal Detected")
    
    # Check for malicious XSS patterns
    if detect_malicious_xss(form_data, xss_patterns):
        return abort(403, description="Malicious XSS Detected")

    # Check for CSRF attack
    if detect_csrf():
        return abort(403, description="CSRF Attack Detected")
    
    # Detect DDoS attack based on request frequency and body
    request_body = request.data.decode('utf-8')  # Get the raw request body
    if detect_ddos(client_ip, request_body):
        return jsonify({'status': 'error', 'attack_type': 'DDoS', 'message': 'Too Many Requests - DDoS Attack Suspected'}), 429

    # Forward the request if no malicious activity is found
    return forward_request_to_backend()

if __name__ == '__main__':
    # Start the WAF with SSL (use your certificate and private key)
    app.run(ssl_context=('certificate.crt', 'private.key'), port=8443, debug=True)
