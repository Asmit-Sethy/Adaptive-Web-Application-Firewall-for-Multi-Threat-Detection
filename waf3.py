from flask import Flask, request, abort, jsonify, make_response
import requests
import re

app = Flask(__name__)

# SQL Injection patterns
SQLI_PATTERNS = [
    r"(?i)(\b(select|insert|update|delete|from|where|or|and|=|;|--|#)\b)",
    r"(?i)'.*' OR '.*'='.*",
    r"(?i)'.*' AND '.*'='.*",
]
# Function to detect SQL Injection from query parameters
def detect_sqli_in_query(query_params):
    sqli_regex = re.compile('|'.join(SQLI_PATTERNS), re.IGNORECASE)
    
    for key, value in query_params.items():
        if sqli_regex.search(value):
            return True  # SQL Injection detected
    return False

# Function to forward the request to DVWA
def forward_request_to_dvwa():
    dvwa_url = "http://localhost:8081"  # DVWA running on port 8081
    response = requests.request(
        method=request.method, 
        url=dvwa_url + request.path,  # Forward the request path to DVWA
        headers={key: value for key, value in request.headers if key.lower() != 'host'},  # Forward all headers except 'Host'
        data=request.get_data(),  # Forward the body of the request
        cookies=request.cookies,  # Forward cookies
        allow_redirects=False
    )
    
    # Forward the response from DVWA back to the client
    return make_response(response.content, response.status_code, [(name, value) for name, value in response.raw.headers.items()])

@app.route('/', methods=['POST', 'GET'])
@app.route('/<path:path>', methods=['POST', 'GET'])  # Capture all paths
def process_request(path=''):
    # Extract query parameters from the request
    query_params = request.args.to_dict()

    # Detect SQL Injection in query parameters
    if detect_sqli_in_query(query_params):
        # Respond with a custom message if SQL Injection is detected
        return make_response("Malicious SQL Injection Detected", 403)

    # If no SQL Injection is found, forward the request to DVWA
    return forward_request_to_dvwa()

if __name__ == '__main__':
    # Start the WAF on port 8443 with SSL
    app.run(ssl_context=('certificate.crt', 'private.key'), port=8443, debug=True)
