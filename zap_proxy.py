import time
import json
from urllib.parse import parse_qs
from xml.etree import ElementTree as ET
from zapv2 import ZAPv2

with open("config.json", "r") as file:
    config = json.load(file)

# Retrieve configuration settings
zap_key = config.get("zap_api_key")
proxy = config.get("proxy")

apikey = zap_key

# Create ZAP instance
zap = ZAPv2(apikey=apikey, proxies=proxy)

# Retrieve all recorded sites
sites = zap.core.sites
print(sites)

# Status code filtering
filter_status_codes = [200, 401, 201]

# Dictionary to avoid duplicates (key: URL + request body shape, value: True)
processed_requests = {}

# List to store data to be saved in JSON file
post_requests_data = []

# Retrieve recorded requests and responses for specific sites
for site in sites:
    # Retrieve the list of requests for that site
    history = zap.core.messages(site)
    
    # Loop through the retrieved requests and responses
    for message in history:
        # Retrieve status code from the response header
        response_header = message['responseHeader']
        if response_header:
            # Extract status code (e.g., get 200 from 'HTTP/1.1 200 OK')
            status_code = int(response_header.split(' ')[1])

            # Filter if status code is 200 or 401
            if status_code in filter_status_codes:
                # Check if the request type is POST or GET
                request_header = message['requestHeader']
                request_method = request_header.split(' ')[0]  # Get the GET or POST part

                # Extract URL and request body
                request_url = request_header.split(' ')[1]
                request_body = message['requestBody'] if "POST" in request_method else ""  # GET usually has no body

                content_type = ""

                # Retrieve Content-Type header (for POST requests)
                if "POST" in request_method:
                    for header in request_header.splitlines():
                        if "Content-Type" in header:
                            content_type = header.split(": ")[1]
                            break

                # If the request is POST, determine if the body is in JSON, XML, multipart, binary, plain text, etc.
                try:
                    if "POST" in request_method:
                        if "application/json" in content_type:
                            # Load as JSON
                            body_json = json.loads(request_body)
                            if isinstance(body_json, dict):
                                # Extract JSON key structure
                                body_shape = tuple(sorted(body_json.keys()))
                            else:
                                body_shape = str(body_json)
                        elif "application/xml" in content_type:
                            # Load as XML
                            xml_tree = ET.ElementTree(ET.fromstring(request_body))
                            body_shape = tuple([elem.tag for elem in xml_tree.iter()])
                        elif "multipart/form-data" in content_type:
                            # Parse multipart data (ignore actual file content)
                            body_shape = tuple(request_body.split('--')[1::2])  # Use boundaries as keys
                        elif "application/octet-stream" in content_type:
                            # Binary data as-is
                            body_shape = "binary_data"
                        elif "text/plain" in content_type:
                            # Plain text
                            body_shape = request_body
                        else:
                            # Form data or other formats
                            try:
                                form_data = parse_qs(request_body)
                                body_shape = tuple(sorted(form_data.keys()))
                            except Exception:
                                body_shape = request_body
                    else:
                        # For GET requests, use URL and parameters as key
                        body_shape = request_url
                except Exception as e:
                    # If parsing fails, treat the whole body as shape
                    print(f"Parsing error: {e}")
                    body_shape = request_body if "POST" in request_method else request_url

                # Check for duplicates based on URL and request body shape
                request_key = f"{request_url}|{body_shape}"

                if request_key not in processed_requests:
                    # Process and record if first-time request
                    processed_requests[request_key] = True
                    
                    # Display request and response
                    if request_body:
                        print("Request Body: ", request_body)
                    
                    # Add to JSON data only if the request is POST
                    if "POST" in request_method:
                        print(f"Request Method: {request_method}")
                        print("Request URL: ", request_url)
                        print("Request header: ", request_header)
                        if request_body:
                           print("Request Body: ", request_body)
                        post_requests_data.append({
                            'url': request_url,
                            'request_header': request_header,
                            'request_body': request_body,
                            'response_header': response_header,
                            'response_body': message['responseBody']
                        })
                else:
                    # Skip duplicate requests
                    print(f"Skipped duplicate {request_method} request with same body shape to {request_url}")
                    if request_body:
                        print("Request Body: ", request_body)

# Save POST request and response data to JSON file
with open('post_requests_data.json', 'w', encoding='utf-8') as f:
    json.dump(post_requests_data, f, ensure_ascii=False, indent=4)

print("POST request and response data has been saved to 'post_requests_data.json'.")
