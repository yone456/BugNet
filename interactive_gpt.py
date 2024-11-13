import pyfiglet
import openai
import requests
import json
import re
from datetime import datetime
import csv

max_iters = 4

report_thought = []
report_element = []
report_request = []
report_response_status_code = []
report_response_text = []

ascii_art = pyfiglet.figlet_format("BugNet")
print(ascii_art)

with open("config.json", "r") as file:
    config = json.load(file)

api_key = config.get("openai_api_key")
proxy = config.get("proxy")
proxies = proxy

def summary(Thought_list, report_thought):
    thoughts_text = "\n".join(Thought_list)
    response = openai.ChatCompletion.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": "Summarize the type of vulnerability being tested."},
        {"role": "user", "content": thoughts_text}
    ]
)

    summary = response['choices'][0]['message']['content']
    report_thought.append(summary)

    return report_thought

def judgement(element, request_data, response_data):
    
    request_data = str(request_data)
    system_prompt = """You are an assistant for vulnerability assessment. You are provided with normal communication request and response information before tampering, as well as the attack request used in the test and its result. Your goal is to determine if the attack request was successful based on this information. Output the result as either True or False."""

    user_prompt = f"""
Normal communication request and response information before tampering: {element}
Attack request: {request_data}
Status code: {response_data.status_code}
Response body: {response_data.text}
"""
   
    response = openai.ChatCompletion.create(
    model="gpt-4o",  
    messages=[
        {"role": "system", "content": system_prompt},  
        {"role": "user", "content": user_prompt}  
    ]
   )
    judge = response['choices'][0]['message']['content']
    
    return judge
    


def send_request_via_zap_proxy(request_data):
    url = request_data['url']
    headers = {}
    method = "POST"  
    body = request_data['request_body']

   
    header_lines = request_data['request_header'].splitlines()
    for line in header_lines:
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key] = value

    try:
        print(f"Resending request to {url} via ZAP Proxy")
        response = requests.post(url, headers=headers, data=body, proxies=proxies, verify=False)
        print(f"Response Status Code: {response.status_code}")
        print(f"Response Body: {response.text}")
        return request_data, response
        
    except requests.RequestException as e:
        print(f"Error sending request to {url} via ZAP Proxy: {e}")
        error = f"Error sending request to {url} via ZAP Proxy: {e}"
        return request_data, error
        


def self_reflection(element, request_data, response_data):
    
  
    request_data = str(request_data)
    system_prompt = """You are an assistant for vulnerability assessment. You are provided with an attack request used in the test and its result. Your goal is to explain how the attack request has affected the application, based on the attack result, while comparing it to normal communication. Determine if a vulnerability exists. This explanation will serve as a hint for retrying the attack later. Provide only a concise explanation without including the attack request."""

    user_prompt = f"""
Normal communication request and response information before tampering: {element}
Attack request: {request_data}
Status code: {response_data.status_code}
Response body: {response_data.text}
"""
   
    response = openai.ChatCompletion.create(
    model="gpt-4o",  
    messages=[
        {"role": "system", "content": system_prompt},  
        {"role": "user", "content": user_prompt}  
    ]
)
    reflection = response['choices'][0]['message']['content']   
    return reflection, user_prompt
    

def resend_prompt(element, previus_element, reflection, thought_list):
   system_prompt = """You are an experienced security assessor, specializing in discovering vulnerabilities related to communication parameter tampering in web application security assessments. In the following scenario, carefully assess whether unauthorized privilege escalation or session hijacking can be performed.
- Target parameters include session IDs, user IDs, privilege information, pricing information, etc.
"""

   user_prompt_1 = f"""Analyze the past attack request (observation), the attack result, hints for generating an effective attack request, and the request/response of the normal communication to determine if unauthorized tampering of the request or response is possible. Indicate specific tampering methods and their outcomes. If previous attacks failed, consider changing parameters to be tampered with or altering multiple parameters simultaneously. Avoid meaningless actions such as sending parameters identical to those of normal communication.

Use the following framework for analysis. Only output the Action section, as demonstrated in the example, and refrain from any output after the Action.

observation_1: Contains the attack request and attack result. {previus_element}
observation_2: Contains hints for generating an effective attack request. {reflection}
observation_3: Contains specific request and response information for normal communication. {element}

Thought: Please output your reasoning based on the analysis, starting with 'Thought:'.

Action: Output only the modified request header and request body in JSON format, following the example.
"""
   user_prompt_2 = """for example {
        "url": "http://example.com",
        "request_header": "POST http://example.com",
        "request_body": "example"
          }"""
          
          
   prompt = user_prompt_1 + user_prompt_2
   response = openai.ChatCompletion.create(
    model="gpt-4o",  
    messages=[
        {"role": "system", "content": system_prompt}, 
        {"role": "user", "content": prompt}  
    ]
)
   reply = response['choices'][0]['message']['content']

   thought_text = re.search(r"Thought:(.*?)(?:\n|$)", reply, re.DOTALL)
   if thought_text:
      thought_text = thought_text.group(1).strip()
      thought_list.append(thought_text)

   json_match = re.search(r"\{.*\}", reply, re.DOTALL)
   if json_match:
      action = json_match.group(0)  
      print("attack request", action)
   else:
      print("The JSON section was not found")

   re_action = json.loads(action)     
   return re_action, thought_list



with open('post_requests_data.json', 'r') as file:
    data = json.load(file)

for i_data in data:
    thought_list = []
    element = i_data
    openai.api_key = api_key

    system_prompt = """You are an experienced security assessor, specializing in the security assessment of web applications, particularly in identifying vulnerabilities related to communication parameter tampering. In the following scenario, carefully assess whether unauthorized privilege escalation or session hijacking can be conducted.
- The target parameters include session IDs, user IDs, privilege information, pricing information, etc.
"""

    prompt = f"""Analyze the observed request and response (referred to as 'observation') to determine if unauthorized tampering with the request or response is possible. Specify the exact tampering methods and their outcomes. Consider altering multiple parameters simultaneously, if necessary.

Use the following framework for analysis. Only output the Action section, as demonstrated in the example, and refrain from any output after the Action.

observation: Detailed information on the specific request and response is provided. {element}

Thought: Please output your reasoning based on the analysis, starting with 'Thought:'.

Action: Output only the modified request header and request body in JSON format, following the example. Ensure all elements are enclosed in double quotes.
"""
    prompt_2 = """for example {
        "url": "http://example.com",
        "request_header": "POST http://example.com",
        "request_body": "example"
          }"""


    prompt = prompt+prompt_2
    response = openai.ChatCompletion.create(
        model="gpt-4o",  
        messages=[
            {"role": "system", "content": system_prompt},  
            {"role": "user", "content": prompt}  
        ]
    )

  
    reply = response['choices'][0]['message']['content']

    thought_text = re.search(r"Thought:(.*?)(?:\n|$)", reply, re.DOTALL)
    if thought_text:
        thought_text = thought_text.group(1).strip()
        thought_list.append(thought_text)
   
    json_match = re.search(r"\{.*\}", reply, re.DOTALL)
    if json_match:
       action = json_match.group(0)  
       print("attack request", action)
    else:
       print("The JSON section was not found")
        
    action = json.loads(action)
    request_data, response_data = send_request_via_zap_proxy(action)
    judge = judgement(element,request_data, response_data)

    if judge=="True":
      report_thought = summary(thought_list, report_thought)
      report_element.append(element)
      report_request.append(request_data)
      report_response_status_code.append(response_data.status_code)
      report_response_text.append(response_data.text)
      print("Vulnerability confirmed")
      continue

    reflection, previus_element = self_reflection(element, request_data, response_data)
    for cur_iter in range(max_iters):

        re_action, thought_list = resend_prompt(element, previus_element, reflection, thought_list)
        request_data, response_data = send_request_via_zap_proxy(re_action)
        judge = judgement(element,request_data, response_data)
        if judge=="True":    
          report_thought = summary(thought_list, report_thought)
          report_element.append(element)
          report_request.append(request_data)
          report_response_status_code.append(response_data.status_code)
          report_response_text.append(response_data.text)
          print("Vulnerability confirmed")
          break

        reflection, previus_element = self_reflection(element, request_data, response_data)


print("Terminating the attack")
print("Generating the report")

current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file_name = f"vulnerability_report_{current_time}.log"

def write_log_entry(thought, request, status_code, response_text):
    log_entry_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (
        f"--- Vulnerability Report ---\n"
        f"Timestamp: {log_entry_time}\n"
        f"Vulnerability Description (Thought): {thought}\n"
        f"Request Details:\n{request}\n"
        f"Response Status Code: {status_code}\n"
        f"Response Text:\n{response_text}\n"
        f"----------------------\n\n"
    )
    with open(log_file_name, "a", encoding="utf-8") as log_file:
        log_file.write(log_entry)

for thought, request, status_code, response_text in zip(report_thought, report_request, report_response_status_code, report_response_text):
    write_log_entry(thought, request, status_code, response_text)

print(f"The vulnerability report has been saved as '{log_file_name}'.")






