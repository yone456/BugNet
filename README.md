# BugNet
Currently, tools like Zap and BurpSuite can detect common vulnerabilities such as XSS and SQL injection. However, these tools struggle to detect vulnerabilities specific to web applications, such as privilege escalation, tampering with purchase information, and user impersonation. Our tool leverages an LLM agent to detect web application-specific vulnerabilities that are difficult for existing scanning tools to identify, rather than focusing on general vulnerabilities like SQL injection and XSS.

Expected vulnerabilities to be detected

- privilege escalation

- tampering with purchase information, and user impersonation

- storing sensitive information in cookies  etc...

Our proposed tool, "BugNet," integrates with Zap to detect vulnerabilities through three primary steps. 

- In the first step, we activate Zap's proxy function to perform scans and routine communications, collecting request and response data. Then, we run a custom script on this data to extract only the POST request and response communications. 

- In the second step, these extracted POST requests and responses are sent to an LLM agent, which performs request tampering. The tampered requests are then resent to the target web application. This agent is built on ReAct and Self-Reflection principles, using ReAct prompts to analyze the POST requests and responses it receives, and then modifying the requests. 

- In the third step, the LLM analyzes the response from the tampered requests to determine if the attack was successful. If the attack fails, the Self-Reflection prompt enables the LLM to output insights on "why the attack did not succeed." This result is incorporated into the next ReAct prompt, which is then used to further refine the request tampering. This loop of ReAct prompts, attack success evaluation, and Self-Reflection—repeats up to five times per request-response pair, until a successful attack is achieved. 

※Currently, BugNet operates using models available through OpenAI's API, with support for Claude and Gemini planned for the future. In a demonstration using GPT-4o, BugNet successfully detected a privilege escalation vulnerability in OWASP Juice Shop. 

## Setup

```
install OWASP ZAP 2.11.1（Verification is in progress to confirm compatibility with other versions.）
Please include the API keys for OpenAI and ZAP, as well as proxy information, in config.json
git clone https://github.com/yone456/BugNet.git
cd BugNet
conda env create -n zap_llm -f zap_llm.yml
conda activate zap_llm
```

## Usage

```
python zap_proxy.py
python interactive_gpt.py
```

## Demo



## How it works?
![](https://github.com/yone456/BugNet/blob/main/image_en.png)
