# BugNet

Our proposed tool, "BugNet," integrates with Zap to detect vulnerabilities through three primary steps. 

- In the first step, we activate Zap's proxy function to perform scans and routine communications, collecting request and response data. Then, we run a custom script on this data to extract only the POST request and response communications. 

- In the second step, these extracted POST requests and responses are sent to an LLM agent, which performs request tampering. The tampered requests are then resent to the target web application. This agent is built on ReAct and Self-Reflection principles, using ReAct prompts to analyze the POST requests and responses it receives, and then modifying the requests. 

- In the third step, the LLM analyzes the response from the tampered requests to determine if the attack was successful. If the attack fails, the Self-Reflection prompt enables the LLM to output insights on "why the attack did not succeed." This result is incorporated into the next ReAct prompt, which is then used to further refine the request tampering. This loop of ReAct prompts, attack success evaluation, and Self-Reflection—repeats up to five times per request-response pair, until a successful attack is achieved. 

※Currently, BugNet operates using models available through OpenAI's API, with support for Claude and Gemini planned for the future. In a demonstration using GPT-4o, BugNet successfully detected a privilege escalation vulnerability in OWASP Juice Shop. 

## Setup

```
conda env create -n zap_llm -f zap_llm.yml
```

## Usage

```
python zap_proxy.py
python interactive_gpt.py
```

## Demo



## How it works?
![](https://github.com/yone456/BugNet/blob/main/image_en.png)
