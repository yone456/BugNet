import pyfiglet
import openai
import requests
import json
import re



ascii_art = pyfiglet.figlet_format("BugNet")
print(ascii_art)

max_iters = 4

with open("config.json", "r") as file:
    config = json.load(file)

# 設定内容の取得
api_key = config.get("openai_api_key")
proxy = config.get("proxy")

# ZAPのプロキシ設定
proxies = proxy

def judgement(element, request_data, response_data):
    
    request_data = str(request_data)
    
  #  response_data = str(response_data)

    system_prompt = """あなたは脆弱性診断のためのアシスタントです。改ざん前の正常系通信のrequestやresponse情報、テストで使用された攻撃requestとその結果が与えられます。あなたの目標は、それらの情報を基に攻撃リクエストの成功結果を判定することです。判定結果をTrueかFalseで出力してください"""

    user_prompt = f"""
改ざん前の正常系通信のrequestやresponse情報：{element}
攻撃リクエスト：{request_data}
ステータスコード：{response_data.status_code}
レスポンス本文：{response_data.text}
"""
   # print(user_prompt)
    response = openai.ChatCompletion.create(
    model="gpt-4o",  # 使用するモデルを指定
    messages=[
        {"role": "system", "content": system_prompt},  # システムメッセージ
        {"role": "user", "content": user_prompt}  # ユーザーからのメッセージ
    ]
   )
    judge = response['choices'][0]['message']['content']
    
    return judge
    

# ZAPのプロキシを経由してリクエストを再送信する関数
def send_request_via_zap_proxy(request_data):
    url = request_data['url']
    headers = {}
    method = "POST"  # POSTリクエストのみを再送信する
    body = request_data['request_body']

    # リクエストヘッダーの解析
    header_lines = request_data['request_header'].splitlines()
    for line in header_lines:
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key] = value

    # Python requestsライブラリを使用して、ZAPプロキシを通してリクエストを再送信
    try:
        print(f"Resending request to {url} via ZAP Proxy")
        response = requests.post(url, headers=headers, data=body, proxies=proxies, verify=False)
      #  print(response.text)
        # 結果を表示
        print(f"Response Status Code: {response.status_code}")
        print(f"Response Body: {response.text}")
        return request_data, response
        
    except requests.RequestException as e:
        print(f"Error sending request to {url} via ZAP Proxy: {e}")
        error = f"Error sending request to {url} via ZAP Proxy: {e}"
        return request_data, error
        


def self_reflection(request_data, response_data):
    
  #  print(response_data)
    request_data = str(request_data)
    
  #  response_data = str(response_data)

    system_prompt = """あなたは脆弱性診断のためのアシスタントです。テストで使用された攻撃requestとその結果が与えられます。あなたの目標は、攻撃結果に基づいて攻撃requestがどのように間違っているかを説明することです。この説明は、後で再試行する際のヒントとして使用されます。回答には簡潔な説明だけを提供し、攻撃requestは含めません。"""

    user_prompt = f"""
攻撃リクエスト：{request_data}
ステータスコード：{response_data.status_code}
レスポンス本文：{response_data.text}
"""
    print(user_prompt)
    response = openai.ChatCompletion.create(
    model="gpt-4o",  # 使用するモデルを指定
    messages=[
        {"role": "system", "content": system_prompt},  # システムメッセージ
        {"role": "user", "content": user_prompt}  # ユーザーからのメッセージ
    ]
)
    reflection = response['choices'][0]['message']['content']
    print(reflection)
    
    return reflection, user_prompt
    

def resend_prompt(element, previus_element, reflection):
   system_prompt = """あなたは熟練したセキュリティ診断者です。特にWebアプリケーションのセキュリティ診断において、通信パラメータ改ざんに関連する脆弱性を発見することを専門としています。次に示すシナリオにおいて、ユーザー権限の不正な昇格やセッションの乗っ取りが行えるかどうか、慎重に診断してください。
- 対象とするパラメータには、セッションID、ユーザーID、権限情報、価格情報などがあります。
"""

   user_prompt_1 = f"""observationである過去の攻撃request、攻撃結果、および攻撃requestを適切に生成するためのヒント、正常系通信のrequestやresponseを分析して不正なrequestやresponseの改ざんが可能かどうか、具体的な改ざん手法とその結果を示してください。
分析のフレームワークは下記を使用してください。ただし、Actionの出力以降は何も出力しないでください。

observation_1:攻撃request、攻撃結果が記載されています。{previus_element}
observation_2:攻撃requestを適切に生成するためのヒントが記載されています。{reflection}
observation_3:具体的な正常系通信のrequestやresponse情報が記載されています。{element}

Thought:分析を基にしたあなたの考えを出力してください

Action:改ざんしたrequest header,request bodyを出力してください。出力形式は例を参考にしながらJSON形式にしてください。また"Action：{{"から出力を始めてください。
"""
   user_prompt_2 = """例 Action：{
        "url": "http://example.com",
        "request_header": "POST http://example.com",
        "request_body": "example"
          }"""
          
          
   prompt = user_prompt_1 + user_prompt_2

# GPT-4 APIを使用してリクエストを送信
   response = openai.ChatCompletion.create(
    model="gpt-4o",  # 使用するモデルを指定
    messages=[
        {"role": "system", "content": system_prompt},  # システムメッセージ
        {"role": "user", "content": prompt}  # ユーザーからのメッセージ
    ]
)

# レスポンスの取得と出力
   reply = response['choices'][0]['message']['content']
#print(reply)


   action_match = re.search(r"Action:\s*(.*)", reply, re.DOTALL)

   if action_match:
      action = action_match.group(1).strip()
      print("次に行うべきアクション:", action)
   else:
      print("アクションが見つかりませんでした。")

  # print(type(action))
   re_action = json.loads(action)
          
   return re_action


    
  

# JSONファイルを開いて読み込む
with open('post_requests_data.json', 'r') as file:
    data = json.load(file)

for i_data in data:
   # print(i_data)
    # 1番目の要素を取り出す (インデックス0)
    element = i_data

    # OpenAIのAPIキーを設定します
    openai.api_key = api_key

    # GPT-4に送信する初期プロンプトを設定
    system_prompt = """あなたは熟練したセキュリティ診断者です。特にWebアプリケーションのセキュリティ診断において、通信パラメータ改ざんに関連する脆弱性を発見することを専門としています。次に示すシナリオにおいて、ユーザー権限の不正な昇格やセッションの乗っ取りが行えるかどうか、慎重に診断してください。
    - 対象とするパラメータには、セッションID、ユーザーID、権限情報、価格情報などがあります。
    """

    prompt = f"""observationであるrequestやresponseを分析して不正なrequestやresponseの改ざんが可能かどうか、具体的な改ざん手法とその結果を示してください。
    分析のフレームワークは下記を使用してください。ただし、Actionの出力以降は何も出力しないでください。

    observation:具体的なrequestやresponse情報が記載されています。{element}

    Thought:分析を基にしたあなたの考えを出力してください

    Action:改ざんしたrequest header,request bodyを出力してください。出力は必ず例を参考にして、JSON形式で行ってください。その他の文字は含めないでください。
    """
    prompt_2 = """出力例:
    "url": "http://example.com"
    "request_header": "POST http://example.com"
    "request_body": "example"
"""

    prompt = prompt+prompt_2

    # GPT-4 APIを使用してリクエストを送信
    response = openai.ChatCompletion.create(
        model="gpt-4o",  # 使用するモデルを指定
        messages=[
            {"role": "system", "content": system_prompt},  # システムメッセージ
            {"role": "user", "content": prompt}  # ユーザーからのメッセージ
        ]
    )

    # レスポンスの取得と出力
    reply = response['choices'][0]['message']['content']
    print(reply)
    
    action_match = re.search(r"Action:\s*(.*)", reply, re.DOTALL)

    if action_match:
        action = action_match.group(1).strip()
        print("次に行うべきアクション:", action)
    else:
        print("アクションが見つかりませんでした。")


    
    
    
   # print(type(action))
    action = json.loads(action)


            
    
    request_data, response_data = send_request_via_zap_proxy(action)
    judge = judgement(element,request_data, response_data)
    reflection, previus_element = self_reflection(request_data, response_data)


    for cur_iter in range(max_iters):

        re_action = resend_prompt(element, previus_element, reflection)
        request_data, response_data = send_request_via_zap_proxy(re_action)
        judge = judgement(element,request_data, response_data)
        reflection, previus_element = self_reflection(request_data, response_data)


print("攻撃を終了します")









