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

# 設定内容の取得
api_key = config.get("openai_api_key")
proxy = config.get("proxy")

# ZAPのプロキシ設定
proxies = proxy

def summary(Thought_list, report_thought):
    thoughts_text = "\n".join(Thought_list)

# GPT-4に要約リクエストを送信
    response = openai.ChatCompletion.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": "以下のテキストでどのような脆弱性を検証しているのかを要約してください"},
        {"role": "user", "content": thoughts_text}
    ]
)

# 要約結果の表示
    summary = response['choices'][0]['message']['content']
    report_thought.append(summary)

    return report_thought

def judgement(element, request_data, response_data):
    
    request_data = str(request_data)
    system_prompt = """あなたは脆弱性診断のためのアシスタントです。改ざん前の正常系通信のrequestやresponse情報、テストで使用された攻撃requestとその結果が与えられます。あなたの目標は、それらの情報を基に攻撃リクエストの成功結果を判定することです。判定結果をTrueかFalseで出力してください"""

    user_prompt = f"""
改ざん前の正常系通信のrequestやresponse情報：{element}
攻撃リクエスト：{request_data}
ステータスコード：{response_data.status_code}
レスポンス本文：{response_data.text}
"""
   
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
      
        # 結果を表示
        print(f"Response Status Code: {response.status_code}")
        print(f"Response Body: {response.text}")
        return request_data, response
        
    except requests.RequestException as e:
        print(f"Error sending request to {url} via ZAP Proxy: {e}")
        error = f"Error sending request to {url} via ZAP Proxy: {e}"
        return request_data, error
        


def self_reflection(element, request_data, response_data):
    
  
    request_data = str(request_data)
    system_prompt = """あなたは脆弱性診断のためのアシスタントです。テストで使用された攻撃requestとその結果が与えられます。あなたの目標は、正常系通信との比較を行いながら、攻撃結果に基づいて攻撃requestがどのように作用しているかを説明し、脆弱性が存在するかどうかを判断してください。この説明は、後で再試行する際のヒントとして使用されます。回答には簡潔な説明だけを提供し、攻撃requestは含めません。"""

    user_prompt = f"""
改ざん前の正常系通信のrequestやresponse情報：{element}
攻撃リクエスト：{request_data}
ステータスコード：{response_data.status_code}
レスポンス本文：{response_data.text}
"""
   
    response = openai.ChatCompletion.create(
    model="gpt-4o",  # 使用するモデルを指定
    messages=[
        {"role": "system", "content": system_prompt},  # システムメッセージ
        {"role": "user", "content": user_prompt}  # ユーザーからのメッセージ
    ]
)
    reflection = response['choices'][0]['message']['content']
  #  print("self reflection", reflection)
    
    return reflection, user_prompt
    

def resend_prompt(element, previus_element, reflection, thought_list):
   system_prompt = """あなたは熟練したセキュリティ診断者です。特にWebアプリケーションのセキュリティ診断において、通信パラメータ改ざんに関連する脆弱性を発見することを専門としています。次に示すシナリオにおいて、ユーザー権限の不正な昇格やセッションの乗っ取りが行えるかどうか、慎重に診断してください。
- 対象とするパラメータには、セッションID、ユーザーID、権限情報、価格情報などがあります。
"""

   user_prompt_1 = f"""observationである過去の攻撃request、攻撃結果、および攻撃requestを適切に生成するためのヒント、正常系通信のrequestやresponseを分析して不正なrequestやresponseの改ざんが可能かどうか、具体的な改ざん手法とその結果を示してください。以前の攻撃が失敗している場合は、改ざんを行うパラメータの変更を行うことや同時に複数のパラメータを変更するなどの工夫を行ってください。間違っても正常系通信と同じパラメータを送信するような無意味な行動はとらないでください。
分析のフレームワークは下記を使用してください。Actionについては例を参考にしながら実際のAction部分のみを出力してください。また、Actionの出力以降は何も出力しないでください。


observation_1:攻撃request、攻撃結果が記載されています。{previus_element}
observation_2:攻撃requestを適切に生成するためのヒントが記載されています。{reflection}
observation_3:具体的な正常系通信のrequestやresponse情報が記載されています。{element}

Thought:分析を基にしたあなたの考えを必ず出力してください。出力はThought：から始めてください。

Action:改ざんしたrequest header,request bodyのみを出力してください。出力形式は例を参考にしながらJSON形式にしてください。
"""
   user_prompt_2 = """例 {
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

  # print(reply)
   thought_text = re.search(r"Thought:(.*?)(?:\n|$)", reply, re.DOTALL)
   if thought_text:
      thought_text = thought_text.group(1).strip()
      thought_list.append(thought_text)
 #  print("Extracted Thought:", thought_text)

   json_match = re.search(r"\{.*\}", reply, re.DOTALL)


   if json_match:
      action = json_match.group(0)  # JSON部分のみを取得
      print("攻撃リクエスト", action)
   else:
      print("JSON部分が見つかりませんでした。")

   re_action = json.loads(action)
          
   return re_action, thought_list


    
  

# JSONファイルを開いて読み込む
with open('post_requests_data.json', 'r') as file:
    data = json.load(file)

for i_data in data:
    thought_list = []
    # 1番目の要素を取り出す (インデックス0)
    element = i_data

    # OpenAIのAPIキーを設定します
    openai.api_key = api_key

    # GPT-4に送信する初期プロンプトを設定
    system_prompt = """あなたは熟練したセキュリティ診断者です。特にWebアプリケーションのセキュリティ診断において、通信パラメータ改ざんに関連する脆弱性を発見することを専門としています。次に示すシナリオにおいて、ユーザー権限の不正な昇格やセッションの乗っ取りが行えるかどうか、慎重に診断してください。
    - 対象とするパラメータには、セッションID、ユーザーID、権限情報、価格情報などがあります。
    """

    prompt = f"""observationであるrequestやresponseを分析して不正なrequestやresponseの改ざんが可能かどうか、具体的な改ざん手法とその結果を示してください。場合によっては複数のパラメータを一度に変更することも視野に入れてください。
    分析のフレームワークは下記を使用してください。Actionについては例を参考にしながら実際のAction部分のみを出力してください。また、Actionの出力以降は何も出力しないでください。

    observation:具体的なrequestやresponse情報が記載されています。{element}

    Thought:分析を基にしたあなたの考えを必ず出力してください。出力はThought：から始めてください。

    Action:改ざんしたrequest header,request bodyのみを出力してください。出力形式は例を参考にしながらJSON形式にし、要素はすべてダブルクォーテーションで囲むようにしてください。
    """
    prompt_2 = """例 {
        "url": "http://example.com",
        "request_header": "POST http://example.com",
        "request_body": "example"
          }"""


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

    thought_text = re.search(r"Thought:(.*?)(?:\n|$)", reply, re.DOTALL)
    if thought_text:
        thought_text = thought_text.group(1).strip()
        thought_list.append(thought_text)
   # print("Extracted Thought:", thought_text)

  #  print(reply)

    json_match = re.search(r"\{.*\}", reply, re.DOTALL)
    if json_match:
       action = json_match.group(0)  # JSON部分のみを取得
       print("攻撃リクエスト", action)
    else:
       print("JSON部分が見つかりませんでした。")
        
    action = json.loads(action)
    request_data, response_data = send_request_via_zap_proxy(action)
    judge = judgement(element,request_data, response_data)

    if judge=="True":
      report_thought = summary(thought_list, report_thought)
      report_element.append(element)
      report_request.append(request_data)
      report_response_status_code.append(response_data.status_code)
      report_response_text.append(response_data.text)
      print("脆弱性が確認されました。次のシナリオに進みます。")
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
          print("脆弱性が確認されました。次のシナリオに進みます。")
          break

        reflection, previus_element = self_reflection(element, request_data, response_data)

  


print("攻撃を終了します")
print("レポートの出力を行っています")

# ファイル生成日時を含むログファイル名
current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file_name = f"vulnerability_report_{current_time}.log"

# ログファイルに追記する関数
def write_log_entry(thought, request, status_code, response_text):
    log_entry_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (
        f"--- 脆弱性レポート ---\n"
        f"生成日時: {log_entry_time}\n"
        f"脆弱性の説明 (Thought): {thought}\n"
        f"リクエスト内容 (Request):\n{request}\n"
        f"レスポンスステータスコード (Response Status Code): {status_code}\n"
        f"レスポンス本文 (Response Text):\n{response_text}\n"
        f"----------------------\n\n"
    )
    with open(log_file_name, "a", encoding="utf-8") as log_file:
        log_file.write(log_entry)

# 各リストからデータを取り出してログに書き込む
for thought, request, status_code, response_text in zip(report_thought, report_request, report_response_status_code, report_response_text):
    write_log_entry(thought, request, status_code, response_text)

print(f"脆弱性レポートが '{log_file_name}' に出力されました。")
