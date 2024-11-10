import time
import json
from urllib.parse import parse_qs
from xml.etree import ElementTree as ET
from zapv2 import ZAPv2


with open("config.json", "r") as file:
    config = json.load(file)

# 設定内容の取得
zap_key = config.get("zap_api_key")
proxy = config.get("proxy")


apikey = zap_key

# ZAPインスタンスの作成
zap = ZAPv2(apikey=apikey, proxies=proxy)

# 記録された全てのサイトを取得
sites = zap.core.sites
print(sites)

# ステータスコードフィルタリング
filter_status_codes = [200, 401, 201]

# 重複を避けるための辞書 (キー: URL + リクエストボディの形状, 値: True)
processed_requests = {}

# JSONファイルに保存するデータを保持するリスト
post_requests_data = []

# 特定のサイトの記録されたリクエストやレスポンスを取得
for site in sites:
    # そのサイトのリクエストのリストを取得
    history = zap.core.messages(site)
    
    # 取得したリクエスト・レスポンスをループ
    for message in history:
        # レスポンスヘッダーからステータスコードを取得
        response_header = message['responseHeader']
        if response_header:
            # ステータスコードの抽出 (例: 'HTTP/1.1 200 OK' から 200 を取得)
            status_code = int(response_header.split(' ')[1])

            # ステータスコードが200または401の場合にフィルタリング
            if status_code in filter_status_codes:
                # リクエストの種類がPOSTかGETか確認
                request_header = message['requestHeader']
                request_method = request_header.split(' ')[0]  # GETまたはPOSTの部分を取得

                # URLとリクエストボディを抽出
                request_url = request_header.split(' ')[1]
                request_body = message['requestBody'] if "POST" in request_method else ""  # GETは通常ボディがない

                content_type = ""

                # Content-Typeヘッダーを取得（POSTリクエストの場合）
                if "POST" in request_method:
                    for header in request_header.splitlines():
                        if "Content-Type" in header:
                            content_type = header.split(": ")[1]
                            break

                # リクエストがPOSTの場合、リクエストボディがJSON形式、XML形式、multipart形式、バイナリ、プレーンテキストなどかを判定
                try:
                    if "POST" in request_method:
                        if "application/json" in content_type:
                            # JSONとしてロード
                            body_json = json.loads(request_body)
                            if isinstance(body_json, dict):
                                # JSONのキー構造を抽出
                                body_shape = tuple(sorted(body_json.keys()))
                            else:
                                body_shape = str(body_json)
                        elif "application/xml" in content_type:
                            # XMLとしてロード
                            xml_tree = ET.ElementTree(ET.fromstring(request_body))
                            body_shape = tuple([elem.tag for elem in xml_tree.iter()])
                        elif "multipart/form-data" in content_type:
                            # マルチパートデータを簡易解析（実際のファイル内容は無視）
                            body_shape = tuple(request_body.split('--')[1::2])  # バウンダリの部分をキーに
                        elif "application/octet-stream" in content_type:
                            # バイナリデータなのでそのまま
                            body_shape = "binary_data"
                        elif "text/plain" in content_type:
                            # プレーンテキスト
                            body_shape = request_body
                        else:
                            # フォームデータ形式またはその他の形式
                            try:
                                form_data = parse_qs(request_body)
                                body_shape = tuple(sorted(form_data.keys()))
                            except Exception:
                                body_shape = request_body
                    else:
                        # GETリクエストの場合は、URLとパラメータをキーにする
                        body_shape = request_url
                except Exception as e:
                    # 何かのパースに失敗した場合はそのままボディ全体を形状として扱う
                    print(f"Parsing error: {e}")
                    body_shape = request_body if "POST" in request_method else request_url

                # URLとリクエストボディの形状の重複をチェック
                request_key = f"{request_url}|{body_shape}"

                if request_key not in processed_requests:
                    # 初めてのリクエストの場合は処理して記録
                    processed_requests[request_key] = True
                    
                    # リクエストとレスポンスを表示
                   # print(f"Request Method: {request_method}")
                  #  print("Request URL: ", request_url)
                   # print("Request header: ", request_header)
                    if request_body:
                        print("Request Body: ", request_body)
                    
                    # POSTリクエストの場合のみJSONデータに追加
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
                    # 重複したリクエストはスキップ
                    print(f"Skipped duplicate {request_method} request with same body shape to {request_url}")
                    if request_body:
                        print("Request Body: ", request_body)

# POST通信のリクエストとレスポンスのデータをJSONファイルに保存
with open('post_requests_data.json', 'w', encoding='utf-8') as f:
    json.dump(post_requests_data, f, ensure_ascii=False, indent=4)

print("POSTリクエストとレスポンスのデータが'post_requests_data.json'に保存されました。")
