from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import hashlib
from secret import*
import uid_generator_pb2
import requests
import struct
import datetime
import base64
import time
import os
import tempfile
from flask import Flask, jsonify
import json
from zitado_pb2 import Users

app = Flask(__name__)

TOKEN_CACHE_FILE = os.path.join(tempfile.gettempdir(), "token_cache.json")
LAST_FORCE_REFRESH = 0

def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)

def create_protobuf(saturn_, garena):
    message = uid_generator_pb2.uid_generator()
    message.saturn_ = saturn_
    message.garena = garena
    return message.SerializeToString()

def protobuf_to_hex(protobuf_data):
    return binascii.hexlify(protobuf_data).decode()

def decode_hex(hex_string):
    byte_data = binascii.unhexlify(hex_string.replace(' ', ''))
    users = Users()
    users.ParseFromString(byte_data)
    return users

def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

def apis(idd, token):
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB54',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = bytes.fromhex(idd)
    response = requests.post('https://client.ind.freefiremobile.com/GetPlayerPersonalShow', headers=headers, data=data)
    hex_response = response.content.hex()
    return hex_response

def load_credentials():
    credentials = []
    # Check success-IND.json
    if os.path.exists("success-IND.json"):
        try:
            with open("success-IND.json", "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        uid = item.get("uid")
                        password = item.get("password")
                        if uid and password:
                            credentials.append((uid, password))
        except Exception as e:
            print(f"Error reading success-IND.json: {e}")
            
    # Also check success-IND.txt
    if os.path.exists("success-IND.txt"):
        try:
            with open("success-IND.txt", "r", encoding="utf-8") as f:
                content = f.read().strip()
                try:
                    data = json.loads(content)
                    if isinstance(data, list):
                        for item in data:
                            uid = item.get("uid")
                            password = item.get("password")
                            if uid and password:
                                credentials.append((uid, password))
                except json.JSONDecodeError:
                    for line in content.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        for sep in [':', ',', '|', '\t']:
                            parts = line.split(sep)
                            if len(parts) >= 2:
                                uid = parts[0].strip()
                                password = parts[1].strip()
                                if uid.isdigit():
                                    credentials.append((uid, password))
                                    break
        except Exception as e:
            print(f"Error reading success-IND.txt: {e}")
            
    return credentials

def is_token_expired(token_str):
    if not token_str:
        return True
    try:
        parts = token_str.split('.')
        if len(parts) < 2:
            return True
        payload_b64 = parts[1]
        payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
        payload = json.loads(base64.b64decode(payload_b64).decode('utf-8'))
        exp = payload.get('exp')
        if exp:
            return time.time() >= (exp - 300)
    except Exception:
        return True
    return True

def load_cached_token():
    if os.path.exists(TOKEN_CACHE_FILE):
        try:
            with open(TOKEN_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                token_str = data.get("token")
                if token_str and not is_token_expired(token_str):
                    return token_str
        except Exception:
            pass
    return None

def save_token_cache(token_str):
    try:
        with open(TOKEN_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({"token": token_str, "cached_at": time.time()}, f)
    except Exception as e:
        print(f"Error saving token cache: {e}")

def get_token(force_refresh=False):
    global LAST_FORCE_REFRESH
    current_time = time.time()
    
    if not force_refresh:
        cached = load_cached_token()
        if cached:
            return cached
    else:
        if current_time - LAST_FORCE_REFRESH < 30:
            print("Force refresh requested too fast. Using cached token if any.")
            cached = load_cached_token()
            if cached:
                return cached
        LAST_FORCE_REFRESH = current_time

    credentials = load_credentials()
    if not credentials:
        print("No credentials found! Returning fallback token.")
        return "eyJhbGciOiJIUzI1NiIsInN2ciI6IjMiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjoxMzYwNTM0ODI5NSwibmlja25hbWUiOiJZZ1JCUVZoVktEWXhhU0kvIiwibm90aV9yZWdpb24iOiJJTkQiLCJsb2NrX3JlZ2lvbiI6IklORCIsImV4dGVybmFsX2lkIjoiZDdiMzc5YmFmMmJhOWE1YTI0NDQwNGJjZDZmYWE1OTMiLCJleHRlcm5hbF90eXBlIjo0LCJwbGF0X2lkIjoxLCJjbGllbnRfdmVyc2lvbiI6IjEuMTA4LjMiLCJlbXVsYXRvcl9zY29yZSI6MTAwLCJpc19lbXVsYXRvciI6dHJ1ZSwiY291bnRyeV9jb2RlIjoiVVMiLCJleHRlcm5hbF91aWQiOjQyMzI1MDIzNzUsInJlZ19hdmF0YXIiOjEwMjAwMDAwNywic291cmNlIjowLCJsb2NrX3JlZ2lvbl90aW1lIjoxNzYwODA1OTIxLCJjbGllbnRfdHlwZSI6Miwic2lnbmF0dXJlX21kNSI6IiIsInVzaW5nX3ZlcnNpb24iOjAsInJlbGVhc2VfY2hhbm5lbCI6IiIsInJlbGVhc2VfdmVyc2lvbiI6Ik9CNTMiLCJleHAiOjE3ODA5NzExNjJ9.JEVr0hVEJo_e_CkPxfzxZpkILN15n9eYA2DvwU2_nts"

    for uid, password in credentials:
        try:
            url = f"https://jwt-beige.vercel.app/guest?uid={uid}&password={password}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                res_data = response.json()
                if res_data.get("status") == "success" and res_data.get("token"):
                    new_token = res_data["token"]
                    save_token_cache(new_token)
                    print(f"Successfully fetched new token using UID: {uid}")
                    return new_token
                else:
                    print(f"Failed to fetch token for {uid}: status={res_data.get('status')}")
            else:
                print(f"HTTP error {response.status_code} for {uid}")
        except Exception as e:
            print(f"Exception fetching token for {uid}: {e}")

    cached = load_cached_token()
    if cached:
        return cached
    return "eyJhbGciOiJIUzI1NiIsInN2ciI6IjMiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjoxMzYwNTM0ODI5NSwibmlja25hbWUiOiJZZ1JCUVZoVktEWXhhU0kvIiwibm90aV9yZWdpb24iOiJJTkQiLCJsb2NrX3JlZ2lvbiI6IklORCIsImV4dGVybmFsX2lkIjoiZDdiMzc5YmFmMmJhOWE1YTI0NDQwNGJjZDZmYWE1OTMiLCJleHRlcm5hbF90eXBlIjo0LCJwbGF0X2lkIjoxLCJjbGllbnRfdmVyc2lvbiI6IjEuMTA4LjMiLCJlbXVsYXRvcl9zY29yZSI6MTAwLCJpc19lbXVsYXRvciI6dHJ1ZSwiY291bnRyeV9jb2RlIjoiVVMiLCJleHRlcm5hbF91aWQiOjQyMzI1MDIzNzUsInJlZ19hdmF0YXIiOjEwMjAwMDAwNywic291cmNlIjowLCJsb2NrX3JlZ2lvbl90aW1lIjoxNzYwODA1OTIxLCJjbGllbnRfdHlwZSI6Miwic2lnbmF0dXJlX21kNSI6IiIsInVzaW5nX3ZlcnNpb24iOjAsInJlbGVhc2VfY2hhbm5lbCI6IiIsInJlbGVhc2VfdmVyc2lvbiI6Ik9CNTMiLCJleHAiOjE3ODA5NzExNjJ9.JEVr0hVEJo_e_CkPxfzxZpkILN15n9eYA2DvwU2_nts"

def token(force_refresh=False):
    return get_token(force_refresh)

@app.route('/<uid>', methods=['GET'])
def main(uid):
    try:
        saturn_ = int(uid)
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
        
    garena = 1
    protobuf_data = create_protobuf(saturn_, garena)
    hex_data = protobuf_to_hex(protobuf_data)
    aes_key = (key)
    aes_iv = (iv)
    encrypted_hex = encrypt_aes(hex_data, aes_key, aes_iv)
    tokenn = token(force_refresh=False)
    infoo = apis(encrypted_hex, tokenn)
    hex_data = infoo
    
    users = None
    try:
        if hex_data:
            users = decode_hex(hex_data)
    except Exception:
        pass

    if not users or not users.basicinfo:
        print("Response empty or invalid. Attempting to force refresh token...")
        tokenn = token(force_refresh=True)
        infoo = apis(encrypted_hex, tokenn)
        hex_data = infoo
        try:
            if hex_data:
                users = decode_hex(hex_data)
        except Exception:
            pass

    if not hex_data:
        return jsonify({"error": "hex_data query parameter is missing"}), 400

    try:
        users = decode_hex(hex_data)
    except binascii.Error:
        return jsonify({"error": "Invalid hex data"}), 400

    result = {}

    if users.basicinfo:
        result['basicinfo'] = []
        for user_info in users.basicinfo:
            result['basicinfo'].append({
                'username': user_info.username,
                'region': user_info.region,
                'level': user_info.level,
                'Exp': user_info.Exp,
                'bio': users.bioinfo[0].bio if users.bioinfo else None,
                'banner': user_info.banner,
                'avatar': user_info.avatar,
                'brrankscore': user_info.brrankscore,
                'BadgeCount': user_info.BadgeCount,
                'likes': user_info.likes,
                'lastlogin': user_info.lastlogin,
                'csrankpoint': user_info.csrankpoint,
                'csrankscore': user_info.csrankscore,
                'brrankpoint': user_info.brrankpoint,
                'createat': user_info.createat,
                'OB': user_info.OB
            })

    if users.claninfo:
        result['claninfo'] = []
        for clan in users.claninfo:
            result['claninfo'].append({
                'clanid': clan.clanid,
                'clanname': clan.clanname,
                'guildlevel': clan.guildlevel,
                'livemember': clan.livemember
            })

    if users.clanadmin:
        result['clanadmin'] = []
        for admin in users.clanadmin:
            result['clanadmin'].append({
                'idadmin': admin.idadmin,
                'adminname': admin.adminname,
                'level': admin.level,
                'exp': admin.exp,
                'brpoint': admin.brpoint,
                'lastlogin': admin.lastlogin,
                'cspoint': admin.cspoint
            })

    result['Owners'] = ['@LcyiQ']
    return jsonify(result)
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)