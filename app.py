from flask import Flask, jsonify, request
import requests
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser
from datetime import datetime, timedelta
import json

app = Flask(__name__)

UID_IND = "3926539978"
PASS_IND = "KAWINXKRSXINSMAJT9J6"

UID_SG = "3858426063"
PASS_SG = "8B5EC22D818D5D7566E00E81C260E4C68E788E00E5E2DA31B426FE585B244D47"

JWT_GEN_URL = "https://jwt-aditya.vercel.app/token"

VALID_KEYS = ["test", "kawinraju"]

cached_jwt_token_ind = None
cached_jwt_token_sg = None
jwt_expiry_ind = datetime.min
jwt_expiry_sg = datetime.min

def get_jwt_ind():
    global cached_jwt_token_ind, jwt_expiry_ind
    if cached_jwt_token_ind and datetime.now() < jwt_expiry_ind:
        return cached_jwt_token_ind

    try:
        params = {
            'uid': UID_IND,
            'password': PASS_IND
        }
        response = requests.get(JWT_GEN_URL, params=params)
        if response.status_code == 200:
            jwt_data = response.json()
            token = jwt_data.get("JWT TOKEN")
            if token:
                cached_jwt_token_ind = token
                jwt_expiry_ind = datetime.now() + timedelta(hours=1)
                return token
        return None
    except Exception:
        return None
    
def get_jwt_sg():
    global cached_jwt_token_sg, jwt_expiry_sg
    if cached_jwt_token_sg and datetime.now() < jwt_expiry_sg:
        return cached_jwt_token_sg

    try:
        params = {
            'uid': UID_SG,
            'password': PASS_SG
        }
        response = requests.get(JWT_GEN_URL, params=params)
        if response.status_code == 200:
            jwt_data = response.json()
            token = jwt_data.get("JWT TOKEN")
            if token:
                cached_jwt_token_sg = token
                jwt_expiry_sg = datetime.now() + timedelta(hours=1)
                return token
        return None
    except Exception:
        return None
       
def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]


def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type in ["varint", "string"]:
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def get_available_room(input_text):
    parsed_results = Parser().parse(input_text)
    parsed_results_dict = parse_results(parsed_results)
    return json.dumps(parsed_results_dict)

@app.route('/api/data/ind', methods=['GET'])
def get_player_info_ind():
    try:
        player_id = request.args.get('uid')
        if not player_id:
            return jsonify({
                "status": "error",
                "message": "Player ID is required",
                "Owner" : "DM @kawinraju in Telegram To Buy Lastest Version And Keys",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 400
        
        api_key = request.args.get('key')
        if not api_key or api_key not in VALID_KEYS:
            return jsonify({
                "status": "error",
                "message": "Invalid or missing API key",
                "Owner" : "DM @kawinraju in Telegram To Buy Lastest Version And Keys",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 401

        token = get_jwt_ind()
        if not token:
            return jsonify({
                "status": "error",
                "message": "Failed to retrieve JWT token",
                "Owner" : "DM @kawinraju in Telegram To Buy Lastest Version And Keys",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 500

        data = bytes.fromhex(encrypt_api(f"08{Encrypt_ID(player_id)}1007"))
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB48',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': f'Bearer {token}',
            'Content-Length': '16',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'clientbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }

        response = requests.post(url, headers=headers, data=data, verify=False)
        if response.status_code == 200:
            hex_response = binascii.hexlify(response.content).decode('utf-8')
            json_result = get_available_room(hex_response)
            parsed_data = json.loads(json_result)

            return parsed_data
        
        return jsonify({
            "status": "error",
            "message": f"API request failed with status code: {response.status_code}",
            "Owner" : "DM @kawinraju in Telegram To Buy Lastest Version And Keys",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), response.status_code

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"An unexpected error occurred: {str(e)}",
            "Owner" : "DM @kawinraju in Telegram To Buy Lastest Version And Keys",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 500
        
@app.route('/api/data/sg', methods=['GET'])
def get_player_info_sg():
    try:
        player_id = request.args.get('uid')
        if not player_id:
            return jsonify({
                "status": "error",
                "message": "Player ID is required",
                "Owner" : "DM @kawinraju in Telegram To Buy Lastest Version And Keys",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 400
        
        api_key = request.args.get('key')
        if not api_key or api_key not in VALID_KEYS:
            return jsonify({
                "status": "error",
                "message": "Invalid or missing API key",
                "Owner" : "DM @kawinraju in Telegram To Buy Lastest Version And Keys",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 401

        token = get_jwt_sg()
        if not token:
            return jsonify({
                "status": "error",
                "message": "Failed to retrieve JWT token",
                "Owner" : "DM @kawinraju in Telegram To Buy Lastest Version And Keys",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }), 500

        data = bytes.fromhex(encrypt_api(f"08{Encrypt_ID(player_id)}1007"))
        url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB48',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': f'Bearer {token}',
            'Content-Length': '16',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'clientbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }

        response = requests.post(url, headers=headers, data=data, verify=False)
        if response.status_code == 200:
            hex_response = binascii.hexlify(response.content).decode('utf-8')
            json_result = get_available_room(hex_response)
            parsed_data = json.loads(json_result)

            return parsed_data
        
        return jsonify({
            "status": "error",
            "message": f"API request failed with status code: {response.status_code}",
            "Owner" : "DM @kawinraju in Telegram To Buy Lastest Version And Keys",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), response.status_code

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"An unexpected error occurred: {str(e)}",
            "Owner" : "DM @kawinraju in Telegram To Buy Lastest Version And Keys",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
