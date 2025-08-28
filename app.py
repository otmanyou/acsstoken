

import os
import json
import time
import base64
import requests
from datetime import datetime
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import urllib3
urllib3.disable_warnings()
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASE_VERSION = "OB02"
USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)"

LOGIN_URLS = [
    "https://loginbp.ggblueshark.com/MajorLogin",
]

INSPECT_URL = "https://100067.connect.garena.com/oauth/token/inspect"

class SimpleProtobuf:
    @staticmethod
    def encode_varint(value):
        """Encode varint"""
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)
    
    @staticmethod
    def encode_string(field_number, value):
        """Encode string field"""
        if isinstance(value, str):
            value = value.encode('utf-8')
        
        result = bytearray()
        result.extend(SimpleProtobuf.encode_varint((field_number << 3) | 2))
        result.extend(SimpleProtobuf.encode_varint(len(value)))
        result.extend(value)
        return bytes(result)
    
    @staticmethod
    def create_login_payload(open_id, platform, access_token, login_platform):
        """Create FreeFire login payload"""
        payload = bytearray()
        payload.extend(SimpleProtobuf.encode_string(22, open_id))  # open_id
        payload.extend(SimpleProtobuf.encode_string(23, platform))  # open_id_type
        payload.extend(SimpleProtobuf.encode_string(29, access_token))  # login_token
        payload.extend(SimpleProtobuf.encode_string(99, platform))  # origin_platform_type
        return bytes(payload)
    
    @staticmethod
    def decode_varint(data, offset):
        """Decode varint"""
        result = 0
        shift = 0
        while offset < len(data):
            byte = data[offset]
            result |= (byte & 0x7F) << shift
            offset += 1
            if not (byte & 0x80):
                break
            shift += 7
        return result, offset
    
    @staticmethod
    def parse_response(data):
        """Parse protobuf response"""
        fields = {}
        offset = 0
        
        while offset < len(data):
            try:
                field_info, offset = SimpleProtobuf.decode_varint(data, offset)
                field_number = field_info >> 3
                wire_type = field_info & 0x7
                
                if wire_type == 2:  # String/bytes
                    length, offset = SimpleProtobuf.decode_varint(data, offset)
                    value = data[offset:offset + length]
                    offset += length
                    
                    if field_number == 8:  # JWT token field
                        try:
                            fields['token'] = value.decode('utf-8')
                        except:
                            fields['token'] = value.hex()
                
                elif wire_type == 0:  # Varint
                    value, offset = SimpleProtobuf.decode_varint(data, offset)
                    fields[f'field_{field_number}'] = value
                else:
                    break
                    
            except Exception:
                break
        
        return fields

def encrypt_aes_cbc(key, iv, plaintext):
    """Encrypt with AES CBC"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_data)

def get_current_time():
    """Get current time"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def inspect_token(access_token):
    """Inspect FreeFire access token"""
    headers = {
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive", 
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P9(SM-G965N ;Android 7.1.2;fr;FR;)"
    }
    
    params = {"token": access_token}
    
    try:
        response = requests.get(INSPECT_URL, headers=headers, params=params, 
                              verify=False, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'success': True,
                'open_id': data.get('open_id', ''),
                'platform': str(data.get('platform', '4')),
                'login_platform': str(data.get('login_platform', '4')),
                'raw_data': data
            }
        else:
            return {
                'success': False,
                'error': f"HTTP {response.status_code}",
                'message': response.text[:200]
            }
    
    except Exception as e:
        return {
            'success': False,
            'error': 'Connection Error',
            'message': str(e)
        }

def get_jwt_token(access_token, open_id, platform, login_platform):
    """Get JWT token from FreeFire servers"""
    try:
        # Create payload
        payload = SimpleProtobuf.create_login_payload(open_id, platform, access_token, login_platform)
        encrypted_payload = encrypt_aes_cbc(MAIN_KEY, MAIN_IV, payload)
        
        headers = {
            'User-Agent': USER_AGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASE_VERSION
        }
        
        # Try multiple URLs
        for url in LOGIN_URLS:
            try:
                response = requests.post(url, data=encrypted_payload, headers=headers,
                                       verify=False, timeout=30)
                
                if response.status_code == 200 and response.content:
                    parsed = SimpleProtobuf.parse_response(response.content)
                    jwt_token = parsed.get('token', '')
                    
                    if jwt_token and len(jwt_token) > 20:
                        return {
                            'success': True,
                            'token': jwt_token,
                            'url_used': url,
                            'parsed_data': parsed
                        }
                
            except Exception as e:
                print(f"Error with URL {url}: {e}")
                continue
        
        return {
            'success': False,
            'error': 'All URLs Failed',
            'message': 'Could not get JWT token from any server'
        }
    
    except Exception as e:
        return {
            'success': False,
            'error': 'Processing Error',
            'message': str(e)
        }

app = FastAPI(
    title="Free Fire Token API",
    description="API لاستخراج JWT tokens من Free Fire",
    version="1.0"
)

class TokenResponse(BaseModel):
    status: str
    token: str = None
    open_id: str = None
    platform: str = None
    error: str = None
    processing_time: float = None
    timestamp: str = None

@app.get("/api/{access_token}")
async def get_token(access_token: str):
    start_time = time.time()
    
    # Step 1: Validate token
    if len(access_token) < 20:
        raise HTTPException(
            status_code=400,
            detail="تنسيق توكن غير صحيح (يجب أن يكون طول التوكن 20 حرفاً على الأقل)"
        )
    
    # Step 2: Inspect token
    inspection = inspect_token(access_token)
    
    if not inspection['success']:
        raise HTTPException(
            status_code=400,
            detail=f"فحص التوكن فشل: {inspection.get('error', '')} - {inspection.get('message', '')}"
        )
    
    open_id = inspection['open_id']
    platform = inspection['platform']
    login_platform = inspection['login_platform']
    
    if not open_id:
        raise HTTPException(
            status_code=400,
            detail="رد توكن غير صحيح (لا يمكن استخراج open_id من التوكن)"
        )
    
    # Step 3: Get JWT token
    jwt_result = get_jwt_token(access_token, open_id, platform, login_platform)
    processing_time = time.time() - start_time
    
    if jwt_result['success']:
        return TokenResponse(
            status="success",
            token=jwt_result['token'],
            open_id=open_id,
            platform=platform,
            processing_time=processing_time,
            timestamp=get_current_time()
        )
    else:
        raise HTTPException(
            status_code=500,
            detail=f"استخراج التوكن فشل: {jwt_result.get('error', '')} - {jwt_result.get('message', '')}"
        )

@app.get("/")
async def health_check():
    return {
        "status": "running",
        "service": "Free Fire Token API",
        "version": "1.0",
        "timestamp": get_current_time()
    }
