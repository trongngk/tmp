from termcolor import colored
import base64
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA1
from mitmproxy import http
import re
import html

public_key = ""

private_key = open('private_key.pem', 'r').read()

def a(string):
    return base64.b64decode(string)


def b(string, key, bool):
    private_key = f(key, bool)
    cipher = PKCS1_v1_5.new(private_key)
    replace = string.replace("\r", "").replace("\n", "")
    bit_length = private_key.size_in_bits() // 8
    i = bit_length % 3
    i2 = (bit_length // 3) * 4
    if i != 0:
        i2 += 4
    length = len(replace) / i2
    i3 = 0
    encrypted_blocks = []
    # for block in replace.split("=="):
    #     block += "=="
    for i4 in range(0, len(replace)):
        i5 = i2 * i4
        part = replace[i5:i5+i2]
        block_bytes = part.encode('utf-8')
        if len(block_bytes) == 0:
            break
        encrypted_block = cipher.decrypt(h(a(block_bytes)), None)
        encrypted_blocks.append(encrypted_block)
    decrypted_data = b''.join(encrypted_blocks)
    return decrypted_data.decode('utf-8').strip()


def c(data):
    return base64.b64encode(data).decode('utf-8')


def d(string, key, bool):
    public_key = g(key, bool)
    cipher = PKCS1_v1_5.new(public_key)
    bit_length = (public_key.size_in_bits() // 8) - 42
    bytes = string.encode('utf-8')
    length = len(bytes)
    i = length // bit_length
    encrypted_blocks = []
    # padded_data = pad(string.encode('utf-8'), block_size)
    for i2 in range(0, i + 1):
        i3 = bit_length * i2
        i4 = length - i3
        to = i4
        if to > bit_length:
            to = bit_length
        # print("start at ", i3, " to ", i3 + to)
        byte_block = bytes[i3: i3 + to]
        encrypted_block = cipher.encrypt(byte_block)
        encrypted_block = h(encrypted_block)
        encrypted_blocks.append(c(encrypted_block))
        # print(c(encrypted_block))
    encrypted_data = ''.join(encrypted_blocks)
    return encrypted_data.replace("\r", "").replace("\n", "")


def e(file_path):
    with open(file_path, 'rb') as file:
        return file.read().decode('utf-8').strip()


def f(key, bool):
    key_data = e(key) if bool else key.strip()
    key_data = key_data.replace("-----BEGIN PRIVATE KEY-----", "").replace(
        "-----END PRIVATE KEY-----", "").replace("\n", "").replace("\r", "").replace(" ", "")
    return RSA.import_key(a(key_data))


def g(key, bool):
    try:
        key_data = e(key) if bool else key.strip()
        return RSA.import_key(a(key_data))
    except:
        return None


def h(data):
    return data[::-1]


def i(string, key, bool):
    private_key = f(key, bool)
    signer = pkcs1_15.new(private_key)
    signature = signer.sign(string.encode('utf-8'))
    return c(signature).replace("\r", "").replace("\n", "")


def j(string, signature, key, bool):
    public_key = g(key, bool)
    verifier = pkcs1_15.new(public_key)
    return verifier.verify(string.encode('utf-8'), a(signature))


def signature(data, private_key, bool):
    m2 = g(private_key, bool)
    signer = pkcs1_15.new(m2)
    h = SHA1.new(data.encode())
    signature = signer.sign(h)
    return base64.b64encode(signature).decode().replace("\r", "").replace("\n", "")




def request(flow: http.HTTPFlow):        
    content_type = flow.request.headers.get("Content-Type", "")
    if "text/xml" not in content_type:
        return

    # Đọc request body
    body = flow.request.get_text()
    if "SETUP_SOFTWARE" in body:
        return
    # Regex extract
    encrypted_match = re.search(r"<encrypted>(.*?)</encrypted>", body, re.DOTALL)
    
    encrypted = encrypted_match.group(1) if encrypted_match else None
    
    encryp_data = d(encrypted, public_key, False)
    sign_data = signature(encrypted, private_key, False)
    body = re.sub(r"<encrypted>.*?</encrypted>", f"<encrypted>{encryp_data}</encrypted>", body, flags=re.DOTALL)
    body = re.sub(r"<signature>.*?</signature>", f"<signature>{sign_data}</signature>", body, flags=re.DOTALL)
    flow.request.set_text(body)
    
def response(flow: http.HTTPFlow):
    global private_key
    content_type = flow.request.headers.get("Content-Type", "")
    if "text/xml" not in content_type:
        return

    body = flow.response.get_text()
    private_key_match = re.search(r"client_private_key=([A-Za-z0-9+/=]+)", body)
    if private_key_match:
        private_key = private_key_match.group(1)
        with open("private_key.pem", "w") as f:
            f.write(private_key)

        print("[+] Found client private key and saved to private_key.pem")
        pass
    else:
        encrypted_match = re.search(r"<return>encrypted=(.*?)&amp;signature=", body, re.DOTALL)
        return_content = encrypted_match.group(1) if encrypted_match else None
        if return_content:
            return_content = html.unescape(return_content)
            decrypted_data = b(return_content, private_key, False)
            decrypt_header =  decrypted_data[:1000]
            flow.response.headers["X-Decrypted-Data"] = decrypt_header

