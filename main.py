import json, requests, threading, time, asyncio, aiohttp, base64, sys, os, signal, hashlib
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser
import data_pb2

INFO_ACCOUNT = {
    "uid": "7905406598",
    "password": "8A16C0A1BED78180AA70"
}

#7766520829 | xSex_3486605

if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

AES_KEY = b"Yg&tc%DEuh6%Zc^8"
AES_IV = b"6oyZDr22E3ychjM%"
VN_TZ = timezone(timedelta(hours=7))

app = Flask(__name__)

current_dir = os.path.dirname(os.path.abspath(__file__))
ACC_FILE = os.path.join(current_dir, "acc.json")
QDZ_ACC_FILE = os.path.join(current_dir, "qdz_acc.json")
DABUFF_FILE = os.path.join(current_dir, "dabuff.json")
STATE_FILE = os.path.join(current_dir, "reset_state.json")

accounts_data = {}
tokens_data = {}
dabuff_data = set()
info_token = None
last_acc_hash = ""

accounts_lock = threading.Lock()
tokens_lock = threading.Lock()
dabuff_lock = threading.Lock()
stats_lock = threading.Lock()

last_refresh_time = 0
total_buffed_count = 0

def get_now_vn():
    return datetime.now(VN_TZ)

def get_cycle_date_vn(dt=None):
    if dt is None:
        dt = get_now_vn()
    # Chu kỳ ngày mới bắt đầu lúc 04:50 sáng giờ VN
    if dt.hour < 4 or (dt.hour == 4 and dt.minute < 50):
        return (dt.date() - timedelta(days=1)).strftime("%Y-%m-%d")
    return dt.date().strftime("%Y-%m-%d")

def get_seconds_until_450_am():
    now = get_now_vn()
    target = now.replace(hour=4, minute=50, second=0, microsecond=0)
    if now >= target:
        target += timedelta(days=1)
    return (target - now).total_seconds()

def get_seconds_until_6h_refresh():
    global last_refresh_time
    if last_refresh_time == 0:
        return 21600
    elapsed = time.time() - last_refresh_time
    remaining = 21600 - elapsed
    return max(0, remaining)

def get_file_md5(path):
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception:
        return ""

def decode_jwt_uid(token):
    if not token or not isinstance(token, str):
        return ""
    try:
        parts = token.split(".")
        if len(parts) >= 2:
            payload_b64 = parts[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            data = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8", errors="ignore"))
            return str(data.get("external_uid") or data.get("account_id") or "")
    except Exception:
        pass
    return ""

def load_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else (default or {})
    except Exception:
        return default or {}

def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
    except Exception:
        pass

def get_last_reset_date():
    state = load_json(STATE_FILE, {})
    return state.get("last_reset_date", "")

def set_last_reset_date(date_str):
    state = load_json(STATE_FILE, {})
    state["last_reset_date"] = date_str
    save_json(STATE_FILE, state)

def load_all_files():
    global accounts_data, tokens_data, dabuff_data, last_acc_hash

    acc_list = load_json(ACC_FILE, {})
    new_acc_hash = get_file_md5(ACC_FILE)

    with accounts_lock:
        accounts_data = {
            str(uid): str(password)
            for uid, password in acc_list.items()
        }
    last_acc_hash = new_acc_hash

    tok_list = load_json(QDZ_ACC_FILE, [])
    with tokens_lock:
        for item in tok_list:
            if isinstance(item, dict) and "token" in item:
                t = item["token"]
                u = str(item.get("uid") or decode_jwt_uid(t))
                file_count = int(item.get("count", 0))

                if t in tokens_data:
                    tokens_data[t]["count"] = max(tokens_data[t]["count"], file_count)
                    tokens_data[t]["uid"] = u
                else:
                    tokens_data[t] = {
                        "count": file_count,
                        "timestamp": float(item.get("timestamp", time.time())),
                        "uid": u
                    }

    db_list = load_json(DABUFF_FILE, [])
    with dabuff_lock:
        dabuff_data = set(str(x) for x in db_list)

def save_tokens_file():
    with tokens_lock:
        tok_list = [
            {
                "token": t,
                "count": v["count"],
                "timestamp": v["timestamp"],
                "uid": v.get("uid") or decode_jwt_uid(t)
            }
            for t, v in tokens_data.items()
        ]
    save_json(QDZ_ACC_FILE, tok_list)

def save_dabuff_file():
    with dabuff_lock:
        db_list = list(dabuff_data)
    save_json(DABUFF_FILE, db_list)

def print_dashboard():
    with tokens_lock:
        total_tok = len(tokens_data)
        counts = [v["count"] for v in tokens_data.values()]
        min_cnt = min(counts) if counts else 0
        max_cnt = max(counts) if counts else 0
        avg_cnt = (sum(counts) / total_tok) if total_tok else 0
    with dabuff_lock:
        total_dabuff = len(dabuff_data)
    sec_450 = int(get_seconds_until_450_am())
    sec_6h = int(get_seconds_until_6h_refresh())
    h_450, m_450 = divmod(sec_450 // 60, 60)
    h_6h, m_6h = divmod(sec_6h // 60, 60)
    time_str = get_now_vn().strftime("%H:%M:%S %d/%m/%Y")
    
    print("\n" + "="*58)
    print(f" TIME (VN): {time_str} | INFO TOKEN: {'OK' if info_token else 'NONE'}")
    print(f" TOTAL TOKENS   : {total_tok:<5} | MIN COUNT: {min_cnt:<4} | MAX COUNT: {max_cnt:<4} | AVG: {avg_cnt:.1f}")
    print(f" DA BUFF TODAY  : {total_dabuff:<5} | TOTAL BUFF SESSIONS: {total_buffed_count}")
    print(f" NEXT 6H REFRESH: {h_6h:02d}h {m_6h:02d}m | NEXT 4H50 RESET: {h_450:02d}h {m_450:02d}m")
    print("="*58 + "\n")

def encode_varint(value):
    out = []
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

def encode_length_delimited(field_num, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    tag = (field_num << 3) | 2
    return encode_varint(tag) + encode_varint(len(data)) + data

def encode_varint_field(field_num, value):
    tag = (field_num << 3) | 0
    return encode_varint(tag) + encode_varint(value)

def create_protobuf_packet(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested = create_protobuf_packet(value)
            packet.extend(encode_length_delimited(field, nested))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, int):
                    packet.extend(encode_varint_field(field, item))
                elif isinstance(item, (str, bytes)):
                    packet.extend(encode_length_delimited(field, item))
                elif isinstance(item, dict):
                    nested = create_protobuf_packet(item)
                    packet.extend(encode_length_delimited(field, nested))
        elif isinstance(value, int):
            packet.extend(encode_varint_field(field, value))
        elif isinstance(value, (str, bytes)):
            packet.extend(encode_length_delimited(field, value))
    return bytes(packet)

def decode_protobuf(data):
    pos = 0
    length = len(data)
    fields = {}
    while pos < length:
        try:
            val = 0
            shift = 0
            while True:
                if pos >= length: break
                b = data[pos]
                pos += 1
                val |= (b & 0x7f) << shift
                if not (b & 0x80): break
                shift += 7
            tag = val
            field_num = tag >> 3
            wire_type = tag & 0x07
            if wire_type == 0:
                v = 0
                s = 0
                while True:
                    if pos >= length: break
                    b = data[pos]
                    pos += 1
                    v |= (b & 0x7f) << s
                    if not (b & 0x80): break
                    s += 7
                fields[field_num] = v
            elif wire_type == 2:
                l = 0
                s = 0
                while True:
                    if pos >= length: break
                    b = data[pos]
                    pos += 1
                    l |= (b & 0x7f) << s
                    if not (b & 0x80): break
                    s += 7
                fields[field_num] = data[pos:pos+l]
                pos += l
            elif wire_type == 1:
                fields[field_num] = data[pos:pos+8]
                pos += 8
            elif wire_type == 5:
                fields[field_num] = data[pos:pos+4]
                pos += 4
            else:
                break
        except Exception:
            break
    return fields

def aes_encrypt(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))

def parse_protobuf_result(raw_bytes):
    try:
        parser = Parser()
        parsed = parser.parse(raw_bytes.hex())
        d = {}
        for r in parsed:
            if r.field not in d:
                d[r.field] = []
            fd = {}
            if r.wire_type in ["varint", "string", "bytes"]:
                fd = r.data
            elif r.wire_type == "length_delimited":
                fd = parse_protobuf_result_nested(r.data.results)
            d[r.field].append(fd)
        return {k: v[0] if len(v) == 1 else v for k, v in d.items()}
    except Exception:
        return {}

def parse_protobuf_result_nested(parsed):
    d = {}
    for r in parsed:
        if r.field not in d:
            d[r.field] = []
        fd = {}
        if r.wire_type in ["varint", "string", "bytes"]:
            fd = r.data
        elif r.wire_type == "length_delimited":
            fd = parse_protobuf_result_nested(r.data.results)
        d[r.field].append(fd)
    return {k: v[0] if len(v) == 1 else v for k, v in d.items()}

async def request_garena_access(uid, password, session):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    payload = {
        "uid": str(uid),
        "password": str(password),
        "response_type": "token",
        "client_type": "2",
        "client_id": "100067",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
    }
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.42(M2004J7AC ;Android 12;vi;VN;app 1.132.3 2019121229;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "Connection": "close"
    }
    try:
        async with session.post(url, data=payload, headers=headers) as r:
            if r.status == 200:
                data = await r.json()
                if "access_token" in data and "open_id" in data:
                    return data["access_token"], data["open_id"]
    except Exception:
        pass
    try:
        async with session.post("https://auth.garena.com/oauth/guest/token/grant", data=payload, headers=headers) as r:
            if r.status == 200:
                data = await r.json()
                if "access_token" in data and "open_id" in data:
                    return data["access_token"], data["open_id"]
    except Exception:
        pass
    return None, None

async def request_game_jwt(access_token, open_id, session):
    fields = {
        3: datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        4: "free fire",
        5: 1,
        7: "1.132.3",
        8: "Android OS 12 / API-31 (SP1A.210812.016/V13.0.8.0.SJHCNXM)",
        9: "Handheld",
        11: "WIFI",
        12: 1666,
        13: 750,
        14: "440",
        15: "ARM64 FP ASIMD AES | 2600 | 8",
        16: 5479,
        17: "Mali-G57 MC5",
        18: "OpenGL ES 3.2 v1.r32p1-00bet5.e94274a04d1e4e37d3804a00cb1f4074",
        19: "Google|21cd1993-491c-45f0-9aee-f4bf86b9245b",
        20: "123.26.135.179",
        21: "vn",
        22: str(open_id),
        23: "4",
        24: "Handheld",
        25: "Xiaomi M2004J7AC",
        26: "VN",
        29: str(access_token),
        30: 1,
        42: "WIFI",
        57: "7428b253defc164018c604a1ebbfebdf",
        60: 48520,
        61: 23518,
        62: 4498,
        64: 23662,
        65: 48520,
        66: 23662,
        67: 48520,
        73: 2,
        74: "/data/app/~~5Oyng5_R0TorqNAyEwZX8A==/com.dts.freefireth-jiQ7sG-AMNwBe9bzqhdluA==/lib/arm64",
        76: 1,
        77: "b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~5Oyng5_R0TorqNAyEwZX8A==/com.dts.freefireth-jiQ7sG-AMNwBe9bzqhdluA==/base.apk",
        78: 3,
        79: 2,
        81: "64",
        83: "2019121229",
        85: 3,
        86: "OpenGLES2",
        87: 4095,
        88: 4,
        92: 21473,
        93: "android",
        94: "KqsHT0ZDw2VRkOchxPu26AP2douhbLpyxAKQ4DlHphBHkJEbs+ga1Ut7OesVOBYNJ49Ipj2Dbr3iycet+FHmTyZfQ2I=",
        95: 111107,
        96: '{"cur_rate":null,"support_etc2":false}',
        97: 1,
        99: "4",
        100: "4",
        102: bytes.fromhex("425d4743005f085230"),
        104: 50900,
        105: 1,
        106: "https://dl.ak.freefiremobile.com/live/ABHotUpdates/|https://core-ak.freefiremobile.com/live/ABHotUpdates/|1c2462939e53942fc995400436a3dc7b",
        107: "c8e41b7a93f02d56e1a94c7b8203f5d1"
    }
    raw_packet = create_protobuf_packet(fields)
    enc_data = aes_encrypt(raw_packet)
    headers = {
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.12f1",
        "X-GA-SV": str(int(time.time())),
        "X-GA": "v1 1",
        "ReleaseVersion": "OB55"
    }
    try:
        async with session.post("https://loginbp.ppmainecoonghj.com/MajorLogin", data=enc_data, headers=headers) as r:
            if r.status == 200:
                raw_bytes = await r.read()
                fields = decode_protobuf(raw_bytes[64:] if len(raw_bytes) >= 64 else raw_bytes)
                tok = fields.get(8)
                if tok:
                    return tok.decode("utf-8", errors="ignore") if isinstance(tok, bytes) else str(tok)
    except Exception:
        pass
    return None

async def login_single_account(uid, password, session, delay=0.0):
    if delay > 0:
        await asyncio.sleep(delay)
    try:
        at, oid = await request_garena_access(uid, password, session)
        if not at or not oid:
            return uid, None
        jwt = await request_game_jwt(at, oid, session)
        return uid, jwt
    except Exception:
        return uid, None

async def refresh_info_token():
    global info_token
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        _, jwt = await login_single_account(INFO_ACCOUNT["uid"], INFO_ACCOUNT["password"], session)
        if jwt:
            info_token = jwt
            return True
        await asyncio.sleep(5)
        _, jwt = await login_single_account(INFO_ACCOUNT["uid"], INFO_ACCOUNT["password"], session)
        if jwt:
            info_token = jwt
            return True
    return False

async def refresh_all_tokens_core(force_relogin=False):
    global accounts_data, tokens_data, last_refresh_time, last_acc_hash
    
    new_acc_hash = get_file_md5(ACC_FILE)
    acc_changed = (last_acc_hash != "" and new_acc_hash != last_acc_hash)
    
    acc_list = load_json(ACC_FILE, {})
    with accounts_lock:
         old_acc_count = len(accounts_data)
         accounts_data = {
        str(uid): str(password)
        for uid, password in acc_list.items()
    }
    
    if acc_changed:
        print(f"[{get_now_vn().strftime('%H:%M:%S')}] [!] File acc.json đã thay đổi (Cũ: {old_acc_count} acc -> Mới: {len(accounts_data)} acc). Đang cập nhật tài khoản...")
    last_acc_hash = new_acc_hash

    uid_counts = {}
    with tokens_lock:
        for t, v in tokens_data.items():
            u = v.get("uid") or decode_jwt_uid(t)
            if u:
                uid_counts[str(u)] = max(uid_counts.get(str(u), 0), v.get("count", 0))
                
    tok_list = load_json(QDZ_ACC_FILE, [])
    for item in tok_list:
        if isinstance(item, dict) and "token" in item:
            t = item["token"]
            u = str(item.get("uid") or decode_jwt_uid(t))
            if u:
                uid_counts[u] = max(uid_counts.get(u, 0), int(item.get("count", 0)))

    await refresh_info_token()
    
    with accounts_lock:
        acc_items = list(accounts_data.items())
    
    if not acc_items:
        print_dashboard()
        return
    
    timeout = aiohttp.ClientTimeout(total=120)
    new_tokens_map = {}
    success_uids = set()
    async with aiohttp.ClientSession(timeout=timeout) as session:
        # Lần 1: Chạy login đồng loạt toàn bộ tài khoản
        tasks = []
        for idx, (u, p) in enumerate(acc_items):
            delay = 0.0 if idx < 200 else (idx - 200) * 0.05
            tasks.append(login_single_account(u, p, session, delay))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        now_ts = time.time()
        
        retry_list = []
        for (u, p), res in zip(acc_items, results):
            u_str = str(u).strip()
            if isinstance(res, tuple) and len(res) >= 2 and res[1]:
                jwt = res[1]
                prev_count = uid_counts.get(u_str, 0)
                new_tokens_map[jwt] = {
                    "count": prev_count,
                    "timestamp": now_ts,
                    "uid": u_str
                }
                success_uids.add(u_str)
            else:
                retry_list.append((u, p))
        
        if retry_list:
            print(f"[{get_now_vn().strftime('%H:%M:%S')}] Có {len(retry_list)}/{len(acc_items)} tài khoản chưa lấy được token. Tạm bỏ qua, chờ 3s lấy lại lần 2...")
            await asyncio.sleep(5)
            
            retry_tasks = []
            for idx, (u, p) in enumerate(retry_list):
                delay = idx * 0.05
                retry_tasks.append(login_single_account(u, p, session, delay))
            
            retry_results = await asyncio.gather(*retry_tasks, return_exceptions=True)
            retry_now_ts = time.time()
            retry_success_count = 0
            
            for (u, p), res in zip(retry_list, retry_results):
                u_str = str(u).strip()
                if isinstance(res, tuple) and len(res) >= 2 and res[1]:
                    jwt = res[1]
                    prev_count = uid_counts.get(u_str, 0)
                    new_tokens_map[jwt] = {
                        "count": prev_count,
                        "timestamp": retry_now_ts,
                        "uid": u_str
                    }
                    success_uids.add(u_str)
                    retry_success_count += 1
            
            print(f"[{get_now_vn().strftime('%H:%M:%S')}] Thử lại hoàn tất: Thành công thêm {retry_success_count}/{len(retry_list)} tài khoản.")
            
            for u, p in retry_list:
                u_str = str(u).strip()
                if u_str not in success_uids:
                    for old_t, old_v in tokens_data.items():
                        if (old_v.get("uid") or decode_jwt_uid(old_t)) == u_str:
                            new_tokens_map[old_t] = old_v
                            break

    with tokens_lock:
        tokens_data = new_tokens_map
    save_tokens_file()
    last_refresh_time = time.time()
    print_dashboard()

def trigger_6h_refresh():
    now_vn = get_now_vn()
    minutes = now_vn.hour * 60 + now_vn.minute
    # Prevent 6h token refresh during daily autolike window (04:50 AM - 05:30 AM Vietnam time GMT+7)
    if 290 <= minutes <= 330:  # 04:50 (290m) to 05:30 (330m)
        target_time = now_vn.replace(hour=5, minute=31, second=0, microsecond=0)
        delay_secs = max(1.0, (target_time - now_vn).total_seconds())
        print(f"[{now_vn.strftime('%H:%M:%S')}] Hoãn refresh token 6h để tránh đụng độ tiến trình Auto-Like 5h sáng (04:50 - 05:30). Thử lại sau {int(delay_secs)} giây (lúc 05:31 AM)...")
        t = threading.Timer(delay_secs, trigger_6h_refresh)
        t.daemon = True
        t.start()
        return

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(refresh_all_tokens_core(force_relogin=True))
        loop.close()
    except Exception as e:
        print(f"Lỗi refresh token 6h: {e}")
        
    t = threading.Timer(21600, trigger_6h_refresh)
    t.daemon = True
    t.start()

def run_daily_450_reset():
    global tokens_data, dabuff_data
    print(f"[{get_now_vn().strftime('%H:%M:%S')}] === ĐÚNG 4H50 SÁNG VN: RESET TOÀN BỘ COUNT VÀ DANH SÁCH ĐÃ BUFF ===")
    with tokens_lock:
        for t in tokens_data:
            tokens_data[t]["count"] = 0
    save_tokens_file()
    
    with dabuff_lock:
        dabuff_data = set()
    save_dabuff_file()
    
    set_last_reset_date(get_cycle_date_vn())
    print_dashboard()
    schedule_daily_reset()

def schedule_daily_reset():
    delay = get_seconds_until_450_am()
    t = threading.Timer(delay, run_daily_450_reset)
    t.daemon = True
    t.start()

def check_and_apply_daily_reset():
    current_cycle = get_cycle_date_vn()
    last_reset = get_last_reset_date()
    if not last_reset:
        set_last_reset_date(current_cycle)
    elif last_reset != current_cycle:
        print(f"[{get_now_vn().strftime('%H:%M:%S')}] Chu kỳ ngày 4h50 mới ({current_cycle}, cũ: {last_reset}). Tự động reset...")
        run_daily_450_reset()
        return True
    return False

async def fetch_player_info(uid_num, session):
    global info_token
    if not info_token:
        await refresh_info_token()
    if not info_token:
        return None

    proto_show = b"\x08" + encode_varint(int(uid_num)) + b"\x10\x09\x18\x01\x20\x01"
    enc_payload = aes_encrypt(proto_show)

    headers = {
        "Host": "clientbp.ppmainecoonghj.com",
        "ReleaseVersion": "OB55",
        "X-Unity-Version": "2018.4.12f1",
        "X-GA": "v1 1",
        "X-GA-SV": str(int(time.time())),
        "Authorization": f"Bearer {info_token}",
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive"
    }

    try:
        async with session.post(
            "https://clientbp.ppmainecoonghj.com/GetPlayerPersonalShow",
            headers=headers,
            data=enc_payload,
            timeout=12
        ) as r:
            if r.status == 200:
                raw_bytes = await r.read()
                info_obj = data_pb2.AccountPersonalShowInfo()
                info_obj.ParseFromString(raw_bytes)
                b = info_obj.basic_info
                return {
                    "uid": b.account_id,
                    "nickname": b.nickname,
                    "level": b.level,
                    "region": b.region,
                    "likes": b.liked
                }
    except Exception:
        pass
    return None

async def send_single_like(payload, token, session, delay):
    if delay > 0:
        await asyncio.sleep(delay)
    headers = {
        "Host": "clientbp.ppmainecoonghj.com",
        "ReleaseVersion": "OB55",
        "X-Unity-Version": "2018.4.12f1",
        "X-GA": "v1 1",
        "X-GA-SV": str(int(time.time())),
        "Authorization": f"Bearer {token}",
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive"
    }
    try:
        async with session.post("https://clientbp.ppmainecoonghj.com/LikeProfile", headers=headers, data=payload, timeout=10) as r:
            return r.status == 200
    except Exception:
        return False

async def process_send_likes(target_uid_str, target_likes=200):
    global dabuff_data, tokens_data, total_buffed_count
    
    with dabuff_lock:
        if target_uid_str in dabuff_data:
            return {"Failed": f"UID {target_uid_str} | Đã đạt giới hạn Max Likes hôm nay (đã buff trong ngày)"}, 200

    timeout = aiohttp.ClientTimeout(total=300)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        info_before = await fetch_player_info(int(target_uid_str), session)
        if not info_before or "likes" not in info_before:
            return {"Failed": f"Tài khoản UID {target_uid_str} không tồn tại hoặc lỗi kết nối Garena"}, 200

        name = info_before.get("nickname", "Không rõ")
        before_likes = int(info_before["likes"])
        start_time = time.time()

        reg = str(info_before.get("region", "VN") or "VN")
        proto_like = b"\x08" + encode_varint(int(target_uid_str)) + b"\x12" + bytes([len(reg.encode("utf-8"))]) + reg.encode("utf-8")
        payload = aes_encrypt(proto_like)

        likes_added = 0
        total_tokens_used = 0
        used_tokens_list = []
        retry_count = 0
        max_retries = 5

        while likes_added < target_likes and retry_count < max_retries:
            missing = target_likes - likes_added
            tokens_to_pick = missing if retry_count > 0 else target_likes
            
            with tokens_lock:
                available = [
                    t for t in tokens_data
                    if t not in used_tokens_list
                ]
                available.sort(key=lambda t: tokens_data[t]["count"])

            if not available:
                break

            batch = available[:tokens_to_pick]
            used_tokens_list.extend(batch)
            total_tokens_used += len(batch)

            tasks = [send_single_like(payload, t, session, idx * 0.003) for idx, t in enumerate(batch)]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            await asyncio.sleep(0.1)
            
            info_after = await fetch_player_info(int(target_uid_str), session)
            if info_after and "likes" in info_after:
                likes_added = int(info_after["likes"]) - before_likes
            
            retry_count += 1

        with tokens_lock:
            for t in used_tokens_list:
                if t in tokens_data:
                    tokens_data[t]["count"] += 1
        save_tokens_file()

        with dabuff_lock:
            dabuff_data.add(target_uid_str)
        save_dabuff_file()

        with stats_lock:
            total_buffed_count += 1

        if likes_added <= 0:
            return {"Failed": f"UID {target_uid_str} | Tên: {name} | Đã đạt giới hạn Max Likes hôm nay (220 likes/ngày) hoặc tài khoản không nhận like"}, 200

        after_likes = before_likes + likes_added
        elapsed = time.time() - start_time

        return {
            "result": {
                "User Info": {
                    "Account UID": target_uid_str,
                    "Account Name": name,
                    "Account Region": info_before.get("region", "Unknown"),
                    "Account Level": info_before.get("level", "0"),
                    "Account Likes": before_likes
                },
                "Likes Info": {
                    "Likes Before": before_likes,
                    "Likes After": after_likes,
                    "Likes Added": likes_added
                },
                "API": {
                    "speed": f"{elapsed:.1f}s",
                    "Success": True,
                    "tokens_used": total_tokens_used
                }
            }
        }, 200

@app.route("/info", methods=["GET"])
def route_info():
    u = request.args.get("uid")
    if not u:
        return jsonify({"err": "Thiếu UID"}), 400
    try:
        uid_num = int(str(u).strip())
    except ValueError:
        return jsonify({"err": "UID phải là số"}), 400

    async def runner():
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            return await fetch_player_info(uid_num, session)

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        data = loop.run_until_complete(runner())
        loop.close()
        if data:
            return jsonify({"status": "success", "data": data}), 200
        return jsonify({"err": "Không thể lấy thông tin hoặc UID không tồn tại"}), 404
    except Exception as e:
        return jsonify({"err": str(e)}), 500

@app.route("/likes", methods=["GET"])
def route_likes():
    u = request.args.get("uid")
    if not u:
        return jsonify({"err": "Thiếu UID"}), 400
    
    count_arg = request.args.get("count")
    try:
        count = int(count_arg) if count_arg is not None else 200
        if count <= 0 or count > 200:
            count = 200
    except ValueError:
        count = 200

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        res, code = loop.run_until_complete(process_send_likes(str(u).strip(), count))
        loop.close()
        return jsonify(res), code
    except Exception as e:
        return jsonify({"err": str(e)}), 500

@app.route("/refresh", methods=["GET"])
@app.route("/rs", methods=["GET"])
def route_refresh():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(refresh_all_tokens_core(force_relogin=True))
        loop.close()
        with tokens_lock:
            total_tok = len(tokens_data)
        return jsonify({
            "status": "success",
            "message": "Toàn bộ token và info_token đã được làm mới thành công (giữ nguyên count)",
            "total_tokens": total_tok
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/status", methods=["GET"])
def route_status():
    with tokens_lock:
        total_tok = len(tokens_data)
        counts = [v["count"] for v in tokens_data.values()]
        min_cnt = min(counts) if counts else 0
        max_cnt = max(counts) if counts else 0
        usage_summary = {}
        for v in tokens_data.values():
            c = v["count"]
            usage_summary[str(c)] = usage_summary.get(str(c), 0) + 1
    with dabuff_lock:
        total_dabuff = len(dabuff_data)
    
    sec_450 = int(get_seconds_until_450_am())
    sec_6h = int(get_seconds_until_6h_refresh())

    return jsonify({
        "server_time_vn": get_now_vn().strftime("%Y-%m-%d %H:%M:%S"),
        "info_token_active": bool(info_token),
        "total_tokens": total_tok,
        "min_token_count": min_cnt,
        "max_token_count": max_cnt,
        "token_usage_distribution": usage_summary,
        "dabuff_today_total": total_dabuff,
        "total_buff_sessions": total_buffed_count,
        "next_6h_refresh_seconds": sec_6h,
        "next_4h50_reset_seconds": sec_450
    }), 200

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: os._exit(0))
    signal.signal(signal.SIGTERM, lambda s, f: os._exit(0))
    load_all_files()
    check_and_apply_daily_reset()
    
    def start_background():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(refresh_all_tokens_core())
        loop.close()
    
    t_bg = threading.Thread(target=start_background, daemon=True)
    t_bg.start()
    
    t_6h = threading.Timer(21600, trigger_6h_refresh)
    t_6h.daemon = True
    t_6h.start()
    
    schedule_daily_reset()
    
    try:
        app.run(host="0.0.0.0", port=3637, threaded=True, debug=False)
    except (KeyboardInterrupt, SystemExit):
        os._exit(0)
