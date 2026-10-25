import json, requests, time, asyncio, aiohttp, base64, sys, os, hashlib
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser
import data_pb2

# ================== REDIS (Vercel KV / Upstash) ==================
try:
    import redis as redis_lib
except ImportError:
    redis_lib = None

REDIS_URL = os.environ.get("REDIS_URL") or os.environ.get("KV_URL")
_redis = None

def get_redis():
    global _redis
    if _redis is not None:
        return _redis
    if redis_lib is None or not REDIS_URL:
        return None
    try:
        _redis = redis_lib.from_url(REDIS_URL, decode_responses=True)
        _redis.ping()
        return _redis
    except Exception as e:
        print(f"[Redis] không kết nối được: {e}")
        return None

# Fallback memory (chỉ dùng khi không có Redis - test local)
_mem = {
    "tokens": {},
    "dabuff": set(),
    "state": {},
    "info_token": None,
}

# ================== CONFIG ==================
INFO_ACCOUNT = {
    "uid": " 8000053530",
    "password": " 8F1F43C8107FE4A8FEB9"
}

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

RESET_INTERVAL = 2 * 3600   # 2 tiếng reset 1 lần
REFRESH_INTERVAL = 6 * 3600 # 6 tiếng refresh token 1 lần

app = Flask(__name__)

current_dir = os.path.dirname(os.path.abspath(__file__))
ACC_FILE = os.path.join(current_dir, "acc.json")

# ================== TIME HELPERS ==================
def get_now_vn():
    return datetime.now(VN_TZ)

def get_seconds_until_6h_refresh():
    last = _load_state().get("last_refresh_time", 0)
    if not last:
        return REFRESH_INTERVAL
    return max(0, REFRESH_INTERVAL - (time.time() - last))

# ================== STATE ==================
def _load_state():
    r = get_redis()
    if r:
        try:
            raw = r.get("app:state")
            return json.loads(raw) if raw else {}
        except Exception:
            return {}
    return dict(_mem["state"])

def _save_state(state):
    r = get_redis()
    if r:
        try:
            r.set("app:state", json.dumps(state))
            return
        except Exception:
            pass
    _mem["state"] = dict(state)

def set_last_refresh_time(ts):
    s = _load_state(); s["last_refresh_time"] = ts; _save_state(s)

def get_last_reset_ts():
    return float(_load_state().get("last_reset_ts", 0) or 0)

def set_last_reset_ts(ts):
    s = _load_state(); s["last_reset_ts"] = ts; _save_state(s)

def get_next_reset_seconds():
    last = get_last_reset_ts()
    if last == 0:
        return 0
    return max(0, int(RESET_INTERVAL - (time.time() - last)))

# ================== INFO TOKEN ==================
def get_info_token():
    r = get_redis()
    if r:
        try:
            return r.get("app:info_token")
        except Exception:
            return None
    return _mem["info_token"]

def save_info_token(tok):
    r = get_redis()
    if r:
        try:
            r.set("app:info_token", tok, ex=3600 * 12)
            return
        except Exception:
            pass
    _mem["info_token"] = tok

# ================== TOKENS ==================
def load_tokens():
    r = get_redis()
    if r:
        try:
            raw = r.hgetall("app:tokens")
            return {k: json.loads(v) for k, v in raw.items()}
        except Exception:
            return {}
    return dict(_mem["tokens"])

def save_tokens(tokens):
    r = get_redis()
    if r:
        try:
            pipe = r.pipeline()
            pipe.delete("app:tokens")
            if tokens:
                pipe.hset("app:tokens", mapping={k: json.dumps(v) for k, v in tokens.items()})
            pipe.execute()
            return
        except Exception:
            pass
    _mem["tokens"] = dict(tokens)

# ================== DABUFF ==================
def load_dabuff():
    r = get_redis()
    if r:
        try:
            return set(r.smembers("app:dabuff"))
        except Exception:
            return set()
    return set(_mem["dabuff"])

def clear_dabuff():
    r = get_redis()
    if r:
        try:
            r.delete("app:dabuff")
            return
        except Exception:
            pass
    _mem["dabuff"] = set()

def add_dabuff(uid):
    r = get_redis()
    if r:
        try:
            r.sadd("app:dabuff", uid)
            return
        except Exception:
            pass
    _mem["dabuff"].add(uid)

def is_dabuff(uid):
    r = get_redis()
    if r:
        try:
            return bool(r.sismember("app:dabuff", uid))
        except Exception:
            pass
    return uid in _mem["dabuff"]

# ================== FILE ACC ==================
def load_acc():
    try:
        with open(ACC_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return {str(k): str(v) for k, v in data.items()}
    except Exception:
        return {}

def decode_jwt_uid(token):
    if not token or not isinstance(token, str):
        return ""
    try:
        parts = token.split(".")
        if len(parts) >= 2:
            p = parts[1]; p += "=" * (-len(p) % 4)
            d = json.loads(base64.urlsafe_b64decode(p).decode("utf-8", errors="ignore"))
            return str(d.get("external_uid") or d.get("account_id") or "")
    except Exception:
        pass
    return ""

# ================== PROTOBUF HELPERS ==================
def encode_varint(value):
    out = []
    while True:
        b = value & 0x7F; value >>= 7
        out.append(b | 0x80 if value else b)
        if not value: break
    return bytes(out)

def encode_length_delimited(field_num, data):
    if isinstance(data, str): data = data.encode('utf-8')
    return encode_varint((field_num << 3) | 2) + encode_varint(len(data)) + data

def encode_varint_field(field_num, value):
    return encode_varint((field_num << 3) | 0) + encode_varint(value)

def create_protobuf_packet(fields):
    p = bytearray()
    for f, v in fields.items():
        if isinstance(v, dict):
            p.extend(encode_length_delimited(f, create_protobuf_packet(v)))
        elif isinstance(v, list):
            for it in v:
                if isinstance(it, int): p.extend(encode_varint_field(f, it))
                elif isinstance(it, (str, bytes)): p.extend(encode_length_delimited(f, it))
                elif isinstance(it, dict): p.extend(encode_length_delimited(f, create_protobuf_packet(it)))
        elif isinstance(v, int): p.extend(encode_varint_field(f, v))
        elif isinstance(v, (str, bytes)): p.extend(encode_length_delimited(f, v))
    return bytes(p)

def decode_protobuf(data):
    pos, length, fields = 0, len(data), {}
    while pos < length:
        try:
            val = 0; shift = 0
            while True:
                if pos >= length: break
                b = data[pos]; pos += 1
                val |= (b & 0x7f) << shift
                if not (b & 0x80): break
                shift += 7
            tag = val; fn = tag >> 3; wt = tag & 0x07
            if wt == 0:
                v = 0; s = 0
                while True:
                    if pos >= length: break
                    b = data[pos]; pos += 1
                    v |= (b & 0x7f) << s
                    if not (b & 0x80): break
                    s += 7
                fields[fn] = v
            elif wt == 2:
                l = 0; s = 0
                while True:
                    if pos >= length: break
                    b = data[pos]; pos += 1
                    l |= (b & 0x7f) << s
                    if not (b & 0x80): break
                    s += 7
                fields[fn] = data[pos:pos+l]; pos += l
            elif wt == 1: fields[fn] = data[pos:pos+8]; pos += 8
            elif wt == 5: fields[fn] = data[pos:pos+4]; pos += 4
            else: break
        except Exception: break
    return fields

def aes_encrypt(data):
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(data, AES.block_size))

# ================== GARENA LOGIN ==================
async def request_garena_access(uid, password, session):
    payload = {
        "uid": str(uid), "password": str(password),
        "response_type": "token", "client_type": "2", "client_id": "100067",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
    }
    base_headers = {
        "User-Agent": "GarenaMSDK/4.0.42(M2004J7AC ;Android 12;vi;VN;app 1.132.3 2019121229;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json", "Connection": "close"
    }
    for host in ("100067.connect.garena.com", "auth.garena.com"):
        try:
            async with session.post(
                f"https://{host}/oauth/guest/token/grant",
                data=payload, headers={**base_headers, "Host": host}
            ) as r:
                if r.status == 200:
                    d = await r.json()
                    if "access_token" in d and "open_id" in d:
                        return d["access_token"], d["open_id"]
        except Exception:
            pass
    return None, None

async def request_game_jwt(access_token, open_id, session):
    fields = {
        3: datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 4: "free fire", 5: 1,
        7: "1.132.3", 8: "Android OS 12 / API-31 (SP1A.210812.016/V13.0.8.0.SJHCNXM)",
        9: "Handheld", 11: "WIFI", 12: 1666, 13: 750, 14: "440",
        15: "ARM64 FP ASIMD AES | 2600 | 8", 16: 5479, 17: "Mali-G57 MC5",
        18: "OpenGL ES 3.2 v1.r32p1-00bet5.e94274a04d1e4e37d3804a00cb1f4074",
        19: "Google|21cd1993-491c-45f0-9aee-f4bf86b9245b", 20: "123.26.135.179",
        21: "vn", 22: str(open_id), 23: "4", 24: "Handheld", 25: "Xiaomi M2004J7AC",
        26: "VN", 29: str(access_token), 30: 1, 42: "WIFI",
        57: "7428b253defc164018c604a1ebbfebdf", 60: 48520, 61: 23518, 62: 4498,
        64: 23662, 65: 48520, 66: 23662, 67: 48520, 73: 2,
        74: "/data/app/~~5Oyng5_R0TorqNAyEwZX8A==/com.dts.freefireth-jiQ7sG-AMNwBe9bzqhdluA==/lib/arm64",
        76: 1, 77: "b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~5Oyng5_R0TorqNAyEwZX8A==/com.dts.freefireth-jiQ7sG-AMNwBe9bzqhdluA==/base.apk",
        78: 3, 79: 2, 81: "64", 83: "2019121229", 85: 3, 86: "OpenGLES2",
        87: 4095, 88: 4, 92: 21473, 93: "android",
        94: "KqsHT0ZDw2VRkOchxPu26AP2douhbLpyxAKQ4DlHphBHkJEbs+ga1Ut7OesVOBYNJ49Ipj2Dbr3iycet+FHmTyZfQ2I=",
        95: 111107, 96: '{"cur_rate":null,"support_etc2":false}', 97: 1, 99: "4", 100: "4",
        102: bytes.fromhex("425d4743005f085230"), 104: 50900, 105: 1,
        106: "https://dl.ak.freefiremobile.com/live/ABHotUpdates/|https://core-ak.freefiremobile.com/live/ABHotUpdates/|1c2462939e53942fc995400436a3dc7b",
        107: "c8e41b7a93f02d56e1a94c7b8203f5d1"
    }
    enc_data = aes_encrypt(create_protobuf_packet(fields))
    headers = {
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept-Encoding": "gzip", "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue", "X-Unity-Version": "2018.4.12f1",
        "X-GA-SV": str(int(time.time())), "X-GA": "v1 1", "ReleaseVersion": "OB55"
    }
    try:
        async with session.post("https://loginbp.ppmainecoonghj.com/MajorLogin",
                                data=enc_data, headers=headers) as r:
            if r.status == 200:
                raw = await r.read()
                fields = decode_protobuf(raw[64:] if len(raw) >= 64 else raw)
                tok = fields.get(8)
                if tok:
                    return tok.decode("utf-8", errors="ignore") if isinstance(tok, bytes) else str(tok)
    except Exception:
        pass
    return None

async def login_single_account(uid, password, session, delay=0.0):
    if delay > 0: await asyncio.sleep(delay)
    try:
        at, oid = await request_garena_access(uid, password, session)
        if not at or not oid: return uid, None
        return uid, await request_game_jwt(at, oid, session)
    except Exception:
        return uid, None

async def refresh_info_token():
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for _ in range(2):
            _, jwt = await login_single_account(INFO_ACCOUNT["uid"], INFO_ACCOUNT["password"], session)
            if jwt:
                save_info_token(jwt)
                return True
            await asyncio.sleep(5)
    return False

# ================== REFRESH ALL TOKENS ==================
async def refresh_all_tokens_core():
    accs = load_acc()
    if not accs:
        print("acc.json rỗng")
        return

    old_tokens = load_tokens()
    uid_counts = {}
    for t, v in old_tokens.items():
        u = v.get("uid") or decode_jwt_uid(t)
        if u:
            uid_counts[str(u)] = max(uid_counts.get(str(u), 0), v.get("count", 0))

    await refresh_info_token()

    acc_items = list(accs.items())
    timeout = aiohttp.ClientTimeout(total=180)
    new_tokens = {}
    success = set()

    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = [login_single_account(u, p, session, i * 0.05) for i, (u, p) in enumerate(acc_items)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        now = time.time()
        retry = []
        for (u, p), res in zip(acc_items, results):
            us = str(u).strip()
            if isinstance(res, tuple) and len(res) >= 2 and res[1]:
                new_tokens[res[1]] = {"count": uid_counts.get(us, 0), "timestamp": now, "uid": us}
                success.add(us)
            else:
                retry.append((u, p))

        if retry:
            print(f"retry {len(retry)} acc...")
            await asyncio.sleep(3)
            rtasks = [login_single_account(u, p, session, i * 0.05) for i, (u, p) in enumerate(retry)]
            rresults = await asyncio.gather(*rtasks, return_exceptions=True)
            rnow = time.time()
            for (u, p), res in zip(retry, rresults):
                us = str(u).strip()
                if isinstance(res, tuple) and len(res) >= 2 and res[1]:
                    new_tokens[res[1]] = {"count": uid_counts.get(us, 0), "timestamp": rnow, "uid": us}
                    success.add(us)
            # acc fail hẳn -> giữ token cũ
            for u, p in retry:
                us = str(u).strip()
                if us in success: continue
                for ot, ov in old_tokens.items():
                    if (ov.get("uid") or decode_jwt_uid(ot)) == us:
                        new_tokens[ot] = ov
                        break

    save_tokens(new_tokens)
    set_last_refresh_time(time.time())
    print(f"refresh xong: {len(new_tokens)} token")

# ================== RESET 2H ==================
def do_reset():
    """Reset count toàn bộ token + xoá danh sách đã buff."""
    tokens = load_tokens()
    for t in tokens:
        tokens[t]["count"] = 0
    save_tokens(tokens)
    clear_dabuff()
    set_last_reset_ts(time.time())
    print(f"[{get_now_vn().strftime('%H:%M:%S')}] Đã reset count + dabuff (chu kỳ 2h)")
    return {
        "reset_at": get_now_vn().strftime("%Y-%m-%d %H:%M:%S"),
        "total_tokens": len(tokens)
    }

def auto_reset_if_due():
    """Reset nếu quá 2h kể từ lần reset trước. Gọi ở đầu mỗi /likes."""
    last = get_last_reset_ts()
    if last == 0:
        set_last_reset_ts(time.time())
        return None
    if time.time() - last >= RESET_INTERVAL:
        return do_reset()
    return None

# ================== PLAYER INFO / LIKE ==================
async def fetch_player_info(uid_num, session):
    tok = get_info_token()
    if not tok:
        await refresh_info_token()
        tok = get_info_token()
    if not tok: return None

    proto = b"\x08" + encode_varint(int(uid_num)) + b"\x10\x09\x18\x01\x20\x01"
    payload = aes_encrypt(proto)
    headers = {
        "Host": "clientbp.ppmainecoonghj.com", "ReleaseVersion": "OB55",
        "X-Unity-Version": "2018.4.12f1", "X-GA": "v1 1",
        "X-GA-SV": str(int(time.time())), "Authorization": f"Bearer {tok}",
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Content-Type": "application/x-www-form-urlencoded", "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive"
    }
    try:
        async with session.post("https://clientbp.ppmainecoonghj.com/GetPlayerPersonalShow",
                                headers=headers, data=payload, timeout=12) as r:
            if r.status == 200:
                raw = await r.read()
                o = data_pb2.AccountPersonalShowInfo(); o.ParseFromString(raw)
                b = o.basic_info
                return {"uid": b.account_id, "nickname": b.nickname, "level": b.level,
                        "region": b.region, "likes": b.liked}
    except Exception:
        pass
    return None

async def send_single_like(payload, token, session, delay):
    if delay > 0: await asyncio.sleep(delay)
    headers = {
        "Host": "clientbp.ppmainecoonghj.com", "ReleaseVersion": "OB55",
        "X-Unity-Version": "2018.4.12f1", "X-GA": "v1 1",
        "X-GA-SV": str(int(time.time())), "Authorization": f"Bearer {token}",
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Content-Type": "application/x-www-form-urlencoded", "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive"
    }
    try:
        async with session.post("https://clientbp.ppmainecoonghj.com/LikeProfile",
                                headers=headers, data=payload, timeout=10) as r:
            return r.status == 200
    except Exception:
        return False

async def process_send_likes(target_uid_str, target_likes=200):
    if is_dabuff(target_uid_str):
        return {"Failed": f"UID {target_uid_str} | Đã buff trong chu kỳ 2h này"}, 200

    timeout = aiohttp.ClientTimeout(total=300)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        info_before = await fetch_player_info(int(target_uid_str), session)
        if not info_before or "likes" not in info_before:
            return {"Failed": f"UID {target_uid_str} không tồn tại hoặc lỗi kết nối"}, 200

        name = info_before.get("nickname", "?")
        before = int(info_before["likes"])
        start = time.time()

        reg = str(info_before.get("region", "VN") or "VN")
        proto = b"\x08" + encode_varint(int(target_uid_str)) + b"\x12" + bytes([len(reg.encode())]) + reg.encode()
        payload = aes_encrypt(proto)

        tokens = load_tokens()
        if not tokens:
            return {"Failed": "Không có token nào. Hãy gọi /refresh trước"}, 200

        ordered = sorted(tokens.keys(), key=lambda t: tokens[t].get("count", 0))
        used = ordered[:max(target_likes * 2, target_likes)]
        likes_added = 0
        total_sent = 0

        try:
            for _ in range(5):
                if likes_added >= target_likes or not used:
                    break
                batch = used[: target_likes]
                total_sent += len(batch)
                tasks = [send_single_like(payload, t, session, i * 0.003) for i, t in enumerate(batch)]
                await asyncio.gather(*tasks, return_exceptions=True)
                await asyncio.sleep(0.5)
                info_after = await fetch_player_info(int(target_uid_str), session)
                if info_after and "likes" in info_after:
                    likes_added = int(info_after["likes"]) - before
                if likes_added >= target_likes:
                    break
                used = used[len(batch):]

            # cộng count cho token đã dùng
            if total_sent > 0:
                tokens = load_tokens()
                for t in ordered[:total_sent]:
                    if t in tokens:
                        tokens[t]["count"] = tokens[t].get("count", 0) + 1
                save_tokens(tokens)

            if likes_added <= 0:
                return {"Failed": f"UID {target_uid_str} | {name} | Không nhận thêm like (max/ngày hoặc lỗi)"}, 200

            add_dabuff(target_uid_str)
            elapsed = time.time() - start
            return {
                "result": {
                    "User Info": {
                        "Account UID": target_uid_str, "Account Name": name,
                        "Account Region": info_before.get("region", "Unknown"),
                        "Account Level": info_before.get("level", "0"),
                        "Account Likes": before
                    },
                    "Likes Info": {
                        "Likes Before": before,
                        "Likes After": before + likes_added,
                        "Likes Added": likes_added
                    },
                    "API": {
                        "speed": f"{elapsed:.1f}s",
                        "Success": True,
                        "tokens_used": total_sent
                    }
                }
            }, 200
        except Exception as e:
            return {"Failed": f"Lỗi xử lý: {e}"}, 200

# ================== ROUTES ==================
@app.route("/info", methods=["GET"])
def route_info():
    u = request.args.get("uid")
    if not u: return jsonify({"err": "Thiếu UID"}), 400
    try: uid_num = int(str(u).strip())
    except ValueError: return jsonify({"err": "UID phải là số"}), 400

    async def runner():
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as s:
            return await fetch_player_info(uid_num, s)

    try:
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        data = loop.run_until_complete(runner()); loop.close()
        if data: return jsonify({"status": "success", "data": data}), 200
        return jsonify({"err": "Không lấy được thông tin"}), 404
    except Exception as e:
        return jsonify({"err": str(e)}), 500

@app.route("/likes", methods=["GET"])
def route_likes():
    u = request.args.get("uid")
    if not u: return jsonify({"err": "Thiếu UID"}), 400
    c = request.args.get("count", "200")
    try: count = max(1, min(200, int(c)))
    except ValueError: count = 200

    # reset tự động nếu đã quá 2h
    try:
        auto_reset_if_due()
    except Exception as e:
        print(f"auto reset fail: {e}")

    try:
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        res, code = loop.run_until_complete(process_send_likes(str(u).strip(), count)); loop.close()
        return jsonify(res), code
    except Exception as e:
        return jsonify({"err": str(e)}), 500

@app.route("/refresh", methods=["GET"])
@app.route("/rs", methods=["GET"])
def route_refresh():
    try:
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        loop.run_until_complete(refresh_all_tokens_core()); loop.close()
        return jsonify({"status": "success", "total_tokens": len(load_tokens())}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/status", methods=["GET"])
def route_status():
    tokens = load_tokens()
    db = load_dabuff()
    state = _load_state()
    last_reset = get_last_reset_ts()
    return jsonify({
        "server_time_vn": get_now_vn().strftime("%Y-%m-%d %H:%M:%S"),
        "info_token_active": bool(get_info_token()),
        "total_tokens": len(tokens),
        "min_token_count": min((v.get("count", 0) for v in tokens.values()), default=0),
        "max_token_count": max((v.get("count", 0) for v in tokens.values()), default=0),
        "dabuff_current_cycle_total": len(db),
        "last_reset_at_vn": (
            datetime.fromtimestamp(last_reset, VN_TZ).strftime("%Y-%m-%d %H:%M:%S")
            if last_reset else ""
        ),
        "next_reset_seconds": get_next_reset_seconds(),
        "reset_interval_seconds": RESET_INTERVAL,
        "next_6h_refresh_seconds": int(get_seconds_until_6h_refresh()),
        "last_refresh_time": state.get("last_refresh_time", 0),
        "storage": "redis" if get_redis() else "memory"
    }), 200

# ================== CRON ENDPOINTS ==================
def _cron_authorized():
    secret = os.environ.get("CRON_SECRET")
    if not secret: return True
    auth = request.headers.get("Authorization", "")
    return auth == f"Bearer {secret}"

@app.route("/cron/refresh", methods=["GET"])
def cron_refresh():
    if not _cron_authorized(): return jsonify({"err": "unauthorized"}), 401
    try:
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        loop.run_until_complete(refresh_all_tokens_core()); loop.close()
        return jsonify({"ok": True, "total_tokens": len(load_tokens())}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/cron/reset", methods=["GET"])
def cron_reset():
    if not _cron_authorized(): return jsonify({"err": "unauthorized"}), 401
    try:
        info = do_reset()
        return jsonify({"ok": True, **info}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.after_request
def cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET,PUT,POST,DELETE,OPTIONS"
    return resp

if __name__ == "__main__":
    # Local: refresh lần đầu
    try:
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        loop.run_until_complete(refresh_all_tokens_core()); loop.close()
    except Exception as e:
        print(f"init refresh fail: {e}")
    app.run(host="0.0.0.0", port=3637, threaded=True, debug=False)
