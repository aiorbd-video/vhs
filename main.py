import os
import time
import hmac
import hashlib
import logging
from aiohttp import web
from pyrogram import Client, utils # utils ইম্পোর্ট করা হয়েছে
from dotenv import load_dotenv

#.env ফাইল থেকে সিকিউর ডেটা লোড করা হচ্ছে
load_dotenv()

# ==========================================
# 0. Pyrogram 64-bit Channel ID Bug Monkey Patch 🚀
# ==========================================
def get_peer_type_new(peer_id: int) -> str:
    peer_id_str = str(peer_id)
    if not peer_id_str.startswith("-"):
        return "user"
    elif peer_id_str.startswith("-100"):
        return "channel"
    else:
        return "chat"

utils.get_peer_type = get_peer_type_new

# ==========================================
# 1. Environment Variables & Configuration
# ==========================================
API_ID = int(os.getenv("API_ID", 0))
API_HASH = os.getenv("API_HASH", "")
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
CHANNEL_ID = int(os.getenv("CHANNEL_ID", 0))
PORT = int(os.getenv("PORT", 8080))

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key").encode()
ALLOWED_ORIGIN = os.getenv("ALLOWED_ORIGIN", "*") 
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin123") 

logging.basicConfig(level=logging.INFO)

# ইন-মেমোরি সেশন ব্যবহার করা হচ্ছে ক্লাউড হোস্টিংয়ের জন্য
tg_app = Client("enterprise_stream", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN, in_memory=True)

# ==========================================
# 2. Signature Generator (IP Lock Removed)
# ==========================================
def generate_secure_signature(message_id, expire_time):
    data = f"{message_id}:{expire_time}".encode()
    return hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()

def verify_signature(message_id, expire_time, provided_sig):
    if int(time.time()) > int(expire_time):
        return False 
    expected_sig = generate_secure_signature(message_id, expire_time)
    return hmac.compare_digest(expected_sig, provided_sig)

# ==========================================
# 3. Request Handlers
# ==========================================
async def generate_link_handler(request):
    msg_id = request.query.get("id")
    password = request.query.get("pass")
    
    if password!= ADMIN_PASS:
        return web.json_response({"error": "Unauthorized"}, status=401)
    
    if not msg_id:
        return web.json_response({"error": "Message ID is required"}, status=400)
    
    expire_time = int(time.time()) + 10800 # ৩ ঘণ্টা মেয়াদ
    signature = generate_secure_signature(msg_id, expire_time)
    
    base_url = f"{request.scheme}://{request.host}"
    secure_url = f"{base_url}/stream/{msg_id}?expire={expire_time}&sig={signature}"
    
    return web.json_response({"status": "success", "secure_link": secure_url})

async def stream_handler(request):
    try:
        origin = request.headers.get("Origin") or request.headers.get("Referer", "")
        
        if ALLOWED_ORIGIN!= "*" and request.headers.get("Sec-Fetch-Mode") in ["cors", "no-cors"] and ALLOWED_ORIGIN not in origin:
             return web.Response(status=403, text="403 Forbidden: Protected Origin.")

        message_id = int(request.match_info.get('message_id'))
        expire = request.query.get("expire")
        sig = request.query.get("sig")

        # এখানে IP মেলানোর শর্ত বাদ দিয়ে শুধু সিগনেচার আর এক্সপায়ার টাইম দেখা হচ্ছে
        if not expire or not sig or not verify_signature(message_id, expire, sig):
            return web.Response(status=403, text="403 Forbidden: Token Expired or Invalid Signature.")

        message = await tg_app.get_messages(CHANNEL_ID, message_id)
        if not message or not (message.video or message.document):
            return web.Response(status=404, text="404 Not Found")

        media = message.video or message.document
        file_size = media.file_size
        range_header = request.headers.get("Range", "")
        start = 0
        end = file_size - 1

        if range_header:
            ranges = range_header.replace("bytes=", "").split("-")
            start = int(ranges) if ranges else 0
            end = int(ranges[1]) if len(ranges) > 1 and ranges[1] else file_size - 1

        chunk_size = (end - start) + 1
        headers = {
            "Content-Type": "video/mp4",
            "Accept-Ranges": "bytes",
            "Content-Range": f"bytes {start}-{end}/{file_size}",
            "Content-Length": str(chunk_size),
            "Access-Control-Allow-Origin": "*",
        }

        response = web.StreamResponse(status=206 if range_header else 200, headers=headers)
        await response.prepare(request)

        async for chunk in tg_app.stream_media(message, offset=start, limit=chunk_size):
            await response.write(chunk)

        return response

    except Exception as e:
        logging.error(f"Streaming Error: {e}")
        return web.Response(status=500, text="Internal Server Error")

# ==========================================
# 4. Server Initialization
# ==========================================
async def init_app():
    logging.info("Starting Telegram MTProto Client...")
    await tg_app.start()
    
    app = web.Application()
    app.router.add_get('/api/generate', generate_link_handler)
    app.router.add_get('/stream/{message_id}', stream_handler)
    return app

if __name__ == '__main__':
    web.run_app(init_app(), port=PORT)
