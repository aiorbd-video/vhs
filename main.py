import os
import time
import hmac
import hashlib
import logging
from aiohttp import web
from pyrogram import Client

# ==========================================
# 1. Environment Variables & Configuration
# ==========================================
API_ID = int(os.environ.get("API_ID", 0))
API_HASH = os.environ.get("API_HASH", "")
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
CHANNEL_ID = int(os.environ.get("CHANNEL_ID", 0))
PORT = int(os.environ.get("PORT", 8080))

SECRET_KEY = os.environ.get("SECRET_KEY", "generate-a-strong-random-key-here").encode()
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "https://xxstream.vercel.app") 
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123") 

logging.basicConfig(level=logging.INFO)
tg_app = Client("enterprise_stream", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

# ==========================================
# 2. IP & Signature Generator
# ==========================================
def get_client_ip(request):
    """সার্ভারের প্রক্সি ভেদ করে ইউজারের আসল আইপি বের করবে"""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote

def generate_secure_signature(message_id, expire_time, user_ip):
    """আইপি সহ HMAC সিগনেচার তৈরি করবে"""
    # ডেটার ভেতর IP অ্যাড্রেস ঢুকিয়ে দেওয়া হলো
    data = f"{message_id}:{expire_time}:{user_ip}".encode()
    return hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()

def verify_signature(message_id, expire_time, user_ip, provided_sig):
    """মেয়াদ এবং ইউজারের আইপি চেক করবে"""
    if int(time.time()) > int(expire_time):
        return False # লিংক এক্সপায়ার হয়ে গেছে
    expected_sig = generate_secure_signature(message_id, expire_time, user_ip)
    return hmac.compare_digest(expected_sig, provided_sig)

# ==========================================
# 3. Request Handlers
# ==========================================
async def generate_link_handler(request):
    """আপনার Next.js সাইট এই রাউট থেকে IP-Locked লিংক জেনারেট করবে"""
    msg_id = request.query.get("id")
    password = request.query.get("pass")
    
    # Next.js থেকে ইউজারের আইপি পাঠানো হবে
    target_ip = request.query.get("client_ip")
    
    if password != ADMIN_PASS:
        return web.json_response({"error": "Unauthorized"}, status=401)
    
    if not msg_id or not target_ip:
        return web.json_response({"error": "Message ID and Client IP are required"}, status=400)
    
    # লিংকের মেয়াদ ৩ ঘণ্টা
    expire_time = int(time.time()) + 10800 
    
    # নির্দিষ্ট আইপির জন্য সিগনেচার তৈরি
    signature = generate_secure_signature(msg_id, expire_time, target_ip)
    
    base_url = f"{request.scheme}://{request.host}"
    secure_url = f"{base_url}/stream/{msg_id}?expire={expire_time}&sig={signature}"
    
    return web.json_response({"status": "success", "secure_link": secure_url})

async def stream_handler(request):
    """প্লেয়ারে ভিডিও স্ট্রিম করার মূল ইঞ্জিন"""
    try:
        # ১. রিকোয়েস্ট করা ইউজারের বর্তমান আইপি বের করা
        current_user_ip = get_client_ip(request)

        origin = request.headers.get("Origin") or request.headers.get("Referer", "")
        if request.headers.get("Sec-Fetch-Mode") in ["cors", "no-cors"] and ALLOWED_ORIGIN not in origin:
             return web.Response(status=403, text="403 Forbidden: Protected Origin.")

        message_id = int(request.match_info.get('message_id'))
        expire = request.query.get("expire")
        sig = request.query.get("sig")

        # ২. আইপি বাইন্ডিং ভেরিফিকেশন (এখানেই ম্যাজিক!)
        if not expire or not sig or not verify_signature(message_id, expire, current_user_ip, sig):
            return web.Response(status=403, text="403 Forbidden: IP Mismatch or Token Expired.")

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
            start = int(ranges[0]) if ranges[0] else 0
            end = int(ranges[1]) if len(ranges) > 1 and ranges[1] else file_size - 1

        chunk_size = (end - start) + 1
        headers = {
            "Content-Type": "video/mp4",
            "Accept-Ranges": "bytes",
            "Content-Range": f"bytes {start}-{end}/{file_size}",
            "Content-Length": str(chunk_size),
            "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
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
