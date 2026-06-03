import os
import time
import hmac
import hashlib
import logging

from aiohttp import web
from telethon import TelegramClient
from telethon.sessions import StringSession
from dotenv import load_dotenv

load_dotenv()

# ==========================================
# CONFIG
# ==========================================

API_ID = int(os.getenv("API_ID", 0))
API_HASH = os.getenv("API_HASH", "")
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
CHANNEL_ID = int(os.getenv("CHANNEL_ID", 0))
PORT = int(os.getenv("PORT", 8080))

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key").encode()

ALLOWED_ORIGIN = os.getenv("ALLOWED_ORIGIN", "*")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin123")

SESSION_STRING = os.getenv("SESSION_STRING", "")

logging.basicConfig(level=logging.INFO)

# ==========================================
# TELEGRAM CLIENT
# ==========================================

tg_client = TelegramClient(
    StringSession(SESSION_STRING),
    API_ID,
    API_HASH
)

# ==========================================
# TOKEN GENERATOR
# ==========================================

def generate_secure_signature(message_id, expire_time):
    data = f"{message_id}:{expire_time}".encode()

    return hmac.new(
        SECRET_KEY,
        data,
        hashlib.sha256
    ).hexdigest()


def verify_signature(message_id, expire_time, provided_sig):

    if int(time.time()) > int(expire_time):
        return False

    expected_sig = generate_secure_signature(
        message_id,
        expire_time
    )

    return hmac.compare_digest(
        expected_sig,
        provided_sig
    )

# ==========================================
# GENERATE LINK
# ==========================================

async def generate_link_handler(request):

    msg_id = request.query.get("id")
    password = request.query.get("pass")

    if password != ADMIN_PASS:
        return web.json_response(
            {"error": "Unauthorized"},
            status=401
        )

    if not msg_id:
        return web.json_response(
            {"error": "Message ID required"},
            status=400
        )

    expire_time = int(time.time()) + 10800

    signature = generate_secure_signature(
        msg_id,
        expire_time
    )

    base_url = f"{request.scheme}://{request.host}"

    secure_url = (
        f"{base_url}/stream/{msg_id}"
        f"?expire={expire_time}"
        f"&sig={signature}"
    )

    return web.json_response({
        "status": "success",
        "secure_link": secure_url
    })

# ==========================================
# STREAM HANDLER
# ==========================================

async def stream_handler(request):

    try:

        origin = (
            request.headers.get("Origin")
            or request.headers.get("Referer", "")
        )

        if (
            ALLOWED_ORIGIN != "*"
            and request.headers.get("Sec-Fetch-Mode") in ["cors", "no-cors"]
            and ALLOWED_ORIGIN not in origin
        ):
            return web.Response(
                status=403,
                text="Forbidden Origin"
            )

        message_id = int(
            request.match_info.get("message_id")
        )

        expire = request.query.get("expire")
        sig = request.query.get("sig")

        # VERIFY TOKEN

        if not expire or not sig:
            return web.Response(
                status=403,
                text="Missing Token"
            )

        if not verify_signature(
            message_id,
            expire,
            sig
        ):
            return web.Response(
                status=403,
                text="Invalid Token"
            )

        # FETCH TELEGRAM MESSAGE

        message = await tg_client.get_messages(
            CHANNEL_ID,
            ids=message_id
        )

        if not message:
            return web.Response(
                status=404,
                text="Message Not Found"
            )

        if not message.media:
            return web.Response(
                status=404,
                text="Media Not Found"
            )

        file_size = message.file.size

        # RANGE SUPPORT

        range_header = request.headers.get("Range")

        start = 0
        end = file_size - 1

        if range_header:

            range_value = (
                range_header
                .replace("bytes=", "")
                .split("-")
            )

            start = int(range_value[0]) if range_value[0] else 0

            if len(range_value) > 1 and range_value[1]:
                end = int(range_value[1])

        chunk_size = (end - start) + 1

        headers = {
            "Content-Type": "video/mp4",
            "Accept-Ranges": "bytes",
            "Content-Length": str(chunk_size),
            "Content-Range": f"bytes {start}-{end}/{file_size}",
            "Access-Control-Allow-Origin": "*",
        }

        status = 206 if range_header else 200

        response = web.StreamResponse(
            status=status,
            headers=headers
        )

        await response.prepare(request)

        downloaded = 0

        async for chunk in tg_client.iter_download(
            message.media,
            offset=start,
            request_size=512 * 1024
        ):

            if downloaded >= chunk_size:
                break

            remaining = chunk_size - downloaded

            if len(chunk) > remaining:
                chunk = chunk[:remaining]

            await response.write(chunk)

            downloaded += len(chunk)

        await response.write_eof()

        return response

    except Exception as e:

        logging.exception("STREAM ERROR")

        return web.Response(
            status=500,
            text=str(e)
        )

# ==========================================
# APP
# ==========================================

async def init_app():

    logging.info("Starting Telegram Client...")

    await tg_client.start(
        bot_token=BOT_TOKEN
    )

    app = web.Application()

    app.router.add_get(
        "/api/generate",
        generate_link_handler
    )

    app.router.add_get(
        "/stream/{message_id}",
        stream_handler
    )

    return app

# ==========================================
# MAIN
# ==========================================

if __name__ == "__main__":

    web.run_app(
        init_app(),
        port=PORT
    )
