import os
import time
import hmac
import base64
import hashlib
import logging

from aiohttp import web
from telethon import TelegramClient
from telethon.sessions import StringSession

# =========================================
# CONFIG
# =========================================

API_ID = int(os.getenv("API_ID", "0"))

API_HASH = os.getenv("API_HASH", "")

SESSION_STRING = os.getenv(
    "SESSION_STRING",
    ""
)

CHANNEL_ID = int(
    os.getenv("CHANNEL_ID", "0")
)

SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "secret_key"
)

PORT = int(
    os.getenv("PORT", "8080")
)

logging.basicConfig(level=logging.INFO)

# =========================================
# TELEGRAM CLIENT
# =========================================

client = TelegramClient(
    StringSession(SESSION_STRING),
    API_ID,
    API_HASH
)

# =========================================
# TOKEN GENERATOR
# =========================================

def generate_token(message_id):

    expire = int(time.time()) + 3600

    raw_data = f"{message_id}:{expire}"

    signature = hmac.new(
        SECRET_KEY.encode(),
        raw_data.encode(),
        hashlib.sha256
    ).hexdigest()

    token = base64.urlsafe_b64encode(
        f"{raw_data}:{signature}".encode()
    ).decode()

    return token

# =========================================
# TOKEN VERIFY
# =========================================

def verify_token(token):

    try:

        decoded = base64.urlsafe_b64decode(
            token
        ).decode()

        message_id, expire, sig = decoded.split(':')

        raw_data = f"{message_id}:{expire}"

        expected_sig = hmac.new(
            SECRET_KEY.encode(),
            raw_data.encode(),
            hashlib.sha256
        ).hexdigest()

        if expected_sig != sig:
            return None

        if int(expire) < int(time.time()):
            return None

        return int(message_id)

    except Exception as e:

        logging.error(f"Token verify error: {e}")

        return None

# =========================================
# HEALTH
# =========================================

async def health(request):

    return web.json_response({
        "status": "running"
    })

# =========================================
# GENERATE URL
# =========================================

async def generate(request):

    message_id = request.query.get("id")

    if not message_id:

        return web.json_response({
            "status": "error",
            "message": "No ID"
        })

    token = generate_token(message_id)

    stream_url = (
        f"{request.scheme}://"
        f"{request.host}"
        f"/{token}/video.mp4"
    )

    return web.json_response({

        "status": "success",

        "url": stream_url
    })

# =========================================
# OPTIONS
# =========================================

async def options_handler(request):

    return web.Response(

        status=200,

        headers={

            "Access-Control-Allow-Origin":
            "*",

            "Access-Control-Allow-Headers":
            "*",

            "Access-Control-Allow-Methods":
            "GET, OPTIONS",
        }
    )

# =========================================
# STREAM VIDEO
# =========================================

async def stream(request):

    token = request.match_info.get("token")

    if not token:

        return web.Response(
            status=403,
            text="No token"
        )

    message_id = verify_token(token)

    if not message_id:

        return web.Response(
            status=403,
            text="Invalid token"
        )

    try:

        message = await client.get_messages(
            CHANNEL_ID,
            ids=message_id
        )

        if not message or not message.media:

            return web.Response(
                status=404,
                text="Video not found"
            )

        file_size = message.file.size

        range_header = request.headers.get(
            "Range"
        )

        start = 0
        end = file_size - 1

        # =====================================
        # RANGE PARSE
        # =====================================

        if range_header:

            bytes_range = (
                range_header
                .replace("bytes=", "")
                .split("-")
            )

            start = int(bytes_range[0])

            if bytes_range[1]:
                end = int(bytes_range[1])

        chunk_size = (
            end - start
        ) + 1

        # =====================================
        # HEADERS
        # =====================================

        headers = {

            "Content-Type":
            "video/mp4",

            "Accept-Ranges":
            "bytes",

            "Content-Length":
            str(chunk_size),

            "Content-Range":
            f"bytes {start}-{end}/{file_size}",

            "Access-Control-Allow-Origin":
            "*",

            "Access-Control-Allow-Headers":
            "*",

            "Access-Control-Allow-Methods":
            "GET, OPTIONS",

            "Cross-Origin-Resource-Policy":
            "cross-origin",

            "Cache-Control":
            "public, max-age=3600",
        }

        response = web.StreamResponse(

            status=206 if range_header else 200,

            headers=headers
        )

        await response.prepare(request)

        current = start

        # =====================================
        # DOWNLOAD STREAM
        # =====================================

        async for chunk in client.iter_download(

            message.media,

            offset=start,

            request_size=1024 * 512,
        ):

            if current > end:
                break

            remaining = (
                end - current
            ) + 1

            if len(chunk) > remaining:

                chunk = chunk[:remaining]

            await response.write(chunk)

            current += len(chunk)

        await response.write_eof()

        return response

    except Exception as e:

        logging.error(
            f"Streaming error: {e}"
        )

        return web.Response(

            status=500,

            text=str(e)
        )

# =========================================
# STARTUP
# =========================================

async def startup(app):

    logging.info(
        "Starting Telegram Client..."
    )

    await client.start()

    logging.info(
        "Telegram Client Started"
    )

# =========================================
# APP
# =========================================

app = web.Application()

app.router.add_get("/", health)

app.router.add_get("/generate", generate)

app.router.add_get("/{token}/video.mp4", stream)

app.router.add_route(
    "OPTIONS",
    "/{token}/video.mp4",
    options_handler
)

app.on_startup.append(startup)

# =========================================
# RUN
# =========================================

web.run_app(
    app,
    port=PORT
)
