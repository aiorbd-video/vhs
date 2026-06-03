import os
import time
import hmac
import base64
import hashlib
import logging

from aiohttp import web
from telethon import TelegramClient
from telethon.sessions import StringSession

# ====================================
# CONFIG
# ====================================

API_ID = int(os.getenv("API_ID"))
API_HASH = os.getenv("API_HASH")
SESSION_STRING = os.getenv("SESSION_STRING")
CHANNEL_ID = int(os.getenv("CHANNEL_ID"))

SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "secret_key"
)

PORT = int(os.getenv("PORT", 8080))

logging.basicConfig(level=logging.INFO)

# ====================================
# TELEGRAM CLIENT
# ====================================

client = TelegramClient(
    StringSession(SESSION_STRING),
    API_ID,
    API_HASH
)

# ====================================
# TOKEN GENERATOR
# ====================================

def generate_token(message_id):

    expire = int(time.time()) + 3600

    raw = f"{message_id}:{expire}"

    signature = hmac.new(
        SECRET_KEY.encode(),
        raw.encode(),
        hashlib.sha256
    ).hexdigest()

    token = base64.urlsafe_b64encode(
        f"{raw}:{signature}".encode()
    ).decode()

    return token

# ====================================
# VERIFY TOKEN
# ====================================

def verify_token(token):

    try:

        decoded = base64.urlsafe_b64decode(
            token
        ).decode()

        message_id, expire, sig = decoded.split(':')

        raw = f"{message_id}:{expire}"

        expected = hmac.new(
            SECRET_KEY.encode(),
            raw.encode(),
            hashlib.sha256
        ).hexdigest()

        if expected != sig:
            return None

        if int(expire) < int(time.time()):
            return None

        return int(message_id)

    except Exception:
        return None

# ====================================
# GENERATE STREAM URL
# ====================================

async def generate(request):

    message_id = request.query.get("id")

    if not message_id:

        return web.json_response({
            "status": "error",
            "message": "No ID"
        })

    token = generate_token(message_id)

    url = f"{request.scheme}://{request.host}/stream?token={token}"

    return web.json_response({
        "status": "success",
        "url": url
    })

# ====================================
# STREAM VIDEO
# ====================================

async def stream(request):

    token = request.query.get("token")

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
            'Range',
            None
        )

        start = 0
        end = file_size - 1

        # RANGE SUPPORT

        if range_header:

            bytes_range = range_header.replace(
                'bytes=',
                ''
            )

            start_str, end_str = bytes_range.split('-')

            start = int(start_str)

            if end_str:
                end = int(end_str)

        chunk_size = (end - start) + 1

        headers = {

            'Content-Type': 'video/mp4',

            'Accept-Ranges': 'bytes',

            'Content-Length': str(chunk_size),

            'Content-Range':
            f'bytes {start}-{end}/{file_size}',

            'Access-Control-Allow-Origin': '*',
        }

        response = web.StreamResponse(
            status=206,
            headers=headers
        )

        await response.prepare(request)

        downloaded = 0

        async for chunk in client.iter_download(
            message.media,
            offset=start,
            request_size=1024 * 512
        ):

            if downloaded >= chunk_size:
                break

            if downloaded + len(chunk) > chunk_size:

                chunk = chunk[
                    :chunk_size - downloaded
                ]

            await response.write(chunk)

            downloaded += len(chunk)

        return response

    except Exception as e:

        logging.error(str(e))

        return web.Response(
            status=500,
            text=str(e)
        )

# ====================================
# HEALTH CHECK
# ====================================

async def health(request):

    return web.json_response({
        "status": "running"
    })

# ====================================
# APP
# ====================================

app = web.Application()

app.router.add_get('/', health)

app.router.add_get('/generate', generate)

app.router.add_get('/stream', stream)

# ====================================
# STARTUP
# ====================================

async def startup(app):

    logging.info(
        "Starting Telegram Client..."
    )

    await client.start()

    logging.info(
        "Telegram Client Started"
    )

app.on_startup.append(startup)

# ====================================
# RUN
# ====================================

web.run_app(
    app,
    port=PORT
)
