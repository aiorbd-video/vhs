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

API_ID = int(os.getenv("API_ID"))
API_HASH = os.getenv("API_HASH")

BOT_TOKEN = os.getenv("BOT_TOKEN")

CHANNEL_ID = int(os.getenv("CHANNEL_ID"))

SESSION_STRING = os.getenv("SESSION_STRING")

SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "super-secret"
).encode()

ALLOWED_ORIGIN = os.getenv(
    "ALLOWED_ORIGIN",
    "*"
)

PORT = int(os.getenv("PORT", 8080))

logging.basicConfig(level=logging.INFO)

# =========================================
# TELEGRAM CLIENT
# =========================================

tg = TelegramClient(
    StringSession(SESSION_STRING),
    API_ID,
    API_HASH
)

# =========================================
# TOKEN
# =========================================

TOKEN_EXPIRE = 300


def create_token(video_id, ip, ua):

    expire = int(time.time()) + TOKEN_EXPIRE

    payload = f"{video_id}|{ip}|{ua}|{expire}"

    sig = hmac.new(
        SECRET_KEY,
        payload.encode(),
        hashlib.sha256
    ).hexdigest()

    token = base64.urlsafe_b64encode(
        f"{payload}|{sig}".encode()
    ).decode()

    return token


def verify_token(token, request_ip, request_ua):

    try:

        decoded = base64.urlsafe_b64decode(
            token.encode()
        ).decode()

        parts = decoded.split("|")

        if len(parts) != 5:
            return None

        video_id = parts[0]
        ip = parts[1]
        ua = parts[2]
        expire = parts[3]
        sig = parts[4]

        if int(time.time()) > int(expire):
            return None

        if ip != request_ip:
            return None

        if ua != request_ua:
            return None

        payload = f"{video_id}|{ip}|{ua}|{expire}"

        expected_sig = hmac.new(
            SECRET_KEY,
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(
            expected_sig,
            sig
        ):
            return None

        return video_id

    except:
        return None

# =========================================
# GENERATE LINK
# =========================================

async def generate_link(request):

    video_id = request.query.get("id")

    if not video_id:
        return web.json_response(
            {"error": "Missing ID"},
            status=400
        )

    ip = request.remote

    ua = request.headers.get(
        "User-Agent",
        ""
    )

    token = create_token(
        video_id,
        ip,
        ua
    )

    base = f"{request.scheme}://{request.host}"

    url = f"{base}/stream?token={token}"

    return web.json_response({
        "status": "success",
        "url": url
    })

# =========================================
# STREAM
# =========================================

async def stream(request):

    try:

        token = request.query.get("token")

        if not token:
            return web.Response(
                status=403,
                text="Missing Token"
            )

        ip = request.remote

        ua = request.headers.get(
            "User-Agent",
            ""
        )

        video_id = verify_token(
            token,
            ip,
            ua
        )

        if not video_id:
            return web.Response(
                status=403,
                text="Invalid Token"
            )

        msg = await tg.get_messages(
            CHANNEL_ID,
            ids=int(video_id)
        )

        if not msg or not msg.media:
            return web.Response(
                status=404,
                text="Video Not Found"
            )

        file_size = msg.file.size

        range_header = request.headers.get(
            "Range",
            ""
        )

        start = 0
        end = file_size - 1

        if range_header:

            range_data = (
                range_header
                .replace("bytes=", "")
                .split("-")
            )

            if range_data[0]:
                start = int(range_data[0])

            if (
                len(range_data) > 1
                and range_data[1]
            ):
                end = int(range_data[1])

        chunk_size = (
            end - start
        ) + 1

        headers = {
            "Content-Type": "video/mp4",
            "Accept-Ranges": "bytes",
            "Content-Length": str(chunk_size),
            "Content-Range":
            f"bytes {start}-{end}/{file_size}",

            "Cache-Control":
            "private, no-store",

            "Access-Control-Allow-Origin":
            ALLOWED_ORIGIN,
        }

        response = web.StreamResponse(
            status=206 if range_header else 200,
            headers=headers
        )

        await response.prepare(request)

        downloaded = 0

        async for chunk in tg.iter_download(
            msg.media,
            offset=start,
            request_size=1024 * 1024
        ):

            if downloaded >= chunk_size:
                break

            remaining = (
                chunk_size
                - downloaded
            )

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

# =========================================
# INIT
# =========================================

async def init():

    await tg.start(
        bot_token=BOT_TOKEN
    )

    app = web.Application()

    app.router.add_get(
        "/generate",
        generate_link
    )

    app.router.add_get(
        "/stream",
        stream
    )

    return app

# =========================================
# RUN
# =========================================

web.run_app(
    init(),
    port=PORT
)
