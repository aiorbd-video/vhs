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

TOKEN_EXPIRE = 300  # 5 minutes

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
# TOKEN CREATE
# =========================================

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

# =========================================
# TOKEN VERIFY
# =========================================

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

        # EXPIRE CHECK

        if int(time.time()) > int(expire):
            return None

        # IP LOCK

        if ip != request_ip:
            return None

        # USER AGENT LOCK

        if ua != request_ua:
            return None

        # SIGNATURE VERIFY

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
# GENERATE STREAM LINK
# =========================================

async def generate_link(request):

    try:

        video_id = request.query.get("id")

        if not video_id:
            return web.json_response(
                {"error": "Missing video id"},
                status=400
            )

        # REAL USER IP

        ip = (
            request.headers.get(
                "CF-Connecting-IP"
            )
            or request.remote
        )

        # USER AGENT

        ua = request.headers.get(
            "User-Agent",
            ""
        )

        token = create_token(
            video_id,
            ip,
            ua
        )

        # FORCE HTTPS

        base = f"https://{request.host}"

        url = f"{base}/stream?token={token}"

        return web.json_response({
            "status": "success",
            "url": url
        })

    except Exception as e:

        logging.exception("GENERATE ERROR")

        return web.json_response({
            "error": str(e)
        }, status=500)

# =========================================
# STREAM HANDLER
# =========================================

async def stream(request):

    try:

        # OPTIONAL HOTLINK PROTECTION

        origin = (
            request.headers.get("Origin")
            or request.headers.get(
                "Referer",
                ""
            )
        )

        if (
            ALLOWED_ORIGIN != "*"
            and ALLOWED_ORIGIN not in origin
            and origin != ""
        ):
            return web.Response(
                status=403,
                text="Forbidden Origin"
            )

        # TOKEN

        token = request.query.get("token")

        if not token:
            return web.Response(
                status=403,
                text="Missing Token"
            )

        # REAL USER IP

        ip = (
            request.headers.get(
                "CF-Connecting-IP"
            )
            or request.remote
        )

        # USER AGENT

        ua = request.headers.get(
            "User-Agent",
            ""
        )

        # VERIFY TOKEN

        video_id = verify_token(
            token,
            ip,
            ua
        )

        if not video_id:
            return web.Response(
                status=403,
                text="Invalid or Expired Token"
            )

        # GET TELEGRAM MESSAGE

        msg = await tg.get_messages(
            CHANNEL_ID,
            ids=int(video_id)
        )

        if not msg:
            return web.Response(
                status=404,
                text="Message Not Found"
            )

        if not msg.media:
            return web.Response(
                status=404,
                text="Media Not Found"
            )

        file_size = msg.file.size

        # =====================================
        # RANGE SUPPORT
        # =====================================

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

        # =====================================
        # RESPONSE HEADERS
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

            "Cache-Control":
            "private, no-store",

            "Access-Control-Allow-Origin":
            ALLOWED_ORIGIN,

            "X-Content-Type-Options":
            "nosniff",

            "Cross-Origin-Resource-Policy":
            "cross-origin",
        }

        status = (
            206
            if range_header
            else 200
        )

        response = web.StreamResponse(
            status=status,
            headers=headers
        )

        await response.prepare(request)

        # =====================================
        # STREAM DOWNLOAD
        # =====================================

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
# HEALTH CHECK
# =========================================

async def health(request):

    return web.json_response({
        "status": "running"
    })

# =========================================
# INIT APP
# =========================================

async def init():

    logging.info(
        "Starting Telegram Client..."
    )

    await tg.start(
        bot_token=BOT_TOKEN
    )

    app = web.Application(
        client_max_size=1024**3
    )

    app.router.add_get(
        "/",
        health
    )

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
# RUN SERVER
# =========================================

web.run_app(
    init(),
    host="0.0.0.0",
    port=PORT
)
