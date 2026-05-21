import base64
from Crypto.Cipher import AES
from Crypto.Util import Counter

KEY = bytes([45, 67, 89, 12, 34, 56, 78, 90, 123, 234, 45, 67, 89, 12, 34, 56])


def fnv1a32(data):
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def derive_iv(timestamp, nonce):
    r67 = "0" + str(timestamp)
    iv = b""
    for i in range(4):
        h = fnv1a32((r67 + str(i) + str(nonce)).encode())
        if h & 0x80000000:
            h = 0x100000000 - h
        iv += h.to_bytes(4, "big")
    return iv


def aes_ctr(iv, data):
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
    return AES.new(KEY, AES.MODE_CTR, counter=ctr).encrypt(data)


def f_str(key, value):
    if not isinstance(value, (bytes, bytearray)):
        value = str(value).encode("latin-1")
    k = key.encode("latin-1")
    return bytes([len(k)]) + k + len(value).to_bytes(2, "little") + value


def f_int(key, value):
    if value <= 0xFF:
        n = 1
    elif value <= 0xFFFF:
        n = 2
    elif value > 0x7FFFFFFF:
        n = 8
    else:
        n = 4
    return f_str(key, value.to_bytes(n, "little"))


def build_inner(
    *,
    # outer fields
    nonce,                      # random int (Math.random()*0x7fffffff|0)
    server_time,                # timestamp + serverTimeOffset
    hash_="",                   # window.location.hash
    user_agent="",              # navigator.userAgent
    sync_hash=0,                # hashString(nonce + flags + tz + ... + appMode) signature
    stack_orig="J",             # 'I' / 'J' / 'K' from analyzeStackOrigin
    webrtc_ips="",              # WebRTC srflx IPs, comma-separated
    curr_rate="",               # flashvars.CURRENCY_EXCHANGE_RATE
    host="",                    # location.host
    country_id="",              # Locator.user.countryId
    flags1=0,                   # anti-bot bitfield #1, 0 = clean
    flags2=0,                   # anti-bot bitfield #2
    flags3=0,                   # anti-bot bitfield #3
    session_id="",              # cookie usdi/sid
    tz_offset=0,                # startDate.getTimezoneOffset() in minutes (-120 = UTC+2)
    url="",                     # current page URL
    app_mode=2,                 # 1 = lite, 2 = default
    body_hash=0,                # fnv1a32(ns_gen5_net.body)
    uqid="",                    # "uqid" cookie value
    timezone="UTC",             # Intl.DateTimeFormat().resolvedOptions().timeZone
    source_tag="?",             # r2, "s" for /placebet, "?" otherwise

    # nested "f" sub-record (sub_6de1)
    f_i_u=0,                    # count of hashed usernames in localStorage 'cf4'
    f_i_r=0,                    # total api calls tracked
    f_i_tf=0,                   # sessionAgeMs at /placebet (0 if not placebet)
    f_i_bt=0,                   # ms between /addbet and /placebet
    f_i_ps=0,                   # localStorage 'cf3' (sessionRandomId)
    f_i_au=0,                   # seconds since ns_datalib_net.Loader was invoked
    f_i_pl=0,                   # seconds since page load
    f_i_vr=157,                 # hardcoded constant
    f_i_hp=66,                  # hardcoded constant
    f_i_kl=231,                 # hardcoded constant
    f_i_ws=0,                   # date-derived byte
    f_mv="0",                   # window._websiteManifest.v
):
    p = b""
    p += f_str("a",  "1")
    p += f_int("b",  nonce)
    p += f_str("c",  hash_)
    p += f_int("d",  server_time)
    p += f_str("e",  user_agent)
    p += f_int("p",  sync_hash)
    p += f_str("g",  "")
    p += f_str("h",  stack_orig)
    p += f_str("i",  webrtc_ips)
    p += f_str("j",  curr_rate)
    p += f_str("k",  host)
    p += f_str("o",  country_id)
    p += f_int("q",  flags2)
    p += f_int("r",  flags1)
    p += f_str("s",  session_id)
    p += f_str("t",  tz_offset)
    p += f_str("u",  url)
    p += f_int("v",  app_mode)
    p += f_int("w",  body_hash)
    p += f_str("x",  uqid)
    p += f_str("z",  timezone)
    p += f_str("ab", source_tag)

    f = b""
    f += f_int("i_u",  f_i_u)
    f += f_int("i_r",  f_i_r)
    f += f_int("i_tf", f_i_tf)
    f += f_int("i_bt", f_i_bt)
    f += f_int("i_ps", f_i_ps)
    f += f_str("uqid", "")
    f += f_str("uv",   "")
    f += f_str("ur",   "")
    f += f_str("ua",   user_agent)
    f += f_str("il",   "false")
    f += f_str("ul",   url)
    f += f_str("d",    host)
    f += f_str("x",    source_tag)
    f += f_int("i_z",  app_mode)
    f += f_int("i_au", f_i_au)
    f += f_int("i_pl", f_i_pl)
    f += f_str("mv",   f_mv)
    f += f_int("i_vr", f_i_vr)
    f += f_int("i_hp", f_i_hp)
    f += f_int("i_kl", f_i_kl)
    f += f_int("i_ws", f_i_ws)
    p += f_str("f", f)

    p += f_int("aa", flags3)
    return p


def build_frame(payload, timestamp, nonce, sst=b"", lite=False):
    iv = derive_iv(timestamp, nonce)
    ct = aes_ctr(iv, payload)
    header = b"\x00" if lite else b"\x03\x34"
    return base64.b64encode(header + b"\x00\x04" + sst + iv + ct).decode()


def build(*, timestamp, nonce, sst=b"", lite=False, server_time=None, **fields):
    if server_time is None:
        server_time = timestamp
    payload = build_inner(nonce=nonce, server_time=server_time, **fields)
    return build_frame(payload, timestamp, nonce, sst=sst, lite=lite)


if __name__ == "__main__":
    frame = build(
        timestamp   = 1757033587456,
        nonce       = 547852641,
        hash_       = "#/HO/",
        user_agent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        sync_hash   = 0xCA0A840E,
        webrtc_ips  = "eefb:749a:6a04:98ed:f1b5:749c:17ea:5ad6",
        curr_rate   = "1.3522",
        host        = "www.va.bet365.com",
        country_id  = "198",
        session_id  = "077BFEC65C7845D48D6CBF380407675F000003",
        tz_offset   = -120,
        url         = "https://members.va.bet365.com/loginapi/lp/login",
        body_hash   = 0xC6B0D2BA,
        timezone    = "Europe/Paris",
        source_tag  = "s",
        f_i_u       = 14,
        f_i_r       = 16,
        f_i_ps      = 0x50F5CB88,
        f_i_pl      = 5,
        f_i_ws      = 174,
        f_mv        = "2671",
    )
    "x-net"
