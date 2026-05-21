# bet365 anti-bot vm writeup

When you hit endpoints like `/placebet` or `/loginapi/...` on bet365,
the page fires an `xcft` CustomEvent with a base64 blob in `detail`.
That blob is the output of a small VM bundled into the page as a
"websafe" script, and the server won't accept the request without it.

This repo has the decompiled VM, plus a python pair (`encryption.py`
and `build_payload.py`) that decrypts captured x-net-sync-term values
and builds new ones from scratch.

## what's in the repo

```
decompiled.js        the VM module, lifted from bytecode (~3.2k lines)
encryption.py      decrypt() / encrypt() for captured x-net-sync-term values
build_payload.py   build() a fresh x-net-sync-term value with custom fields
```

## the stack

Three layers of obfuscation before you see anything real:

1. A small bootstrap that `eval`s a base64 blob.
2. The eval'd module includes the VM interpreter and a second base64
   string, which decodes to the actual bytecode buffer.
3. The interpreter walks the buffer one opcode at a time.

I pulled the inner buffer out and dumped it to `bytecode.bin`.
About 67 KB.

## the VM

Around 40 opcodes. Standard register-based interpreter with a
`while (!eof)` loop, dispatch table, and a "saved frame" mechanism
for closures and CALL/RET. Operand patterns are minimal:

```
u8         one byte (register index, count, immediate)
u16be      two bytes, big-endian (string length)
i32be      four bytes, big-endian, signed (jumps and i32 immediates)
f64        eight bytes, custom IEEE 754 layout
xorstr:N   N bytes, each XOR'd with 0x71
reglist:N  N register indexes
pairs:N    N pairs of (dst, src_in_saved_frame), used by CALL
```

The opcode table looks like this:

```
0x02 BUILD_ARRAY    0x42 STRICT_EQ      0x91 GE
0x05 JMP            0x48 LOAD_I32       0x93 GET_PROP
0x08 OR             0x4e STRICT_NEQ     0x99 NEW
0x0d CALL           0x55 LE             0x9a SHL
0x0e EQ             0x59 NEQ            0xa7 MUL
0x12 SET_PROP       0x5a LOAD_U8        0xae SUB
0x13 GT             0x63 LOAD_F64       0xb1 HALT
0x2a RET            0x64 LOAD_STR       0xb5 ADD
0x36 APPLY          0x69 MOV            0xbb AND
0x37 TRY            0x6e XOR            0xc6 MOD
0x3c JZ             0x6f USHR           0xca MAKE_FN
                    0x72 DIV            0xea EVAL
                    0x77 THROW          0xef JNZ
                    0x88 SHR
                    0x8d LT
```

Strings are XOR'd with `0x71` on a per-byte basis. The bigger constant
tables (AES S-box, T-tables, FNV magic) are stored as decimal CSV in a
literal and each value is XOR'd with `0x7F` before going into the
table, parsed by `parseI32CsvArray` in the bootstrap.

## tools used

I wrote a handful of small scripts to get from the bootstrap down to
readable code:

- `extract_bytecode.js` peels the inner base64 out of the eval blob.
- `decoder.js` reverses the various string/buffer encodings.
- `disasm.js` walks the buffer and writes `disasm.txt` plus a
  JSON dump.
- `lift.js` rebuilds a CFG (back-edges, dominators, the usual),
  matches if/else, while, for, do/while, try/catch, and prints
  `decompiled.js`. The output is `r66 = sub_0xabcd(...)`-style
  pseudo-JS, but it reads.
- `rename.js` is a flat dict of `from -> to`. Every name in there was
  only added once I'd read the function body or its call sites.
  Anything still called `subNNNN` in the decompiled file is just "I
  haven't gotten around to it".

## the crypto

The interesting block lives in `onXcftrTriggerEvent`:

```js
r99 = sub_684a(r6c);             // r6c = Date.now()
r9b = sub_60fa(payload);         // string -> byte array
r9a = sub_6922(r99, r9b);        // AES happens in here
ra0 = sub_6a58(r99, r9a);        // header + sst + iv + ct, btoa'd
```

`sub_6922` is recognisable as AES-CTR pretty quickly. 16-byte counter,
per-block encryptor, XOR keystream into data, big-endian increment
with carry from the last byte:

```js
r78 = 15;
while (0 <= r78) {
  if (r68[r78] != 255) { r68[r78] = r68[r78] + 1; }
  else { r68[r78] = 0; r78 = r78 - 1; continue; }
}
```

The block encryptor `sub_657e` is textbook T-table AES: 4 tables of
256 i32s (`r56`, `r58`, `r5a`, `r5c`), final round through an S-box
(`r54`), 11 round keys at `r0[0..10]`. Standard AES-128.

So far this is what you'd expect. The interesting part is the key
schedule.

## the misdirection

The natural read of `sub_6922(r99, r9b)` is "key, data". `r99` is 16
bytes coming out of `sub_684a`, which builds them from FNV-1a hashes
of `(timestamp + i + nonce)`. You'd assume that's the AES key.

Open `sub_634a`:

```js
r67[0] = (45  << 24 | 67  << 16 | 89  << 8 | 12 );
r67[1] = (34  << 24 | 56  << 16 | 78  << 8 | 90 );
r67[2] = (123 << 24 | 234 << 16 | 45  << 8 | 67 );
r67[3] = (89  << 24 | 12  << 16 | 34  << 8 | 56 );

ra5 = 0;
while (ra5 < 4) {
  ra8 = (ra5 >> 2);
  r0[ra8][ra5 % 4] = r67[ra5];      // first round key gets the hardcoded words
  r1[10 - ra8][ra5 % 4] = r67[ra5];
  ra5++;
}

ra8 = sub_621e(r67, 4, r66);        // r66 is the caller's "key"
```

First round key is hardcoded:

```
2D 43 59 0C  22 38 4E 5A  7B EA 2D 43  59 0C 22 38
```

`sub_621e` does take the user key as its third argument, but if you
trace it you'll see the parameter is carried straight through and
returned unchanged. It's never read inside the function. The key
schedule is fully determined by the hardcoded 16 bytes.

What that means:

- **AES key**: the 16 hardcoded bytes above. Same for every request.
- **Initial counter (IV)**: the per-message 16 bytes from `sub_684a`.
- **IV is sent inside the x-net-sync-term value** so the server can pull it back out.

The misdirection is pretty clean. Anyone glancing at the call site
sees "function takes a key, here's where the key gets built", and
moves on. You only catch it if you actually read the schedule body.

## the x-net-sync-term value

The output of `sub_6a58` ends up as the `x-net-sync-term` request header
on the eventual HTTP call:

```
btoa( header || marker || sst || iv || ciphertext )
```

- header: `03 34` (default) or `00` (lite mode, when `liteMode == 1`)
- marker: always `00 04`
- sst:    `atob(WebsiteConfig.SST)`, runtime config from the page,
          variable length, no length prefix
- iv:     16 bytes (the counter from `sub_684a`)
- ct:     same length as the input payload

The server knows the SST length because it picked it. We don't.

## recovering the IV anyway

The first thing `buildRequestPayload` does is:

```js
r67 = sub_6abc("a", "1");
```

`sub_6abc` is the TLV emitter: 1-byte key length, key bytes, 2-byte
LE value length, value bytes. So `("a", "1")` is always exactly 5
bytes:

```
01 'a' 01 00 '1'   ->   01 61 01 00 31
```

That's a fixed prefix on every decrypted payload. So in `decrypt()`:

```python
for off in range(len(raw) - 16):
    iv = raw[off:off + 16]
    pt = _cipher(iv).decrypt(raw[off + 16:])
    if pt.startswith(b"\x01a\x01\x001"):
        return pt
```

Trial-decrypt at every offset, check for the prefix. Slow worst-case
but the SST is usually under a few hundred bytes so it lands fast.

## the payload format

Every field is the same TLV shape: `1B keylen | key | 2B LE vallen | value`.
Two helpers:

- `sub_6abc(k, v)` for strings.
- `sub_6c3f(k, n)` for integers. Picks u8 / u16 / u32 / u64 LE by
  magnitude (`<= 0xFF` -> u8, `<= 0xFFFF` -> u16, `> 0x7FFFFFFF` ->
  u64, else u32).

`buildRequestPayload` (`sub_78df`) glues the outer fields together.
There's also a nested record built by `sub_6de1` that gets emitted as
field `"f"`.

Decoded fields from a captured x-net-sync-term value:

```
a  "1"                              hardcoded marker
b  u32 nonce                        Math.random based, set once at boot
c  string                           window.location.hash
d  u64 server time (ms)             Date.now() + serverTimeOffset
e  string                           navigator.userAgent
p  u64                              X-Net-Sync-Term signature
g  string                           window.readit.conId (often empty)
h  string                           'I' / 'J' / 'K' from analyzeStackOrigin
i  string                           WebRTC srflx IPs, comma-separated
j  string                           CURRENCY_EXCHANGE_RATE
k  string                           location.host
o  string                           Locator.user.countryId
q  u8                               anti-bot bitfield #2
r  u8                               anti-bot bitfield #1
s  string                           session id
t  string                           tz offset in minutes (e.g. "-120")
u  string                           current page URL
v  u8                               app mode (1 = lite, 2 = default)
w  u64                              FNV1a of outgoing request body
x  string                           "uqid" cookie value
z  string                           IANA timezone name
ab string                           dispatch source tag ("s" for /placebet)
f  nested record                    timing / fingerprint sub-fields
aa u8                               anti-bot bitfield #3
```

The nested `f` record carries things like `i_u` (count of usernames
hashed in localStorage `cf4`), `i_r` (total api calls this hour),
`i_ps` (persistent random id from localStorage `cf3`), `i_pl`
(seconds since page load), `mv` (`_websiteManifest.v`), and a few
hardcoded version-ish constants (`i_vr=157`, `i_hp=66`, `i_kl=231`).

The two anti-bot bitfields `q` and `r` are flipped by all the various
probes scattered through the bytecode (WebRTC reachability, plugins,
UA-data, headless markers, `pointerEvents: none` on media, hidden
canvas font widths, etc.). `0` in both means every check passed.

## using it

Decrypt an x-net-sync-term value:

```python
from encryption import decrypt
pt = decrypt("AzQABAC6AAFQkc8T...")
```

Build a fresh x-net-sync-term value:

```python
from build_payload import build

sync_term = build(
    timestamp   = 1757033587456,
    nonce       = 547852641,
    user_agent  = "Mozilla/5.0 ...",
    session_id  = "077BFEC65C7845D48D6CBF380407675F000003",
    url         = "https://members.va.bet365.com/loginapi/lp/login",
    host        = "www.va.bet365.com",
    sst         = b"<your config's SST>",
)
```

Every parameter on `build()` has a default and a one-line comment in the
source. Set the ones you care about, leave the rest.

## what's not in the repo

- The SST blob. That's per-site / per-config; grab your own from
  `window.ns_weblib_util.WebsiteConfig.SST` in devtools.
- The hooks I dropped into the page to capture live x-net-sync-term
  values for the testing rig.
- Anything tied to a specific account.

## 📞 Contact

For inquiries, discussions or **paid projects / freelance work**:  
**Telegram:** [@azulax1](https://t.me/azulax1)  
**Discord:** dch002

## references

- `decompiled.js` is the full decompiled VM, all 3.2k lines of
  it. Search by `subXXXX` if you want to follow something specific.
- `disasm.txt` is the raw instruction listing if you want
  byte-level detail.
- The opcode table is also documented inline at the top of
  `disasm.js`.
