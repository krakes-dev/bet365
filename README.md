# bet365 anti-bot VM writeup

How bet365 builds the `x-net-sync-term` value that its endpoints (`/placebet`,
`/loginapi/...`) refuse to work without, and how to read the virtual machine that
produces it. 

It lets you scrape odds or any data from the site in real time

## 📞 Contact

**Questions, bugs, or want something analysed? Paid projects and freelance work welcome.**

| | |
| --- | --- |
| **Telegram** | [@azulax1](https://t.me/azulax1) |
| **Discord** | dch002 |

---

## In short

The page runs a small VM, shipped as a "websafe" script. When you hit a protected
endpoint, it fires an `xcft` CustomEvent with a base64 blob in `detail`. That blob is
the VM's output, and the server rejects the request without it.

The blob is AES-128-CTR. The surprise: **the key is hardcoded and the same for every
request.** Only the IV changes.

## Run it

You need Python 3.10+ and Node 18+.


    ./run.sh

Then open **`work/decompiled_clean.js`**, the readable version.

If the download is refused (403), bet365 blocked your address. Use a proxy:

    PROXY=http://user:pass@host:port ./run.sh

## Files

| File | What it is |
| --- | --- |
| `work/decompiled_clean.js` | Readable JavaScript. Start here. |
| `work/decompiled_renamed.js` | Same code, closer to the raw instructions. Use it to double-check the clean one. |
| `work/decompiled.js` | Raw output, no names. |
| `work/disasm.txt` | One line per VM instruction. |

## Tools

`./run.sh` runs these in order. Each reads what the one before wrote.

1. `fetch.py` downloads the bundle from bet365
2. `extract_bytecode.js` peels the hidden base64 payload out of it
3. `decoder.js` works out what each VM opcode does
4. `disasm.js` turns the payload into instructions
5. `lift.js` rebuilds the control flow (if/else, loops, try/catch)
6. `clean.js` simplifies that into readable JavaScript


## The crypto

The interesting block is `onXcftrTriggerEvent`:

```js
r99 = sub_684a(r6c);             // r6c = Date.now()
r9b = sub_60fa(payload);         // string -> byte array
r9a = sub_6922(r99, r9b);        // AES happens in here
ra0 = sub_6a58(r99, r9a);        // header + sst + iv + ct, btoa'd
```

`sub_6922` is AES-CTR: a 16-byte counter, a per-block encryptor, the keystream XORed
into the data, and a big-endian increment with carry from the last byte.

```js
r78 = 15;
while (0 <= r78) {
  if (r68[r78] != 255) { r68[r78] = r68[r78] + 1; }
  else { r68[r78] = 0; r78 = r78 - 1; continue; }
}
```

The block encryptor `sub_657e` is textbook T-table AES-128: four tables of 256
integers, a final round through an S-box, 11 round keys.

## The misdirection

`sub_6922(r99, r9b)` reads as "key, data". `r99` is 16 bytes from `sub_684a`, built
from FNV-1a hashes of `(timestamp + i + nonce)`. It looks like the AES key. It is not.

Open `sub_634a`:

```js
r67[0] = (45  << 24 | 67  << 16 | 89  << 8 | 12 );
r67[1] = (34  << 24 | 56  << 16 | 78  << 8 | 90 );
r67[2] = (123 << 24 | 234 << 16 | 45  << 8 | 67 );
r67[3] = (89  << 24 | 12  << 16 | 34  << 8 | 56 );
```

The first round key is hardcoded:

    2D 43 59 0C  22 38 4E 5A  7B EA 2D 43  59 0C 22 38

`sub_621e` receives the caller's "key" as its third argument, but never reads it: the
parameter is returned unchanged. The whole key schedule comes from those 16 bytes.

- **AES key:** the 16 hardcoded bytes above. Same for every request.
- **IV (initial counter):** the per-message 16 bytes from `sub_684a`.
- **The IV travels inside the value**, so the server can pull it back out.

Anyone glancing at the call site sees "a function that takes a key" and moves on. You
only catch it by reading the schedule.

## The x-net-sync-term value

```
btoa( header || marker || sst || iv || ciphertext )
```

| Part | Value |
| --- | --- |
| header | `03` + a version byte, or just `00` in lite mode (`liteMode == 1`) |
| marker | always `00 04` |
| sst | `atob(WebsiteConfig.SST)`, from the page config, variable length, no length prefix |
| iv | 16 bytes, the counter from `sub_684a` |
| ct | same length as the input payload |

The version byte changes between bundles: `4D` in the `cwc` v749 bundle decompiled
here, `47` in an older capture. Read it from the bundle you are analysing.

## Names in this repo

The writeup uses the function names from the original analysis. In the current
`decompiled_clean.js` the same roles are named:

| Writeup | Current name | Role |
| --- | --- | --- |
| `sub_684a` | `deriveIV` | 4 x FNV-1a, gives the 16-byte IV |
| `sub_60fa` | `stringToBytes` | string to byte array |
| `sub_6a58` | `packEnvelopeBase64` | header + sst + iv + ct, then `btoa` |
| `sub_634a` | `aesSetupKey` | holds the hardcoded key |
| `sub_6922` | `aesCtrEncrypt` | CTR mode (matched by role) |
| `sub_621e` | `aesExpandKey` | key schedule (matched by role) |
| `sub_657e` | `aesEncryptBlock` | one AES block (matched by role) |

## Good to know

The clean version is a best effort, not bet365's source. A few spots still show a
`goto`, or a loop that does not read cleanly. When a result looks odd, compare it with
`decompiled_renamed.js`.

---

**📞 Telegram [@azulax1](https://t.me/azulax1)  |  Discord dch002**
