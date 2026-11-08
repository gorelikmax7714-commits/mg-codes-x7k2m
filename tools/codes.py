#!/usr/bin/env python3
"""כלי עדכון קודים — מצפין/מפענח את רשימת הבניינים שב-index.html.

הקודים לעולם לא נשמרים בריפו כטקסט גלוי. רק הגרסה המוצפנת (VAULT) נכנסת ל-index.html.

שימוש (הסיסמה מגיעה ממשתנה סביבה, לא משורת הפקודה):
  CODES_PW=xxxx python3 tools/codes.py decrypt data.json   # index.html -> data.json (גלוי, מחוץ לריפו!)
  CODES_PW=xxxx python3 tools/codes.py encrypt data.json   # data.json -> VAULT ב-index.html

הצפנה: AES-256-GCM, מפתח נגזר ב-PBKDF2-SHA256 (ITER חזרות) — תואם WebCrypto בדפדפן.
"""
import base64, json, os, re, sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 600_000
INDEX = Path(__file__).resolve().parent.parent / "index.html"
VAULT_RE = re.compile(r"^const VAULT = .*;$", re.M)


def key(pw: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, ITER).derive(pw.encode())


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def encrypt(pw: str, data) -> dict:
    salt, iv = os.urandom(16), os.urandom(12)
    plain = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
    ct = AESGCM(key(pw, salt)).encrypt(iv, plain, None)
    return {"v": 1, "iter": ITER, "salt": b64(salt), "iv": b64(iv), "ct": b64(ct)}


def decrypt(pw: str, vault: dict):
    d = base64.b64decode
    k = PBKDF2HMAC(hashes.SHA256(), 32, d(vault["salt"]), vault["iter"]).derive(pw.encode())
    return json.loads(AESGCM(k).decrypt(d(vault["iv"]), d(vault["ct"]), None))


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("encrypt", "decrypt"):
        sys.exit(__doc__)
    pw = os.environ.get("CODES_PW") or sys.exit("חסר CODES_PW")
    cmd, path = sys.argv[1], Path(sys.argv[2])
    html = INDEX.read_text(encoding="utf-8")
    m = VAULT_RE.search(html) or sys.exit("לא נמצאה שורת VAULT ב-index.html")
    if cmd == "decrypt":
        data = decrypt(pw, json.loads(m.group(0)[len("const VAULT = "):-1]))
        path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"פוענחו {len(data)} בניינים -> {path}")
    else:
        data = json.loads(path.read_text(encoding="utf-8"))
        line = "const VAULT = " + json.dumps(encrypt(pw, data)) + ";"
        INDEX.write_text(html[:m.start()] + line + html[m.end():], encoding="utf-8")
        print(f"הוצפנו {len(data)} בניינים -> index.html")


if __name__ == "__main__":
    main()
