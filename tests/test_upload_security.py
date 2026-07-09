#!/usr/bin/env python3
"""文件上传安全测试"""
import sys, os, io
sys.path.insert(0, "/root")
from app.upload_handler import validate_upload
from werkzeug.datastructures import FileStorage
from PIL import Image

results = []

def test(name, ok, detail=""):
    mark = "OK" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f"  ({detail})" if detail else ""))
    results.append((name, ok))

def mkf(content, filename, ct=None):
    return FileStorage(stream=io.BytesIO(content), filename=filename, content_type=ct)

def rpng():
    buf = io.BytesIO()
    Image.new("RGB", (5,5), (255,0,0)).save(buf, "PNG")
    return buf.getvalue()

def rjpg():
    buf = io.BytesIO()
    Image.new("RGB", (5,5), (0,255,0)).save(buf, "JPEG")
    return buf.getvalue()

def rgif():
    buf = io.BytesIO()
    Image.new("RGB", (5,5), (0,0,255)).save(buf, "GIF")
    return buf.getvalue()

d = "/root/uploads"
if os.path.exists(d):
    for f in os.listdir(d):
        os.remove(os.path.join(d, f))

print("=" * 50)
print("Upload Security Tests")
print("=" * 50)

print("\n--- 1. Valid images ---")
ok, m, r = validate_upload(mkf(rpng(), "avatar.png", "image/png"))
test("PNG upload success", ok, m)

ok, m, r = validate_upload(mkf(rjpg(), "photo.jpg", "image/jpeg"))
test("JPG upload success", ok, m)

ok, m, r = validate_upload(mkf(rgif(), "anim.gif", "image/gif"))
test("GIF upload success", ok, m)

print("\n--- 2. Dangerous types rejected ---")
test("SVG rejected", not validate_upload(mkf(b"<svg>", "a.svg", "image/svg+xml"))[0])
test("PHP rejected", not validate_upload(mkf(b"<?php", "a.php", "app/x-php"))[0])
test("HTML rejected", not validate_upload(mkf(b"<html>", "a.html", "text/html"))[0])

print("\n--- 3. Double extension bypass ---")
test("evil.jpg.php rejected", not validate_upload(mkf(rpng(), "evil.jpg.php", "image/png"))[0])

print("\n--- 4. Fake content-type ---")
test("PHP disguised as PNG", not validate_upload(mkf(b"<?php eval();?>", "c.png", "image/png"))[0])
test("text as jpg rejected", not validate_upload(mkf(b"plain text", "i.jpg", "image/jpeg"))[0])

print("\n--- 5. MIME mismatch ---")
test("png ext but text content", not validate_upload(mkf(b"not an image", "f.png", "image/png"))[0])

print("\n--- 6. Path traversal ---")
test("../../app.py rejected", not validate_upload(mkf(rpng(), "../../app.py", "image/png"))[0])

print("\n--- 7. No overwrite ---")
_, _, r1 = validate_upload(mkf(rpng(), "same.png", "image/png"))
_, _, r2 = validate_upload(mkf(rpng(), "same.png", "image/png"))
test("different filenames for same name", r1 and r2 and r1["safe_name"] != r2["safe_name"])

print("\n--- 8. Size limit ---")
test(">16MB rejected", not validate_upload(mkf(b"x"*(17<<20), "big.png", "image/png"))[0])

print("\n--- Summary ---")
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}")
sys.exit(0 if failed == 0 else 1)
