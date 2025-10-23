#!/usr/bin/env python3
import re, os, sys, pathlib, shutil, urllib.request

SRC_DIR = pathlib.Path("src/content/posts")
OUT_DIR = pathlib.Path("public/images/hackmd")
OUT_DIR.mkdir(parents=True, exist_ok=True)

if not SRC_DIR.exists():
    print(f"[!] Source dir not found: {SRC_DIR}")
    sys.exit(1)

pattern_full = re.compile(r'\[!image\]\((https://hackmd\.io/_uploads/[^)]+)\)')
pattern_md = re.compile(r'!\[([^\]]*)\]\((https://hackmd\.io/_uploads/[^)]+)\)')

urls = set()
for md in SRC_DIR.rglob("*.md"):
    text = md.read_text(encoding="utf-8")
    for m in pattern_full.finditer(text):
        urls.add(m.group(1))
    for m in pattern_md.finditer(text):
        urls.add(m.group(2))

if not urls:
    print("[*] No hackmd images found. Exiting.")
    sys.exit(0)

print(f"[*] Found {len(urls)} unique images. Downloading into {OUT_DIR} ...")
for url in sorted(urls):
    fname = os.path.basename(url)
    outpath = OUT_DIR / fname
    if outpath.exists():
        print(" - exists:", fname)
        continue
    try:
        print(" - downloading:", fname)
        with urllib.request.urlopen(url) as r, open(outpath, "wb") as f:
            f.write(r.read())
    except Exception as e:
        print("   ! failed to download", url, ":", e)
        if outpath.exists():
            outpath.unlink()

print("[*] Rewriting markdown files (backups *.bak created):")
for md in SRC_DIR.rglob("*.md"):
    txt = md.read_text(encoding="utf-8")
    new = pattern_full.sub(lambda m: f"![image](/images/hackmd/{os.path.basename(m.group(1))})", txt)
    new = pattern_md.sub(lambda m: f"![{m.group(1)}](/images/hackmd/{os.path.basename(m.group(2))})", new)
    if new != txt:
        bak = md.with_suffix(md.suffix + ".bak")
        shutil.copy2(md, bak)
        md.write_text(new, encoding="utf-8")
        print(" - patched:", md)
print("[*] Done. Run your dev server and verify.")
