"""Add a 'Created' column and image-provenance info to the LogHarvest viewer page.
Usage: python patch_viewer.py path/to/index.html     (makes index.html.bak; safe to run twice)
Needs the manifest rows to carry a `created` field (written by `image` / `desktop-apps` on file systems that record it)."""
import re, shutil, sys
p = sys.argv[1]; s = open(p, encoding="utf-8").read()
if 'k:"created"' in s: print("already patched"); sys.exit(0)
shutil.copy(p, p + ".bak"); n = 0
s, c = re.subn(r'(\{k:"changed_or_created",[^}]*\},)', r'\1{k:"created",t:"Created",w:150},', s, count=1); n += c
s, c = re.subn(r'(changed_or_created:fmtT\([^)]*\)[^,]*,)', r'\1created:fmtT(r.created),', s, count=1); n += c
s, c = re.subn(r'(const m=\[\["Source",r\.source\],)', r'\1["Created",r.created?fmtT(r.created):"(not recorded)"],["Image / origin",/^image:\\/\\//.test(r.source||"")?"read from disk image (guest file system times)":"live or mounted source"],', s, count=1); n += c
if n != 3: shutil.copy(p + ".bak", p); print(f"could not find all 3 places ({n}/3); page left unchanged. Edit by hand: add a Created column, row field and detail line."); sys.exit(1)
open(p, "w", encoding="utf-8").write(s); print("patched: Created column + image origin in the detail panel")
