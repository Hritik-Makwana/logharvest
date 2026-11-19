"""Adds an "All apps" dropdown to the LogHarvest viewer (index.html).

Usage:   python add_app_filter.py path/to/logharvest/index.html
Safe on a page you have already edited: it only touches the five places listed below, skips any it cannot find
(and says so), and does nothing if the filter is already there. A backup is written to index.html.bak.

What it changes:
  1. a <select id=fapp> next to the other filters
  2. the row filter in draw(): rows must match the chosen app (manifest field "app")
  3. the filter lists that wire 'input' events and the Reset button
  4. filling the dropdown with the apps present in the case
  5. an "App" line in the detail panel
"""
import re, shutil, sys

p = sys.argv[1] if len(sys.argv) > 1 else "index.html"
s = open(p, encoding="utf-8").read()
if "fapp" in s:
    print("already patched"); sys.exit(0)
shutil.copyfile(p, p + ".bak")
done, skipped = [], []


def sub(name, pattern, repl, flags=0, count=1):
    global s
    new, n = re.subn(pattern, repl, s, count=count, flags=flags)
    if n: s = new; done.append(name)
    else: skipped.append(name)


sub("1 dropdown", r"(<select id=fcat>.*?</select>)", r'\1\n<select id=fapp><option value="">All apps</option></select>', re.S)
sub("2 row filter", r'(&&\(!\$\("#fcat"\)\.value\|\|r\.category==\$\("#fcat"\)\.value\))', r'\1&&(!$("#fapp").value||r.app==$("#fapp").value)')
sub("3 listeners/reset", r'(\["#q",(?:"#\w+",)*"#\w+")(\])', r'\1,"#fapp"\2', count=0)
sub("4 fill dropdown", r'(\[\.\.\.new Set\(rows\.map\(r=>r\.os\)\)\]\.forEach\(v=>\$\("#fos"\)\.add\(new Option\(v,v\)\)\);)',
    r'\1[...new Set(rows.map(r=>r.app).filter(Boolean))].sort().forEach(v=>$("#fapp").add(new Option(v,v)));')
sub("5 detail line", r'(const m=\[\["Source",r\.source\],)', r'\1...(r.app?[["App",r.app+(r.app_group?" ("+r.app_group+")":"")]]:[]),')
open(p, "w", encoding="utf-8").write(s)
print("patched:", ", ".join(done) or "nothing")
if skipped: print("could not find (add by hand or send me the file):", ", ".join(skipped))
