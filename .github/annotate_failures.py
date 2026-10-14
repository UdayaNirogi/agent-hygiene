"""Turn unittest FAIL/ERROR blocks into GitHub error annotations, so the failing test
and its traceback show up on the run summary without opening the raw log."""
import re
import sys

text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
blocks = re.split(r"^={50,}$", text, flags=re.M)
count = 0
for block in blocks:
    block = block.strip()
    m = re.match(r"(FAIL|ERROR): (\S+) \(([^)]+)\)", block)
    if not m:
        continue
    body = block.split("-" * 70, 1)[-1].strip()
    body = body.split("\n" + "-" * 70, 1)[0][-3500:]
    body = body.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::error title={m.group(1)} {m.group(3)}.{m.group(2)}::{body}")
    count += 1
    if count >= 10:
        break
if count == 0:
    tail = text[-3500:].replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::error title=test run failed::{tail}")
