#!/usr/bin/env python3
"""Known-answer checks for OVN's lflow language, taken from upstream's own
autotest suite (tests/ovn.at): every case of the "expression parser",
"expression annotation" and "action parsing" tests is fed to
`ovstest test-ovn <cmd>` (tests/test-ovn.c) and its output compared with the
expected output upstream records. Prints "PASS/FAIL <name>" per case and a
final "COUNTS <passed> <failed>" line."""
import re
import subprocess
import sys

OVSTEST, OVN_AT = sys.argv[1], sys.argv[2]
lines = open(OVN_AT, encoding="utf-8").read().split("\n")


def at_data(setup):
    """Raw AT_DATA([test-cases.txt], ...) body of AT_SETUP([setup])."""
    i = lines.index("AT_SETUP([%s])" % setup)
    while not lines[i].startswith("AT_DATA([test-cases.txt]"):
        i += 1
    double = lines[i].endswith("[[")
    body = []
    i += 1
    while lines[i] not in ("]])", "])"):
        # m4 quadrigraphs for brackets.
        body.append(lines[i].replace("@<:@", "[").replace("@:>@", "]"))
        i += 1
    return body, double


def run(cmd, text):
    p = subprocess.run([OVSTEST, "test-ovn", cmd], input=text, capture_output=True,
                       text=True, timeout=300)
    return p.stdout.split("\n")


passed = failed = 0


def check(name, ok):
    global passed, failed
    print(("PASS " if ok else "FAIL ") + name)
    if ok:
        passed += 1
    else:
        failed += 1


# 1) expression parser / annotation: one line per case, "input => expected".
for setup, cmd in (("expression parser", "parse-expr"),
                   ("expression annotation", "annotate-expr")):
    body, _ = at_data(setup)
    cases = []
    for l in body:
        if not l.strip() or l.startswith("#"):
            continue
        inp, sep, exp = l.partition(" => ")
        cases.append((inp, exp if sep else inp))
    out = run(cmd, "".join(c[0] + "\n" for c in cases))
    for n, (inp, exp) in enumerate(cases):
        got = out[n] if n < len(out) else None
        check("%s: %s" % (cmd, inp[:60]), got == exp)

# 2) action parsing: an unindented input line followed by indented expected
# lines. The block is m4 single-quoted, so "[[" / "]]" stand for "[" / "]";
# cases that use m4 macros (table names, lflow_table) are skipped.
body, _ = at_data("action parsing")
cases = []
cur = None
for l in body:
    if not l.strip() or l.startswith("#") or l.startswith("dnl") or l.startswith("m4_"):
        cur = None
        continue
    if l[0] in " \t":
        if cur is not None:
            cur[1].append(l)
        continue
    cur = (l, [])
    cases.append(cur)
# m4 macro names defined in ovn.at (oflow_in_table, ...) stand for table numbers.
m4names = re.findall(r"m4_define\(\[(\w+)\]", "\n".join(lines))
# Group/meter ids are allocated across the whole upstream run (state carried
# from earlier cases), so cases whose expected output names one are skipped.
macro = re.compile(r"OFTABLE_|m4_|\$\[|\]\$|meter:|group:|uses group|\b(%s)\b"
                   % "|".join(map(re.escape, m4names or ["lflow_table"])))
good = [(i, e) for i, e in cases if not macro.search(i + "".join(e))]
unq = lambda s: s.replace("[[", "[").replace("]]", "]")
good = [(unq(i), [unq(x) for x in e]) for i, e in good]
for inp, exp in good:
    out = run("parse-actions", inp + "\n")
    got = [x for x in out if x != ""]
    check("parse-actions: %s" % inp[:60], got == [inp] + exp)

print("COUNTS %d %d" % (passed, failed))
