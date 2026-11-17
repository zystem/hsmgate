#!/usr/bin/env python3
"""Builds the site of GitHub Pages into a directory: the README of the project as the first page (index.html) and the API reference (api/) next to it.

    python3 tools/site/build.py OUTDIR            (GITHUB_TOKEN in the environment makes the call below authenticated; GITHUB_SHA is printed in the footer)

The README is turned into HTML by GitHub's own markdown service (POST https://api.github.com/markdown, mode gfm), so the page reads like the README on the repository and no
program is installed. The links in the README that point to files of the repository (docs/faq.md, deploy/..., LICENSE) are made absolute (github.com/.../blob/main/...), because
those files are not on the site; the link to api/index.html becomes api/. Nothing but the standard library is used.
"""
import datetime
import html
import json
import os
import re
import shutil
import sys
import urllib.request

REPO = "zystem/hsmgate"
BRANCH = "main"
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>hsmgate: the master key on a smart card or HSM, behind a policy</title>
<meta name="description" content="{description}">
<style>
:root {{ --bg:#fff; --fg:#1f2328; --muted:#59636e; --line:#d1d9e0; --code:#f6f8fa; --link:#0969da; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0d1117; --fg:#e6edf3; --muted:#9198a1; --line:#3d444d; --code:#151b23; --link:#4493f8; }} }}
html {{ background:var(--bg); }}
body {{ margin:0; background:var(--bg); color:var(--fg); font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
header {{ border-bottom:1px solid var(--line); }}
nav, main, footer {{ max-width:60rem; margin:0 auto; padding:0 16px; }}
nav {{ display:flex; flex-wrap:wrap; gap:4px 20px; align-items:center; padding-top:12px; padding-bottom:12px; }}
nav strong {{ margin-right:auto; font-size:1.1rem; }}
a {{ color:var(--link); }}
main {{ padding-top:8px; padding-bottom:40px; }}
h1,h2,h3 {{ line-height:1.25; }}
h2 {{ border-bottom:1px solid var(--line); padding-bottom:.3em; margin-top:2rem; }}
pre {{ background:var(--code); padding:12px 16px; overflow:auto; border-radius:6px; line-height:1.4; }}
code {{ background:var(--code); padding:.15em .35em; border-radius:4px; font-size:90%; }}
pre code {{ background:none; padding:0; font-size:88%; }}
table {{ border-collapse:collapse; display:block; overflow:auto; }}
th, td {{ border:1px solid var(--line); padding:6px 12px; text-align:left; vertical-align:top; }}
img {{ max-width:100%; }}
footer {{ color:var(--muted); font-size:.85rem; padding-top:12px; padding-bottom:32px; border-top:1px solid var(--line); }}
</style>
</head>
<body>
<header><nav>
<strong>hsmgate</strong>
<a href="api/">API reference</a>
<a href="https://github.com/{repo}/blob/{branch}/docs/README.md">Documentation</a>
<a href="https://github.com/{repo}/releases">Releases</a>
<a href="https://github.com/{repo}">GitHub</a>
</nav></header>
<main>
{body}
</main>
<footer>This page is the README of the project, made by <code>tools/site/build.py</code> from <code>README.md</code> {commit}on {date}. The API reference is <a href="api/">api/</a>.</footer>
</body>
</html>
"""


def render(markdown):
    """The HTML of a markdown text, made by GitHub (mode gfm, in the context of the repository)."""
    req = urllib.request.Request(
        "https://api.github.com/markdown",
        data=json.dumps({"text": markdown, "mode": "gfm", "context": REPO}).encode(),
        headers={"Accept": "application/vnd.github+json", "Content-Type": "application/json", "User-Agent": "hsmgate-site-build"},
    )
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode()


def absolute(href):
    """A link of the README for the site: a file of the repository becomes a link to it on github.com, the API page becomes api/, the rest stays."""
    if re.match(r"^([a-z][a-z0-9+.-]*:|#|//)", href, re.I):
        return href
    path = href[2:] if href.startswith("./") else href
    if path in ("api/index.html", "api/", "api"):
        return "api/"
    kind = "tree" if path.split("#")[0].endswith("/") else "blob"
    return "https://github.com/%s/%s/%s/%s" % (REPO, kind, BRANCH, path)


def fix_links(body):
    return re.sub(r'href="([^"]*)"', lambda m: 'href="%s"' % absolute(html.unescape(m.group(1)).replace('"', "%22")), body)


def add_ids(body):
    """The service gives the headings no id, so a link such as #install-for-real would lead nowhere: the id is the heading as GitHub writes it (lower case, spaces to hyphens)."""
    def one(m):
        text = html.unescape(re.sub(r"<[^>]+>", "", m.group(3)))
        slug = re.sub(r"[^\w\- ]", "", text.lower()).strip().replace(" ", "-")
        return '<h%s%s id="%s">%s</h%s>' % (m.group(1), m.group(2), slug, m.group(3), m.group(1))
    return re.sub(r"<h([1-6])([^>]*)>(.*?)</h\1>", one, body, flags=re.S)


def first_sentence(markdown):
    for line in markdown.splitlines():
        line = line.strip()
        if line.startswith("**") and line.endswith("**"):
            return line.strip("*")
    return "hsmgate"


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out = sys.argv[1]
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
        readme = f.read()
    body = add_ids(fix_links(render(readme)))
    sha = os.environ.get("GITHUB_SHA", "")
    page = PAGE.format(
        description=html.escape(first_sentence(readme), quote=True),
        repo=REPO,
        branch=BRANCH,
        body=body,
        commit=("at commit <code>%s</code> " % sha[:7]) if sha else "",
        date=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
    )
    shutil.rmtree(out, ignore_errors=True)
    shutil.copytree(os.path.join(ROOT, "api"), os.path.join(out, "api"))
    with open(os.path.join(out, "index.html"), "w", encoding="utf-8") as f:
        f.write(page)
    print("site: %s/index.html (%d bytes) and %s/api/" % (out, len(page), out))


if __name__ == "__main__":
    main()
