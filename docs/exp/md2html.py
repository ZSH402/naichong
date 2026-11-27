#!/usr/bin/env python3
"""把 docs 下的 markdown 转成自包含 HTML（图片以 base64 内嵌）。

用法:
    python3 md2html.py <输出目录> <文件1.md> [文件2.md ...]

生成同名的 .html，外加一个 index.html。图片不依赖外部文件，
拷到任何地方双击都能看。
"""
import base64
import mimetypes
import os
import re
import sys

import markdown

TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{
  --fg: #1f2328;
  --fg-dim: #59636e;
  --bg: #ffffff;
  --line: #d1d9e0;
  --code-bg: #1b1f24;
  --code-fg: #e6edf3;
  --inline-bg: #f0f2f5;
  --accent: #1f4e79;
}}
* {{ box-sizing: border-box; }}
html {{ -webkit-text-size-adjust: 100%; }}
body {{
  margin: 0;
  padding: 0 20px 120px;
  background: var(--bg);
  color: var(--fg);
  font-family: -apple-system, "Segoe UI", "Microsoft YaHei", "PingFang SC",
               "Hiragino Sans GB", "Source Han Sans SC", sans-serif;
  font-size: 16.5px;
  line-height: 1.8;
  letter-spacing: .01em;
}}
main {{ max-width: 830px; margin: 0 auto; }}
h1, h2, h3, h4 {{ line-height: 1.4; font-weight: 650; letter-spacing: -.005em; }}
h1 {{
  font-size: 2.05em; margin: 2.4em 0 .9em; padding-bottom: .35em;
  border-bottom: 3px solid var(--fg); letter-spacing: -.02em;
}}
h2 {{
  font-size: 1.42em; margin: 2.3em 0 .8em; padding-bottom: .3em;
  border-bottom: 1px solid var(--line);
}}
h3 {{ font-size: 1.16em; margin: 1.8em 0 .6em; color: #2c333a; }}
h4 {{ font-size: 1.02em; margin: 1.4em 0 .5em; color: var(--fg-dim); }}
p {{ margin: .95em 0; }}
a {{ color: var(--accent); text-decoration: none; border-bottom: 1px solid rgba(31,78,121,.3); }}
a:hover {{ border-bottom-color: var(--accent); }}
strong {{ font-weight: 680; color: #12161a; }}
hr {{ border: 0; border-top: 1px solid var(--line); margin: 2.8em 0; }}
ul, ol {{ padding-left: 1.5em; margin: .9em 0; }}
li {{ margin: .35em 0; }}
li > ul, li > ol {{ margin: .3em 0; }}
blockquote {{
  margin: 1.2em 0; padding: .6em 1.1em; color: var(--fg-dim);
  border-left: 3px solid var(--line); background: #fafbfc;
}}
code {{
  font-family: "JetBrains Mono", "Cascadia Mono", Consolas, "SF Mono",
               "DejaVu Sans Mono", monospace;
  font-size: .875em;
  background: var(--inline-bg);
  padding: .15em .38em;
  border-radius: 4px;
  word-break: break-word;
}}
pre {{
  position: relative;
  background: var(--code-bg); color: var(--code-fg);
  padding: 16px 18px; border-radius: 8px;
  overflow-x: auto; line-height: 1.62;
  margin: 1.3em 0;
  font-size: 14px;
  box-shadow: 0 1px 3px rgba(0,0,0,.14);
}}
pre code {{ background: none; padding: 0; font-size: 1em; color: inherit; white-space: pre; }}
pre::before {{
  content: attr(data-lang);
  position: absolute; top: 6px; right: 12px;
  font-size: 11px; color: #6e7681; letter-spacing: .06em; text-transform: uppercase;
}}
table {{
  border-collapse: collapse; width: 100%; margin: 1.4em 0;
  font-size: .95em;
}}
th, td {{ border: 1px solid var(--line); padding: 9px 13px; text-align: left; vertical-align: top; }}
th {{ background: #f6f8fa; font-weight: 650; }}
tbody tr:nth-child(even) {{ background: #fcfcfd; }}
img {{
  display: block; max-width: 100%; height: auto;
  margin: 1.7em auto; border-radius: 8px;
  border: 1px solid var(--line);
  box-shadow: 0 2px 10px rgba(0,0,0,.08);
}}
em {{ color: var(--fg-dim); }}
.nav {{ max-width: 830px; margin: 0 auto; padding: 16px 0; font-size: 14px; color: var(--fg-dim); }}
.nav a {{ margin-right: 16px; }}
footer {{ max-width: 830px; margin: 60px auto 0; padding-top: 18px; border-top: 1px solid var(--line);
          color: var(--fg-dim); font-size: 13.5px; }}
@media print {{
  body {{ font-size: 11pt; }}
  pre {{ box-shadow: none; }}
  a {{ color: var(--fg); }}
}}
@media (max-width: 640px) {{
  body {{ font-size: 16px; padding: 0 14px 80px; }}
  h1 {{ font-size: 1.7em; }}
}}
</style>
</head>
<body>
<div class="nav">{nav}</div>
<main>
{body}
</main>
<footer>异构 agent · 渗透编排系统 · 本文图片与命令输出均为实际运行结果</footer>
</body>
</html>
"""

IMAGE_RE = re.compile(r'<img([^>]*?)src="([^"]+)"([^>]*?)/?>')


def embed_images(html: str, base_dir: str) -> tuple[str, int]:
    """把 <img src="img/x.png"> 换成 base64 data URI。"""
    count = 0

    def repl(m: re.Match) -> str:
        nonlocal count
        pre, src, post = m.group(1), m.group(2), m.group(3)
        if src.startswith(("data:", "http://", "https://")):
            return m.group(0)
        path = os.path.join(base_dir, src)
        if not os.path.isfile(path):
            return m.group(0)
        mime = mimetypes.guess_type(path)[0] or "image/png"
        with open(path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")
        count += 1
        return f'<img{pre}src="data:{mime};base64,{b64}"{post}/>'

    return IMAGE_RE.sub(repl, html), count


def render(md_path: str) -> tuple[str, str, int]:
    with open(md_path, encoding="utf-8") as f:
        text = f.read()
    title = text.lstrip().split("\n", 1)[0].lstrip("# ").strip()

    html = markdown.markdown(
        text,
        extensions=["tables", "fenced_code", "sane_lists", "attr_list"],
        output_format="html5",
    )
    base = os.path.dirname(os.path.abspath(md_path))
    html, n = embed_images(html, base)

    # 给 <pre> 加语言标记，用 CSS 显示在右上角
    def pre_lang(m: re.Match) -> str:
        cls = m.group(1) or ""
        lang = cls.replace("language-", "").strip()
        return f'<pre data-lang="{lang}">'

    html = re.sub(r'<pre class="([^"]*)"', pre_lang, html)
    html = html.replace("<pre>", '<pre data-lang="">')
    return title, html, n


def main() -> None:
    out_dir = sys.argv[1]
    files = sys.argv[2:]
    os.makedirs(out_dir, exist_ok=True)

    made = []
    for md_path in files:
        title, body, n_img = render(md_path)
        name = os.path.splitext(os.path.basename(md_path))[0]
        nav = '<a href="index.html">目录</a>'
        page = TEMPLATE.format(title=title, body=body, nav=nav)
        out = os.path.join(out_dir, name + ".html")
        with open(out, "w", encoding="utf-8") as f:
            f.write(page)
        kb = os.path.getsize(out) // 1024
        print(f"{out}  {kb} KB  内嵌图片 {n_img} 张  — {title}")
        made.append((name + ".html", title, kb))

    # 索引页
    items = "\n".join(
        f'<li><a href="{href}">{title}</a> <span style="color:#59636e">（{kb} KB）</span></li>'
        for href, title, kb in made
    )
    index_body = (
        "<h1>异构 agent · 三份说明</h1>\n"
        "<p>一个跑真实渗透任务的多 agent 系统。三篇各写一个方向，图片与命令输出都是实际运行结果。</p>\n"
        f"<ul>\n{items}\n</ul>\n"
        "<p>代码：<code>dsh-secops/</code>（微层，TypeScript 插件）+ <code>engine/</code>（宏层，Python / Rust / Rego）。</p>"
    )
    index = TEMPLATE.format(title="异构 agent · 三份说明", body=index_body, nav="")
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(index)
    print(f"{os.path.join(out_dir, 'index.html')}  索引页")


if __name__ == "__main__":
    main()
