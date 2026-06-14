# 这是一个示例 Python 脚本。

# 按 Shift+F10 执行或将其替换为您的代码。
# 按 双击 Shift 在所有地方搜索类、文件、工具窗口、操作和设置。


def print_hi(name):
    # 在下面的代码行中使用断点来调试脚本。
    print(f'Hi, {name}')  # 按 Ctrl+F8 切换断点。


# 按装订区域中的绿色按钮以运行脚本。
if __name__ == '__main__':
    print_hi('PyCharm')

# 访问 https://www.jetbrains.com/help/pycharm/ 获取 PyCharm 帮助
#!/usr/bin/env python3
"""
LightScan - 轻量级 Web 漏洞扫描仪
信息安全竞赛作品
用法：python lightscan.py http://目标 [选项]
"""

import requests
import re
import sys
import time
import random
import os
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from html import escape
from datetime import datetime
from collections import defaultdict

# ============================================
# 配置
# ============================================
class Config:
    TIMEOUT = 10
    MAX_CRAWL = 30
    DELAY = 0.3
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0",
    ]

# ============================================
# 终端颜色输出
# ============================================
class Console:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @staticmethod
    def info(msg):
        print(f"{Console.BLUE}[*]{Console.END} {msg}")

    @staticmethod
    def success(msg):
        print(f"{Console.GREEN}[+]{Console.END} {msg}")

    @staticmethod
    def warning(msg):
        print(f"{Console.YELLOW}[!]{Console.END} {msg}")

    @staticmethod
    def error(msg):
        print(f"{Console.RED}[-]{Console.END} {msg}")

    @staticmethod
    def vuln(severity, msg):
        colors = {"HIGH": Console.RED, "MEDIUM": Console.YELLOW, "LOW": Console.GREEN}
        c = colors.get(severity, Console.END)
        print(f"  {c}[{severity}]{Console.END} {msg}")

# ============================================
# HTTP 引擎
# ============================================
class HTTP:
    def __init__(self):
        self.sess = requests.Session()
        self.sess.headers.update({
            "User-Agent": random.choice(Config.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })

    def request(self, url, method="GET", data=None, timeout=None):
        timeout = timeout or Config.TIMEOUT
        try:
            if method == "GET":
                return self.sess.get(url, timeout=timeout)
            elif method == "POST":
                return self.sess.post(url, data=data, timeout=timeout)
            elif method == "HEAD":
                return self.sess.head(url, timeout=timeout)
        except:
            return None

# ============================================
# 爬虫模块
# ============================================
class Crawler:
    def __init__(self, http):
        self.http = http

    def crawl(self, base_url, max_pages=Config.MAX_CRAWL):
        Console.info("开始爬取目标...")
        visited = set()
        to_visit = [base_url]
        found_urls = []

        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            if not url.startswith(base_url):
                continue
            if any(url.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.ico', '.svg']):
                continue
            visited.add(url)

            try:
                resp = self.http.request(url)
                if not resp or resp.status_code != 200:
                    continue
            except:
                continue

            # 收集带参数的 URL
            if '?' in url:
                base = url.split('?')[0]
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                found_urls.append({"url": base, "params": {k: v[0] for k, v in params.items()}, "method": "GET"})

            # 提取链接
            links = re.findall(r'href=["\']([^"\']+)["\']', resp.text, re.I)
            for link in links:
                link = link.split('#')[0]
                if not link or link.startswith('javascript:'):
                    continue
                full = urljoin(url, link)
                if full not in visited and full not in to_visit:
                    to_visit.append(full)

            time.sleep(Config.DELAY)

        Console.success(f"爬取完成：发现 {len(found_urls)} 个带参数的 URL")
        return found_urls

# ============================================
# SQL 注入检测
# ============================================
class SQLiScanner:
    def __init__(self, http):
        self.http = http
        self.skip_params = ['token', 'csrf', 'timestamp', 'nonce', 'sign', 'signature']

    def build_url(self, base, params, target_param, extra):
        parts = []
        for k, v in params.items():
            if k == target_param:
                parts.append(f"{k}={v}{extra}")
            else:
                parts.append(f"{k}={v}")
        return f"{base}?{'&'.join(parts)}"

    def scan(self, url_info):
        url = url_info['url']
        method = url_info.get('method', 'GET')
        params = url_info.get('params', {})
        vulns = []

        for param in list(params.keys()):
            if any(s in param.lower() for s in self.skip_params):
                continue

            # 报错注入
            for payload in ["'", '"', "')"]:
                test_url = self.build_url(url, params, param, payload)
                resp = self.http.request(test_url)
                if resp and re.search(r"(SQL syntax|mysql_fetch|ORA-|PostgreSQL|unclosed quotation)", resp.text, re.I):
                    vulns.append({
                        "type": "SQL注入(报错)", "param": param, "payload": payload,
                        "detail": f"参数 {param} 触发数据库错误", "severity": "HIGH"
                    })
                    Console.vuln("HIGH", f"SQL注入(报错) {param}")
                    break
            else:
                # 布尔盲注
                base_resp = self.http.request(self.build_url(url, params, param, ""))
                true_resp = self.http.request(self.build_url(url, params, param, "' AND 1=1 -- "))
                false_resp = self.http.request(self.build_url(url, params, param, "' AND 1=2 -- "))
                if base_resp and true_resp and false_resp:
                    l1, l2 = len(true_resp.text), len(false_resp.text)
                    if abs(l1 - l2) > 80 and abs(len(base_resp.text) - l1) > 30:
                        vulns.append({
                            "type": "SQL注入(布尔盲注)", "param": param,
                            "payload": "' AND 1=1 -- ",
                            "detail": f"参数 {param} 真/假响应差异 {abs(l1-l2)} 字节",
                            "severity": "HIGH"
                        })
                        Console.vuln("HIGH", f"SQL注入(布尔) {param}")

        return vulns

# ============================================
# XSS 检测
# ============================================
class XSSScanner:
    def __init__(self, http):
        self.http = http
        self.payloads = [
            ("<script>alert(1)</script>", "HIGH"),
            ('"><script>alert(1)</script>', "HIGH"),
            ("< img src=x onerror=alert(1)>", "MEDIUM"),
        ]

    def build_url(self, base, params, target_param, payload):
        parts = []
        for k, v in params.items():
            parts.append(f"{k}={payload if k == target_param else v}")
        return f"{base}?{'&'.join(parts)}"

    def scan(self, url_info):
        url = url_info['url']
        method = url_info.get('method', 'GET')
        params = url_info.get('params', {})
        vulns = []

        for param in params:
            for payload, severity in self.payloads:
                test_url = self.build_url(url, params, param, payload)
                resp = self.http.request(test_url)
                if resp and payload in resp.text and f"&lt;script&gt;" not in resp.text:
                    # 简易上下文检查：是否在 <script> 或事件处理器内
                    idx = resp.text.find(payload)
                    context = resp.text[max(0, idx-50):idx+len(payload)+50]
                    if re.search(r'<script| on\w+=', context, re.I):
                        vulns.append({
                            "type": "XSS", "param": param, "payload": payload,
                            "detail": f"参数 {param} 存在反射型 XSS", "severity": severity
                        })
                        Console.vuln(severity, f"XSS {param}")
                        break
        return vulns

# ============================================
# 目录扫描
# ============================================
class DirScanner:
    def __init__(self, http):
        self.http = http
        self.common = ["admin", "login", "backup", "test", "api", ".git/HEAD", "robots.txt",
                       "wp-admin", "phpmyadmin", "config.php.bak", ".env"]

    def is_soft_404(self, response):
        if not response or response.status_code != 200:
            return False
        content = response.text[:500].lower()
        return any(kw in content for kw in ['not found', '404', '找不到', '不存在'])

    def scan(self, base_url):
        Console.info("目录扫描...")
        vulns = []
        for path in self.common:
            url = urljoin(base_url, path)
            try:
                resp = self.http.request(url, method="HEAD")
                if resp is None:
                    resp = self.http.request(url)
                if resp and resp.status_code in [200, 301, 302, 403]:
                    if self.is_soft_404(resp):
                        continue
                    severity = "MEDIUM" if any(w in path for w in ["admin", ".git", "backup"]) else "LOW"
                    vulns.append({
                        "type": "敏感路径", "url": url,
                        "detail": f"发现 {path} (状态码 {resp.status_code})", "severity": severity
                    })
                    Console.vuln(severity, f"路径 {path}")
                time.sleep(Config.DELAY)
            except:
                pass
        return vulns

# ============================================
# HTTP 头分析
# ============================================
class HeaderAnalyzer:
    def __init__(self, http):
        self.http = http

    def analyze(self, target):
        Console.info("HTTP 头分析...")
        resp = self.http.request(target)
        if not resp:
            return []
        vulns = []
        checks = {
            "Content-Security-Policy": ("缺少 CSP 头", "MEDIUM"),
            "Strict-Transport-Security": ("缺少 HSTS 头", "MEDIUM"),
            "X-Content-Type-Options": ("缺少 X-Content-Type-Options", "LOW"),
            "X-Frame-Options": ("缺少 X-Frame-Options", "LOW"),
        }
        for header, (desc, severity) in checks.items():
            if header not in resp.headers:
                vulns.append({"type": "HTTP头缺失", "detail": desc, "severity": severity})
                Console.vuln(severity, desc)

        for leak in ["Server", "X-Powered-By"]:
            if leak in resp.headers:
                vulns.append({"type": "信息泄露", "detail": f"{leak}: {resp.headers[leak]}", "severity": "INFO"})
                Console.info(f"信息泄露: {leak}={resp.headers[leak]}")
        return vulns

# ============================================
# HTML 报告生成
# ============================================
class Report:
    @staticmethod
    def generate(target, vulns):
        severity_count = defaultdict(int)
        for v in vulns:
            severity_count[v.get("severity", "INFO")] += 1

        html = f"""<!DOCTYPE html>
<html lang="zh">
<head><meta charset="UTF-8"><title>扫描报告 - {target}</title>
<style>
    body {{ font-family: Arial; background: #f5f6fa; margin: 20px; }}
    .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px; }}
    .stat {{ display: inline-block; background: white; padding: 15px; margin: 10px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
    .vuln {{ background: white; border-left: 4px solid #e74c3c; padding: 10px; margin: 8px 0; border-radius: 4px; }}
</style></head><body>
<div class="header"><h1>LightScan 漏洞扫描报告</h1><p>目标: {target}</p ><p>时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p ></div>
<div class="stats">
    <div class="stat">高危: {severity_count.get('HIGH',0)}</div>
    <div class="stat">中危: {severity_count.get('MEDIUM',0)}</div>
    <div class="stat">低危: {severity_count.get('LOW',0)}</div>
    <div class="stat">信息: {severity_count.get('INFO',0)}</div>
</div>
<h2>漏洞详情</h2>
"""
        for v in vulns:
            html += f"<div class='vuln'><strong>[{v.get('severity')}] {v.get('type')}</strong><br>{v.get('detail')}<br>"
            if v.get('payload'):
                html += f"<code>Payload: {escape(v['payload'])}</code>"
            html += "</div>"

        html += "</body></html>"
        filename = f"report_{int(time.time())}.html"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        return filename

# ============================================
# 主扫描器
# ============================================
class LightScan:
    def __init__(self, target):
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        self.target = target
        self.http = HTTP()
        self.vulns = []

    def run(self):
        start = time.time()
        Console.info(f"目标: {self.target}")

        # 爬虫
        crawler = Crawler(self.http)
        urls = crawler.crawl(self.target)

        # HTTP 头
        self.vulns.extend(HeaderAnalyzer(self.http).analyze(self.target))

        # 目录扫描
        self.vulns.extend(DirScanner(self.http).scan(self.target))

        # 注入检测
        sqli = SQLiScanner(self.http)
        xss = XSSScanner(self.http)
        Console.info("漏洞检测...")
        for i, u in enumerate(urls):
            self.vulns.extend(sqli.scan(u))
            self.vulns.extend(xss.scan(u))
            time.sleep(Config.DELAY)

        # 报告
        report = Report.generate(self.target, self.vulns)
        elapsed = time.time() - start
        Console.success(f"扫描完成！耗时 {elapsed:.1f}s，发现 {len(self.vulns)} 个漏洞")
        Console.success(f"报告已生成: {report}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python lightscan.py http://目标 [选项]")
        print("示例: python lightscan.py http://testphp.vulnweb.com/")
        sys.exit(0)

    target = sys.argv[1]
    scanner = LightScan(target)
    try:
        scanner.run()
    except KeyboardInterrupt:
        Console.warning("扫描中断")
    except Exception as e:
        Console.error(f"发生错误: {e}")