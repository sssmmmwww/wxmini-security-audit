#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
endpoint_extractor.py — 微信小程序接口正则提取脚本
纯标准库实现，不需要 pip install 任何包。

用法:
    python endpoint_extractor.py <target_dir> [--inventory <file_inventory.json>]

输出:
    <target_dir>/raw_endpoints.json
"""

import json
import os
import re
import sys
import time
from collections import defaultdict

# ─────────────────── 正则模式定义 ───────────────────

# 完整 URL
RE_FULL_HTTP = re.compile(r'''https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]+''', re.IGNORECASE)
RE_FULL_WS = re.compile(r'''wss?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]+''', re.IGNORECASE)

# API 路径片段 (以 / 开头，至少两段)
RE_PATH_FRAGMENT = re.compile(
    r'''(?:['"`])(/(?:api|v[0-9]+|rest|service|gateway|app|web|admin|user|auth|open|public|internal|rpc|graphql|mock)/[a-zA-Z0-9_/.{}-]+)(?:['"`])'''
)

# 通用路径片段 - 更宽泛，匹配字符串中以/开头的多段路径
RE_GENERIC_PATH = re.compile(
    r'''(?:['"`])((?:/[a-zA-Z][a-zA-Z0-9_-]+){2,})(?:['"`])'''
)

# wx.request 调用
RE_WX_REQUEST = re.compile(r'''wx\.request\s*\(\s*\{''')
RE_WX_UPLOAD = re.compile(r'''wx\.uploadFile\s*\(\s*\{''')
RE_WX_DOWNLOAD = re.compile(r'''wx\.downloadFile\s*\(\s*\{''')
RE_WX_SOCKET = re.compile(r'''wx\.connectSocket\s*\(\s*\{''')

# url: 参数 (在 wx.request 等调用内部)
RE_URL_PARAM = re.compile(
    r'''url\s*:\s*(?:['"`]([^'"`\n]+)['"`]|`([^`]*)`|([a-zA-Z_$][a-zA-Z0-9_$.]*))'''
)

# BaseURL 配置
RE_BASEURL = re.compile(
    r'''(?:baseURL|baseUrl|BASE_URL|base_url|apiUrl|apiHost|API_URL|API_HOST|apiBase|requestUrl|serverUrl|SERVER_URL|host|HOST|domain|DOMAIN|server|SERVER)\s*[:=]\s*['"`]([^'"`\n]+)['"`]''',
    re.IGNORECASE
)

# 环境配置
RE_ENV_URL = re.compile(
    r'''(?:dev|test|prod|production|staging|uat|sit|pre|online|release)\s*[:=]\s*['"`](https?://[^'"`\n]+)['"`]''',
    re.IGNORECASE
)

# 云函数
RE_CLOUD_FUNCTION = re.compile(
    r'''wx\.cloud\.callFunction\s*\(\s*\{[^}]*name\s*:\s*['"`]([^'"`]+)['"`]''',
    re.DOTALL
)

# 云数据库集合
RE_CLOUD_COLLECTION = re.compile(
    r'''\.collection\s*\(\s*['"`]([^'"`]+)['"`]\s*\)'''
)

# 第三方 HTTP 库
RE_AXIOS = re.compile(
    r'''axios\s*\.\s*(?:get|post|put|delete|patch|request|head|options)\s*\(\s*['"`]([^'"`\n]+)['"`]'''
)
RE_FETCH = re.compile(
    r'''fetch\s*\(\s*['"`]([^'"`\n]+)['"`]'''
)
RE_JQUERY_AJAX = re.compile(
    r'''\$\s*\.\s*(?:get|post|ajax|getJSON)\s*\(\s*['"`]([^'"`\n]+)['"`]'''
)

# 路由配置对象 (key: '/path' 格式)
RE_ROUTE_CONFIG = re.compile(
    r'''(\w+)\s*:\s*['"`](/[a-zA-Z0-9_/.{}-]+)['"`]'''
)

# WebView src
RE_WEBVIEW_SRC = re.compile(
    r'''<web-view[^>]+src\s*=\s*['"]([^'"]+)['"]''',
    re.IGNORECASE
)

# 封装请求函数定义检测
RE_WRAPPER_DEF = re.compile(
    r'''(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:function|\([^)]*\)\s*=>))[^{]*\{[^}]*wx\.request''',
    re.DOTALL
)

# 封装调用 - method style: request.get('/api/...')
RE_METHOD_CALL = re.compile(
    r'''(?:request|http|service|api|ajax)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`\n]+)['"`]'''
)

# 封装调用 - function style: request('/api/...') or request({ url: '...' })
RE_FUNC_CALL = re.compile(
    r'''(?:request|http|service|api|fetchApi)\s*\(\s*(?:\{[^}]*url\s*:\s*['"`]([^'"`\n]+)['"`]|['"`]([^'"`\n]+)['"`])''',
    re.DOTALL
)

# 小程序变体
RE_UNI_REQUEST = re.compile(r'''uni\.request\s*\(\s*\{''')
RE_TT_REQUEST = re.compile(r'''tt\.request\s*\(\s*\{''')
RE_MY_REQUEST = re.compile(r'''my\.request\s*\(\s*\{''')
RE_SWAN_REQUEST = re.compile(r'''swan\.request\s*\(\s*\{''')

# 协议相对 URL
RE_PROTOCOL_RELATIVE = re.compile(
    r'''['"`](//[A-Za-z0-9.-]+(?:/[^\s'"`]*)?)['"`]'''
)

# 无前导/的接口路径
RE_NO_SLASH_API = re.compile(
    r'''['"`]((?:api|rest|service|gateway|auth|user|order|pay|v[0-9]+)/[A-Za-z0-9_./{}-]+)['"`]'''
)

# 常见业务路径
RE_BUSINESS_PATH = re.compile(
    r'''['"`](/(?:login|logout|register|user|order|pay|cart|goods|product|member|coupon|sms|captcha|auth|upload|download|config|query|list|detail)[A-Za-z0-9_./{}-]*)['"`]'''
)

# 微信跳转小程序
RE_NAV_MINIPROGRAM_APPID = re.compile(
    r'''wx\.navigateToMiniProgram\s*\(\s*\{[^}]*appId\s*:\s*['"`]([^'"`]+)['"`]''',
    re.DOTALL
)
RE_NAV_MINIPROGRAM_PATH = re.compile(
    r'''wx\.navigateToMiniProgram\s*\(\s*\{[^}]*path\s*:\s*['"`]([^'"`]+)['"`]''',
    re.DOTALL
)

# 小程序路由跳转
RE_WX_NAVIGATE = re.compile(
    r'''wx\.(?:navigateTo|redirectTo|reLaunch|switchTab)\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]''',
    re.DOTALL
)

# 云开发文件操作
RE_CLOUD_UPLOAD = re.compile(
    r'''wx\.cloud\.uploadFile\s*\(\s*\{[^}]*cloudPath\s*:\s*['"`]([^'"`]+)['"`]''',
    re.DOTALL
)
RE_CLOUD_DOWNLOAD = re.compile(
    r'''wx\.cloud\.downloadFile\s*\(\s*\{[^}]*fileID\s*:\s*['"`]([^'"`]+)['"`]''',
    re.DOTALL
)
RE_CLOUD_TEMP_FILE = re.compile(
    r'''wx\.cloud\.getTempFileURL\s*\(\s*\{[^}]*fileList\s*:\s*\[[^\]]+\]''',
    re.DOTALL
)

# GraphQL
RE_GRAPHQL_ENDPOINT = re.compile(r'''['"`]([^'"`\n]*graphql[^'"`\n]*)['"`]''', re.IGNORECASE)

# WebSocket URL 变量
RE_SOCKET_URL_VAR = re.compile(r'''(?i)socket[_-]?url\s*[:=]\s*['"`]([^'"`]+)['"`]''')

# 微信服务市场
RE_SERVICE_MARKET = re.compile(
    r'''wx\.serviceMarket\.invokeService\s*\(\s*\{[^}]*service\s*:\s*['"`]([^'"`]+)['"`]''',
    re.DOTALL
)

# 插件调用
RE_REQUIRE_PLUGIN = re.compile(r'''requirePlugin\s*\(\s*['"`]([^'"`]+)['"`]\s*\)''')

# WXML: ad 组件
RE_AD_UNIT = re.compile(r'''<ad[^>]+ad-unit-id\s*=\s*['"]([^'"]+)['"]''', re.IGNORECASE)

# WXML: contact-button
RE_CONTACT_SESSION = re.compile(
    r'''<contact-button[^>]+session-from\s*=\s*['"]([^'"]+)['"]''', re.IGNORECASE
)

# baseUrl 模板拼接
RE_TEMPLATE_URL = re.compile(
    r'''`[^`]*(?:\$\{[^}]+\}|baseUrl|apiUrl|BASE_URL|API_URL)[^`]*(?:api|v[0-9]+|rest|service)[^`]*`'''
)

# XMLHttpRequest
RE_XHR_OPEN = re.compile(
    r'''\.open\s*\(\s*['"`](?:GET|POST|PUT|DELETE|PATCH)['"`]\s*,\s*['"`]([^'"`\n]+)['"`]''',
    re.IGNORECASE
)

# globalData URL
RE_GLOBAL_DATA_URL = re.compile(r'''getApp\s*\(\s*\)\.globalData\.[a-zA-Z_]\w*(?:Url|Host|Domain|Api)''')

# window/global URL
RE_WINDOW_GLOBAL_URL = re.compile(r'''(?:window|global)\.[a-zA-Z_]\w*(?:Url|Host|Domain|Api)''')

# require API 模块
RE_REQUIRE_API = re.compile(r'''require\s*\(\s*['"`]\.\/(?:api|request|http|service)['"`]\s*\)''')

# ─────────────────── 排除规则 ───────────────────

# 排除的 URL 模式（CDN 图片、npm、微信 SDK 等）
EXCLUDE_URL_PATTERNS = [
    re.compile(r'''\.(?:png|jpg|jpeg|gif|svg|ico|webp|bmp|tiff|mp3|mp4|wav|avi|mov|ttf|woff|woff2|eot|otf|css)(?:\?|$)''', re.IGNORECASE),
    re.compile(r'''(?:npm|registry\.npmjs\.org|unpkg\.com|cdn\.jsdelivr\.net)''', re.IGNORECASE),
    re.compile(r'''(?:github\.com|stackoverflow\.com|w3\.org|mozilla\.org|google\.com/fonts)''', re.IGNORECASE),
    re.compile(r'''(?:example\.com|localhost|127\.0\.0\.1)''', re.IGNORECASE),
]

# 排除的文件/目录
EXCLUDE_DIRS = {'node_modules', '.git', '__MACOSX', '.DS_Store'}

# 支持扫描的文件扩展名
SCAN_EXTENSIONS = {'.js', '.json', '.wxml', '.html', '.ts'}

# ─────────────────── 工具函数 ───────────────────

def should_exclude_url(url):
    """判断 URL 是否应该被排除"""
    for pat in EXCLUDE_URL_PATTERNS:
        if pat.search(url):
            return True
    return False

def clean_url(url):
    """清理 URL，去除尾部的引号、括号等"""
    url = url.rstrip("',\");>}]\\")
    url = url.rstrip()
    return url

def get_context(lines, line_idx, before=1, after=1):
    """获取代码上下文"""
    start = max(0, line_idx - before)
    end = min(len(lines), line_idx + after + 1)
    ctx_lines = []
    for i in range(start, end):
        prefix = ">>> " if i == line_idx else "    "
        ctx_lines.append(f"{prefix}{i+1}: {lines[i].rstrip()}")
    return "\n".join(ctx_lines)

def is_excluded_dir(path):
    """检查路径中是否包含排除的目录"""
    parts = path.replace("\\", "/").split("/")
    return any(p in EXCLUDE_DIRS for p in parts)

def get_file_size_kb(filepath):
    """获取文件大小（KB）"""
    try:
        return os.path.getsize(filepath) / 1024
    except OSError:
        return 0

# ─────────────────── 主提取逻辑 ───────────────────

def extract_from_file(filepath, rel_path):
    """从单个文件中提取所有接口信息"""
    hits = []
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        return hits, []
    
    lines = content.split('\n')
    base_url_candidates = []
    
    # 1. 提取完整 HTTP URL
    for match in RE_FULL_HTTP.finditer(content):
        url = clean_url(match.group(0))
        if not should_exclude_url(url) and len(url) > 10:
            line_num = content[:match.start()].count('\n')
            hits.append({
                "type": "full_url",
                "value": url,
                "line": line_num + 1,
                "context": get_context(lines, line_num),
                "pattern": "full_http_url"
            })
    
    # 2. 提取 WebSocket URL
    for match in RE_FULL_WS.finditer(content):
        url = clean_url(match.group(0))
        if len(url) > 10:
            line_num = content[:match.start()].count('\n')
            hits.append({
                "type": "websocket_url",
                "value": url,
                "line": line_num + 1,
                "context": get_context(lines, line_num),
                "pattern": "websocket_url"
            })
    
    # 3. 提取 API 路径片段
    for match in RE_PATH_FRAGMENT.finditer(content):
        path = match.group(1)
        line_num = content[:match.start()].count('\n')
        hits.append({
            "type": "path_fragment",
            "value": path,
            "line": line_num + 1,
            "context": get_context(lines, line_num),
            "pattern": "api_path_fragment"
        })
    
    # 4. 提取通用路径片段（更宽泛）
    for match in RE_GENERIC_PATH.finditer(content):
        path = match.group(1)
        # 排除明显的非接口路径
        if not path.startswith('/pages/') and not path.startswith('/components/') and \
           not path.startswith('/node_modules/') and not path.startswith('/assets/'):
            line_num = content[:match.start()].count('\n')
            hits.append({
                "type": "path_fragment",
                "value": path,
                "line": line_num + 1,
                "context": get_context(lines, line_num),
                "pattern": "generic_path"
            })
    
    # 5. 提取 BaseURL 配置
    for match in RE_BASEURL.finditer(content):
        value = match.group(1)
        line_num = content[:match.start()].count('\n')
        base_url_candidates.append({
            "value": value,
            "file": rel_path,
            "line": line_num + 1,
            "context": get_context(lines, line_num)
        })
    
    # 6. 提取环境配置 URL
    for match in RE_ENV_URL.finditer(content):
        url = match.group(1)
        line_num = content[:match.start()].count('\n')
        base_url_candidates.append({
            "value": url,
            "file": rel_path,
            "line": line_num + 1,
            "context": get_context(lines, line_num),
            "env_hint": True
        })
    
    # 7. 检测 wx.request 及类似调用
    for pattern, api_name in [
        (RE_WX_REQUEST, "wx.request"),
        (RE_WX_UPLOAD, "wx.uploadFile"),
        (RE_WX_DOWNLOAD, "wx.downloadFile"),
        (RE_WX_SOCKET, "wx.connectSocket"),
        (RE_UNI_REQUEST, "uni.request"),
        (RE_TT_REQUEST, "tt.request"),
        (RE_MY_REQUEST, "my.request"),
        (RE_SWAN_REQUEST, "swan.request"),
    ]:
        for match in pattern.finditer(content):
            start_pos = match.start()
            line_num = content[:start_pos].count('\n')
            # 在调用区域内搜索 url 参数
            search_region = content[start_pos:start_pos + 500]
            url_match = RE_URL_PARAM.search(search_region)
            if url_match:
                url_value = url_match.group(1) or url_match.group(2) or url_match.group(3)
                hits.append({
                    "type": "wx_api_call",
                    "value": url_value,
                    "line": line_num + 1,
                    "context": get_context(lines, line_num, before=1, after=3),
                    "pattern": api_name
                })
    
    # 8. 提取云函数
    for match in RE_CLOUD_FUNCTION.finditer(content):
        name = match.group(1)
        line_num = content[:match.start()].count('\n')
        hits.append({
            "type": "cloud_function",
            "value": f"cloud://{name}",
            "line": line_num + 1,
            "context": get_context(lines, line_num),
            "pattern": "wx.cloud.callFunction"
        })
    
    # 9. 提取云数据库集合
    for match in RE_CLOUD_COLLECTION.finditer(content):
        name = match.group(1)
        line_num = content[:match.start()].count('\n')
        hits.append({
            "type": "cloud_collection",
            "value": f"collection://{name}",
            "line": line_num + 1,
            "context": get_context(lines, line_num),
            "pattern": "cloud.database.collection"
        })
    
    # 10. 提取第三方 HTTP 库调用
    for pattern, lib_name in [
        (RE_AXIOS, "axios"),
        (RE_FETCH, "fetch"),
        (RE_JQUERY_AJAX, "jquery_ajax")
    ]:
        for match in pattern.finditer(content):
            url = match.group(1)
            line_num = content[:match.start()].count('\n')
            hits.append({
                "type": "third_party_http",
                "value": url,
                "line": line_num + 1,
                "context": get_context(lines, line_num),
                "pattern": lib_name
            })
    
    # 11. 检测封装请求函数
    for match in RE_WRAPPER_DEF.finditer(content):
        func_name = match.group(1) or match.group(2)
        if func_name:
            line_num = content[:match.start()].count('\n')
            hits.append({
                "type": "request_wrapper_def",
                "value": func_name,
                "line": line_num + 1,
                "context": get_context(lines, line_num, before=0, after=5),
                "pattern": "wrapper_function_definition"
            })
    
    # 12. WXML: WebView src, ad组件, contact-button
    if rel_path.endswith('.wxml') or rel_path.endswith('.html'):
        for match in RE_WEBVIEW_SRC.finditer(content):
            src = match.group(1)
            line_num = content[:match.start()].count('\n')
            hits.append({
                "type": "webview_src",
                "value": src,
                "line": line_num + 1,
                "context": get_context(lines, line_num),
                "pattern": "web-view_src"
            })
        for match in RE_AD_UNIT.finditer(content):
            ad_id = match.group(1)
            line_num = content[:match.start()].count('\n')
            hits.append({
                "type": "ad_unit",
                "value": ad_id,
                "line": line_num + 1,
                "context": get_context(lines, line_num),
                "pattern": "ad_unit_id"
            })
        for match in RE_CONTACT_SESSION.finditer(content):
            session_from = match.group(1)
            line_num = content[:match.start()].count('\n')
            hits.append({
                "type": "contact_session",
                "value": session_from,
                "line": line_num + 1,
                "context": get_context(lines, line_num),
                "pattern": "contact-button_session-from"
            })
    
    # 13. 路由配置文件检测（仅在文件名含特征关键词时）
    fname_lower = os.path.basename(rel_path).lower()
    if any(kw in fname_lower for kw in ['api', 'url', 'config', 'request', 'http', 'service', 'route']):
        route_hits = list(RE_ROUTE_CONFIG.finditer(content))
        if len(route_hits) >= 3:  # 至少3条才算路由配置文件
            for match in route_hits:
                key_name = match.group(1)
                path_value = match.group(2)
                line_num = content[:match.start()].count('\n')
                hits.append({
                    "type": "route_config",
                    "value": path_value,
                    "line": line_num + 1,
                    "context": get_context(lines, line_num),
                    "pattern": f"route_config_key:{key_name}"
                })
    
    # 14. 封装调用 - method style: request.get('/api/...')
    for match in RE_METHOD_CALL.finditer(content):
        url = match.group(1)
        if url and len(url) > 1:
            line_num = content[:match.start()].count('\n')
            hits.append({
                "type": "wrapper_call",
                "value": url,
                "line": line_num + 1,
                "context": get_context(lines, line_num),
                "pattern": "method_style_call"
            })
    
    # 15. 封装调用 - function style: request('/api/...')
    for match in RE_FUNC_CALL.finditer(content):
        url = match.group(1) or match.group(2)
        if url and len(url) > 1:
            line_num = content[:match.start()].count('\n')
            hits.append({
                "type": "wrapper_call",
                "value": url,
                "line": line_num + 1,
                "context": get_context(lines, line_num),
                "pattern": "func_style_call"
            })
    
    # 16. 协议相对 URL
    for match in RE_PROTOCOL_RELATIVE.finditer(content):
        url = match.group(1)
        if not should_exclude_url(url):
            line_num = content[:match.start()].count('\n')
            hits.append({
                "type": "protocol_relative_url",
                "value": url,
                "line": line_num + 1,
                "context": get_context(lines, line_num),
                "pattern": "protocol_relative"
            })
    
    # 17. 无前导/的接口路径
    for match in RE_NO_SLASH_API.finditer(content):
        path = match.group(1)
        line_num = content[:match.start()].count('\n')
        hits.append({
            "type": "path_fragment",
            "value": path,
            "line": line_num + 1,
            "context": get_context(lines, line_num),
            "pattern": "no_slash_api_path"
        })
    
    # 18. 常见业务路径
    for match in RE_BUSINESS_PATH.finditer(content):
        path = match.group(1)
        if not path.startswith('/pages/') and not path.startswith('/components/'):
            line_num = content[:match.start()].count('\n')
            hits.append({
                "type": "business_path",
                "value": path,
                "line": line_num + 1,
                "context": get_context(lines, line_num),
                "pattern": "business_path"
            })
    
    # 19. 微信跳转小程序
    for match in RE_NAV_MINIPROGRAM_APPID.finditer(content):
        appid = match.group(1)
        line_num = content[:match.start()].count('\n')
        hits.append({
            "type": "miniprogram_jump",
            "value": appid,
            "line": line_num + 1,
            "context": get_context(lines, line_num, before=1, after=3),
            "pattern": "navigateToMiniProgram_appId"
        })
    for match in RE_NAV_MINIPROGRAM_PATH.finditer(content):
        path = match.group(1)
        line_num = content[:match.start()].count('\n')
        hits.append({
            "type": "miniprogram_jump",
            "value": path,
            "line": line_num + 1,
            "context": get_context(lines, line_num, before=1, after=3),
            "pattern": "navigateToMiniProgram_path"
        })
    
    # 20. 小程序路由跳转
    for match in RE_WX_NAVIGATE.finditer(content):
        url = match.group(1)
        line_num = content[:match.start()].count('\n')
        hits.append({
            "type": "wx_navigate",
            "value": url,
            "line": line_num + 1,
            "context": get_context(lines, line_num),
            "pattern": "wx_route_navigate"
        })
    
    # 21. 云开发文件操作
    for pat, pat_name in [
        (RE_CLOUD_UPLOAD, "wx.cloud.uploadFile"),
        (RE_CLOUD_DOWNLOAD, "wx.cloud.downloadFile"),
    ]:
        for match in pat.finditer(content):
            value = match.group(1)
            line_num = content[:match.start()].count('\n')
            hits.append({
                "type": "cloud_file_op",
                "value": value,
                "line": line_num + 1,
                "context": get_context(lines, line_num),
                "pattern": pat_name
            })
    for match in RE_CLOUD_TEMP_FILE.finditer(content):
        line_num = content[:match.start()].count('\n')
        hits.append({
            "type": "cloud_file_op",
            "value": "[getTempFileURL call]",
            "line": line_num + 1,
            "context": get_context(lines, line_num, before=0, after=3),
            "pattern": "wx.cloud.getTempFileURL"
        })
    
    # 22. GraphQL 端点检测
    for match in RE_GRAPHQL_ENDPOINT.finditer(content):
        endpoint = match.group(1)
        if len(endpoint) > 3:
            line_num = content[:match.start()].count('\n')
            hits.append({
                "type": "graphql_endpoint",
                "value": endpoint,
                "line": line_num + 1,
                "context": get_context(lines, line_num),
                "pattern": "graphql_endpoint"
            })
    
    # 23. WebSocket URL 变量
    for match in RE_SOCKET_URL_VAR.finditer(content):
        url = match.group(1)
        line_num = content[:match.start()].count('\n')
        base_url_candidates.append({
            "value": url,
            "file": rel_path,
            "line": line_num + 1,
            "context": get_context(lines, line_num)
        })
    
    # 24. 微信服务市场 & 插件调用
    for match in RE_SERVICE_MARKET.finditer(content):
        service = match.group(1)
        line_num = content[:match.start()].count('\n')
        hits.append({
            "type": "service_market",
            "value": service,
            "line": line_num + 1,
            "context": get_context(lines, line_num),
            "pattern": "wx.serviceMarket.invokeService"
        })
    for match in RE_REQUIRE_PLUGIN.finditer(content):
        plugin = match.group(1)
        line_num = content[:match.start()].count('\n')
        hits.append({
            "type": "plugin_require",
            "value": plugin,
            "line": line_num + 1,
            "context": get_context(lines, line_num),
            "pattern": "requirePlugin"
        })
    
    # 25. baseUrl 模板拼接
    for match in RE_TEMPLATE_URL.finditer(content):
        template = match.group(0)
        line_num = content[:match.start()].count('\n')
        hits.append({
            "type": "template_url",
            "value": template,
            "line": line_num + 1,
            "context": get_context(lines, line_num),
            "pattern": "template_string_url"
        })
    
    # 26. XMLHttpRequest .open()
    for match in RE_XHR_OPEN.finditer(content):
        url = match.group(1)
        line_num = content[:match.start()].count('\n')
        hits.append({
            "type": "xhr_call",
            "value": url,
            "line": line_num + 1,
            "context": get_context(lines, line_num),
            "pattern": "XMLHttpRequest_open"
        })
    
    # 27. globalData / window URL 引用
    for pat, pat_name in [
        (RE_GLOBAL_DATA_URL, "getApp_globalData"),
        (RE_WINDOW_GLOBAL_URL, "window_global_url"),
    ]:
        for match in pat.finditer(content):
            ref = match.group(0)
            line_num = content[:match.start()].count('\n')
            hits.append({
                "type": "global_url_ref",
                "value": ref,
                "line": line_num + 1,
                "context": get_context(lines, line_num),
                "pattern": pat_name
            })
    
    # 28. require API 模块
    for match in RE_REQUIRE_API.finditer(content):
        module = match.group(0)
        line_num = content[:match.start()].count('\n')
        hits.append({
            "type": "api_module_import",
            "value": module,
            "line": line_num + 1,
            "context": get_context(lines, line_num, before=0, after=2),
            "pattern": "require_api_module"
        })
    
    return hits, base_url_candidates

def collect_files(target_dir, inventory_path=None):
    """收集需要扫描的文件列表"""
    files = []
    
    # 如果有 file_inventory.json，优先使用
    if inventory_path and os.path.exists(inventory_path):
        try:
            with open(inventory_path, 'r', encoding='utf-8') as f:
                inventory = json.load(f)
            # 兼容两种格式：嵌套在 file_inventory 下，或直接在根层级
            file_inv = inventory.get('file_inventory', None)
            if file_inv is None or not isinstance(file_inv, dict):
                # 回退：尝试根层级的 *_files 字段
                file_inv = {}
                for key in inventory:
                    if key.endswith('_files') and isinstance(inventory[key], list):
                        file_inv[key] = inventory[key]
                if file_inv:
                    print(f"[!] 警告: file_inventory.json 格式不匹配预期（缺少 file_inventory 嵌套层），已兼容解析根层级字段")
            target_categories = ['js_files', 'json_files', 'wxml_files', 'other_files']
            if not file_inv:
                print(f"[!] 警告: file_inventory.json 中未找到文件列表，回退到目录遍历")
                raise ValueError("empty inventory")
            for category in target_categories:
                for rel in file_inv.get(category, []):
                    if not isinstance(rel, str):
                        continue
                    clean_rel = rel.replace('[LARGE] ', '')
                    full = os.path.join(target_dir, clean_rel)
                    if os.path.isfile(full):
                        files.append((full, clean_rel))
            if files:
                return files
            print(f"[!] 警告: file_inventory.json 解析后无有效文件，回退到目录遍历")
        except Exception as e:
            if str(e) != "empty inventory":
                print(f"[!] 警告: 解析 file_inventory.json 失败 ({e})，回退到目录遍历")
    
    # 目录遍历
    for root, dirs, filenames in os.walk(target_dir):
        # 排除目录
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in SCAN_EXTENSIONS:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, target_dir)
                if not is_excluded_dir(rel):
                    files.append((full, rel))
    
    return files

def deduplicate_hits(hits):
    """对同一文件内的 hits 去重"""
    seen = set()
    deduped = []
    for h in hits:
        key = (h['type'], h['value'], h['line'])
        if key not in seen:
            seen.add(key)
            deduped.append(h)
    return deduped

def main():
    if len(sys.argv) < 2:
        print("用法: python endpoint_extractor.py <target_dir> [--inventory <path>] [--output <dir>]")
        sys.exit(1)
    
    target_dir = sys.argv[1]
    
    # 解析 --output 参数（输出目录，默认为 target_dir）
    output_dir = target_dir
    if '--output' in sys.argv:
        idx = sys.argv.index('--output')
        if idx + 1 < len(sys.argv):
            output_dir = sys.argv[idx + 1]
    
    # 解析 --inventory 参数
    inventory_path = os.path.join(output_dir, 'file_inventory.json')
    if '--inventory' in sys.argv:
        idx = sys.argv.index('--inventory')
        if idx + 1 < len(sys.argv):
            inventory_path = sys.argv[idx + 1]
    
    if not os.path.isdir(target_dir):
        print(f"错误: 目录 {target_dir} 不存在")
        sys.exit(1)
    
    print(f"[*] 开始接口提取扫描: {target_dir}")
    start_time = time.time()
    
    # 收集文件
    files = collect_files(target_dir, inventory_path)
    print(f"[*] 共发现 {len(files)} 个文件待扫描")
    
    # 逐文件提取
    by_file = {}
    all_hits = []
    all_base_url_candidates = []
    skipped_large = []
    
    for full_path, rel_path in files:
        size_kb = get_file_size_kb(full_path)
        
        # 超大文件（>2MB）跳过，记录
        if size_kb > 2048:
            skipped_large.append({"file": rel_path, "size_kb": round(size_kb, 1), "reason": "over_2mb"})
            continue
        
        hits, base_urls = extract_from_file(full_path, rel_path)
        all_base_url_candidates.extend(base_urls)
        
        if hits:
            hits = deduplicate_hits(hits)
            by_file[rel_path] = {
                "file_size_kb": round(size_kb, 1),
                "hit_count": len(hits),
                "hits": hits
            }
            for h in hits:
                h_copy = dict(h)
                h_copy["file"] = rel_path
                all_hits.append(h_copy)
    
    # 去重 base_url_candidates
    seen_base = set()
    unique_base = []
    for bu in all_base_url_candidates:
        if bu['value'] not in seen_base:
            seen_base.add(bu['value'])
            unique_base.append(bu)
    
    # 统计各类型命中数
    type_stats = defaultdict(int)
    for h in all_hits:
        type_stats[h['type']] += 1
    
    elapsed = round(time.time() - start_time, 2)
    
    # 构建输出
    result = {
        "extraction_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "elapsed_seconds": elapsed,
        "total_files_scanned": len(files),
        "total_raw_hits": len(all_hits),
        "type_statistics": dict(type_stats),
        "base_url_candidates": unique_base,
        "skipped_large_files": skipped_large,
        "by_file": by_file,
        "all_hits": all_hits
    }
    
    # 写出
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, 'raw_endpoints.json')
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    
    print(f"[+] 扫描完成! 耗时 {elapsed}s")
    print(f"[+] 扫描文件: {len(files)}, 命中: {len(all_hits)}, BaseURL候选: {len(unique_base)}")
    print(f"[+] 类型统计: {dict(type_stats)}")
    print(f"[+] 结果已保存: {output_path}")

if __name__ == '__main__':
    main()
