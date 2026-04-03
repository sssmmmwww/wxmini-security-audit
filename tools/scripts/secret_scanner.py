#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
secret_scanner.py — 微信小程序敏感信息正则提取脚本
纯标准库实现，不需要 pip install 任何包。

用法:
    python secret_scanner.py <target_dir> [--inventory <file_inventory.json>]

输出:
    <target_dir>/raw_secrets.json
"""

import json
import os
import re
import sys
import time
from collections import defaultdict

# ─────────────────── 扫描规则定义 ───────────────────
# 每条规则: (category, sub_type, regex_pattern, severity, need_context_keywords)
# need_context_keywords: None 表示不需要上下文, list 表示需要上下文出现这些关键词才报告

SCAN_RULES = [
    # ── 微信凭证 ──
    ("wechat", "appid", re.compile(r'wx[a-f0-9]{16}'), "Info", None),
    ("wechat", "appsecret", re.compile(r'(?i)(?:secret|appsecret)\s*[:=]\s*[\'"][a-f0-9]{32}[\'"]'), "Critical", None),
    ("wechat", "mch_id", re.compile(r'(?i)(?:mch_?id|merchant_?id)\s*[:=]\s*[\'"][0-9]{7,10}[\'"]'), "High", None),
    ("wechat", "pay_key", re.compile(r'(?i)(?:mch_?key|pay_?key|api_?key)\s*[:=]\s*[\'"][a-zA-Z0-9]{32}[\'"]'), "Critical",
     ["pay", "wechat", "wxpay", "payment", "微信支付"]),
    ("wechat", "session_key", re.compile(r'(?i)session[_-]?key\s*[:=]\s*[\'"][A-Za-z0-9_-]{8,}[\'"]'), "High", None),
    ("wechat", "openid_unionid", re.compile(r'(?i)(?:openid|unionid)\s*[:=]\s*[\'"][A-Za-z0-9_-]{8,}[\'"]'), "Medium", None),

    # ── 云服务凭证 ──
    ("cloud_key", "aws_ak", re.compile(r'AKIA[0-9A-Z]{16}'), "Critical", None),
    ("cloud_key", "aliyun_ak", re.compile(r'LTAI[0-9a-zA-Z]{12,20}'), "Critical", None),
    ("cloud_key", "tencent_ak", re.compile(r'AKID[0-9a-zA-Z]{13,20}'), "Critical", None),
    ("cloud_key", "huawei_ak", re.compile(r'[A-Z0-9]{20}'), "Critical",
     ["huaweicloud", "hwc", "HuaweiCloud", "华为云"]),
    ("cloud_key", "baidu_ak", re.compile(r'[a-f0-9]{32}'), "Critical",
     ["bce", "baidu", "百度云"]),
    ("cloud_key", "qiniu_ak", re.compile(r'[a-zA-Z0-9_-]{40}'), "Critical",
     ["qiniu", "七牛"]),
    ("cloud_key", "volcengine_ak", re.compile(r'AKLT[a-zA-Z0-9]{16,}'), "Critical", None),
    ("cloud_key", "generic_apikey", re.compile(r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*[\'"][^\'"]{8,}[\'"]'), "High", None),
    ("cloud_key", "generic_secret", re.compile(r'(?i)(?:secret[_-]?key|secretkey)\s*[:=]\s*[\'"][^\'"]{8,}[\'"]'), "Critical", None),
    ("cloud_key", "aws_secret_key", re.compile(r'(?i)(?:aws[_-]?secret|secretaccesskey)\s*[:=]\s*[\'"][A-Za-z0-9/+=]{40}[\'"]'), "Critical", None),
    ("cloud_key", "aliyun_ak_secret", re.compile(r'(?i)(?:accesskeysecret|access[_-]?key[_-]?secret)\s*[:=]\s*[\'"][A-Za-z0-9]{30,}[\'"]'), "Critical", None),
    ("cloud_key", "tencent_secret", re.compile(r'(?i)(?:secretid|secretkey)\s*[:=]\s*[\'"][A-Za-z0-9]{16,}[\'"]'), "Critical", None),
    ("cloud_key", "gcp_firebase_key", re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "Critical", None),
    ("cloud_key", "firebase_server_key", re.compile(r'AAAA[A-Za-z0-9_-]{7,}:[A-Za-z0-9_-]{140,}'), "Critical", None),
    ("cloud_key", "azure_storage_conn", re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+'), "Critical", None),
    ("cloud_key", "azure_sas_token", re.compile(r'sv=[^&\s]+&ss=[^&\s]+&srt=[^&\s]+&sp=[^&\s]+&se=[^&\s]+&sig=[^\s\'"]+'), "Critical", None),
    ("cloud_key", "huawei_sk", re.compile(r'(?i)(?:huawei[_-]?sk|huawei[_-]?secret[_-]?key)\s*[:=]\s*[\'"][A-Za-z0-9/+_=.-]{16,}[\'"]'), "Critical",
     ["huaweicloud", "hwc", "HuaweiCloud", "华为云"]),
    ("cloud_key", "cloudflare_token", re.compile(r'[a-f0-9]{40}'), "High",
     ["cloudflare", "Cloudflare", "CF_"]),
    ("cloud_key", "digitalocean_token", re.compile(r'dop_v1_[a-f0-9]{64}'), "Critical", None),
    ("cloud_key", "heroku_key", re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'), "High",
     ["heroku", "Heroku", "HEROKU"]),
    ("cloud_key", "oracle_cloud_ocid", re.compile(r'(?i)ocid1\.[a-z]+\.[a-z0-9]+\.\.[a-z0-9]+'), "High", None),

    # ── 第三方服务凭证 ──
    ("third_party", "github_token", re.compile(r'ghp_[a-zA-Z0-9]{36}'), "Critical", None),
    ("third_party", "github_token_2", re.compile(r'gho_[a-zA-Z0-9]{36}'), "Critical", None),
    ("third_party", "github_pat", re.compile(r'github_pat_[a-zA-Z0-9_]{22,}'), "Critical", None),
    ("third_party", "gitlab_token", re.compile(r'glpat-[a-zA-Z0-9_\-]{20,}'), "Critical", None),
    ("third_party", "slack_token", re.compile(r'xox[baprs]-[a-zA-Z0-9-]+'), "Critical", None),
    ("third_party", "dingtalk_webhook", re.compile(r'https://oapi\.dingtalk\.com/robot/send\?access_token=[a-f0-9]{64}'), "High", None),
    ("third_party", "feishu_webhook", re.compile(r'https://open\.feishu\.cn/open-apis/bot/v2/hook/[a-f0-9-]{36}'), "High", None),
    ("third_party", "wecom_webhook", re.compile(r'https://qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[a-f0-9-]{36}'), "High", None),
    ("third_party", "sendgrid_key", re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'), "Critical", None),
    ("third_party", "stripe_key", re.compile(r'sk_live_[a-zA-Z0-9]{24,}'), "Critical", None),
    ("third_party", "stripe_pk", re.compile(r'pk_live_[a-zA-Z0-9]{24,}'), "Critical", None),
    ("third_party", "oauth_secret", re.compile(r'(?i)(?:client[_-]?secret)\s*[:=]\s*[\'"][^\'"]{10,}[\'"]'), "High", None),
    ("third_party", "stripe_test_key", re.compile(r'(?:sk|pk)_test_[A-Za-z0-9]{16,}'), "High", None),
    ("third_party", "sentry_dsn", re.compile(r'https://[A-Za-z0-9]+@[A-Za-z0-9.-]+/\d+'), "High", None),
    ("third_party", "twilio_sid", re.compile(r'AC[a-f0-9]{32}'), "Critical", None),
    ("third_party", "telegram_bot_token", re.compile(r'\b\d{8,10}:[A-Za-z0-9_-]{35}\b'), "Critical", None),
    ("third_party", "npm_token", re.compile(r'npm_[a-zA-Z0-9]{36}'), "Critical", None),
    ("third_party", "docker_hub_token", re.compile(r'dckr_pat_[a-zA-Z0-9]{24}'), "Critical", None),
    ("third_party", "netlify_token", re.compile(r'netlify_[a-zA-Z0-9]{40}'), "Critical", None),
    ("third_party", "vercel_token", re.compile(r'(?i)(?:vercel[_-]?token|VERCEL_TOKEN)\s*[:=]\s*[\'"][a-zA-Z0-9]{24,}[\'"]'), "High",
     ["vercel", "Vercel", "VERCEL"]),

    # ── 国内服务凭证 ──
    ("china_service", "wecom_corpid", re.compile(r'ww[a-f0-9]{16}'), "Medium", None),
    ("china_service", "wecom_corpsecret", re.compile(r'(?i)corp[_-]?secret\s*[:=]\s*[\'"][a-f0-9]{32}[\'"]'), "High", None),
    ("china_service", "dingtalk_corpid", re.compile(r'ding[a-f0-9]{16}'), "Medium", None),
    ("china_service", "dingtalk_app_credential", re.compile(r'(?i)ding[_-]?(?:app[_-]?key|app[_-]?secret)\s*[:=]\s*[\'"][a-zA-Z0-9]{16,}[\'"]'), "High", None),
    ("china_service", "feishu_appid", re.compile(r'cli_[a-f0-9]{16}'), "Medium", None),
    ("china_service", "feishu_appsecret", re.compile(r'(?i)feishu[_-]?app[_-]?secret\s*[:=]\s*[\'"][a-zA-Z0-9]{16,}[\'"]'), "High", None),
    ("china_service", "alipay_appid", re.compile(r'2088[0-9]{12}'), "Medium",
     ["alipay", "支付宝", "Alipay", "antfin"]),
    ("china_service", "amap_key", re.compile(r'(?i)amap[_-]?key\s*[:=]\s*[\'"][a-f0-9]{32}[\'"]'), "Medium", None),
    ("china_service", "tencent_map_key", re.compile(r'(?i)(?:tencent[_-]?map|qq[_-]?map)[_-]?key\s*[:=]\s*[\'"][a-zA-Z0-9]{16,}[\'"]'), "Medium", None),
    ("china_service", "baidu_map_key", re.compile(r'(?i)baidu[_-]?map[_-]?key\s*[:=]\s*[\'"][a-f0-9]{32}[\'"]'), "Medium", None),

    # ── 数据库与中间件 ──
    ("database", "mysql_conn", re.compile(r'mysql://[^\s\'"]+'), "Critical", None),
    ("database", "mongodb_conn", re.compile(r'mongodb(?:\+srv)?://[^\s\'"]+'), "Critical", None),
    ("database", "redis_conn", re.compile(r'redis://[^\s\'"]+'), "Critical", None),
    ("database", "postgres_conn", re.compile(r'postgres(?:ql)?://[^\s\'"]+'), "Critical", None),
    ("database", "jdbc_conn", re.compile(r'jdbc:[a-z]+://[^\s\'"]+'), "Critical", None),
    ("database", "ftp_conn", re.compile(r'ftp://[^\s\'"]+'), "High", None),
    ("database", "smtp_config", re.compile(r'(?i)(?:smtp[_.]?(?:host|server|addr))\s*[:=]\s*[\'"][^\'"]+[\'"]'), "Medium", None),
    ("database", "ldap_conn", re.compile(r'ldaps?://[^\s\'"]+'), "High", None),
    ("database", "rabbitmq_conn", re.compile(r'amqps?://[^\s\'"]+'), "High", None),
    ("database", "db_config_fields", re.compile(r'(?i)(?:db[_-]?host|db[_-]?user|db[_-]?pass|mysql[_-]?host|mysql[_-]?user|mysql[_-]?password|redis[_-]?host|redis[_-]?password|mongo[_-]?host|mongo[_-]?password)\s*[:=]\s*[\'"][^\'"]+[\'"]'), "High", None),

    # ── Token与密钥 ──
    ("token", "jwt_token", re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+'), "High", None),
    ("token", "private_key", re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), "Critical", None),
    ("token", "openssh_key", re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'), "Critical", None),
    ("token", "hardcoded_password", re.compile(r'(?i)(?:password|passwd|pwd)\s*[:=]\s*[\'"][^\'"]{3,}[\'"]'), "High", None),
    ("token", "bearer_token", re.compile(r'(?i)(?:authorization|token|access[_-]?token|refresh[_-]?token|id[_-]?token)\s*[:=]\s*[\'"](?:Bearer\s+)?[A-Za-z0-9._-]{16,}[\'"]'), "High", None),
    ("token", "generic_app_credential", re.compile(r'(?i)(?:app[_-]?key|app[_-]?secret|access[_-]?token)\s*[:=]\s*[\'"][^\'"]{8,}[\'"]'), "High", None),
    ("token", "session_cookie_id", re.compile(r'(?i)(?:JSESSIONID|PHPSESSID|sessionid|session[_-]?id|remember[_-]?token)\s*[:=]\s*[\'"][A-Za-z0-9._-]{8,}[\'"]'), "High", None),
    ("token", "jwk_structure", re.compile(r'"kty"\s*:\s*"(?:RSA|EC|oct)"'), "High", None),
    ("token", "certificate", re.compile(r'-----BEGIN CERTIFICATE-----'), "Medium", None),
    ("token", "public_key", re.compile(r'-----BEGIN PUBLIC KEY-----'), "Medium", None),

    # ── 内网与基础设施 ──
    ("infra", "internal_ip_10", re.compile(r'(?<![0-9.])10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![0-9.])'), "High", None),
    ("infra", "internal_ip_172", re.compile(r'(?<![0-9.])172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}(?![0-9.])'), "High", None),
    ("infra", "internal_ip_192", re.compile(r'(?<![0-9.])192\.168\.\d{1,3}\.\d{1,3}(?![0-9.])'), "High", None),
    ("infra", "ip_with_port", re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}'), "Medium", None),
    ("infra", "oss_bucket", re.compile(r'[a-z0-9.-]+\.(?:oss|s3)[a-z0-9.-]*\.(?:com|amazonaws\.com)'), "Medium", None),
    ("infra", "elasticsearch", re.compile(r'https?://[^/]*:9200'), "High", None),
    ("infra", "kibana", re.compile(r'https?://[^/]*:5601'), "Medium", None),
    ("infra", "nacos", re.compile(r'https?://[^/]*/nacos'), "High", None),
    ("infra", "actuator", re.compile(r'/actuator(?:/[a-z]+)?'), "Medium", None),
    ("infra", "internal_domain", re.compile(r'\b[a-zA-Z0-9.-]+\.(?:local|lan|internal|corp|intranet)\b'), "High", None),
    ("infra", "k8s_service", re.compile(r'\b[a-z0-9-]+\.(?:svc\.cluster\.local|svc)\b'), "High", None),

    # ── 个人敏感信息 ──
    ("pii", "phone_number", re.compile(r'[\'"]1[3-9]\d{9}[\'"]'), "Medium", None),
    ("pii", "email", re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'), "Low", None),
    ("pii", "id_card", re.compile(r'[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]'), "High", None),
    ("pii", "bank_card", re.compile(r'[3-6]\d{15,18}'), "High",
     ["bank", "card", "pay", "银行", "卡号", "bankCard"]),
    ("pii", "social_credit_code", re.compile(r'[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}'), "Medium", None),

    # ── 域名与URL ──
    ("url", "test_env_url", re.compile(r'https?://[^\s\'"]*(?:test|dev|staging|pre|uat|sit)\.[^\s\'"]+'), "Medium", None),

    # ── 调试标记 ──
    ("debug", "debug_mode", re.compile(r'(?i)(?:debug\s*[:=]\s*true|isDebug\s*[:=]\s*true|debugMode\s*[:=]\s*[1"\'])'), "Medium", None),
    ("debug", "todo_security", re.compile(r'(?i)(?:TODO|FIXME|HACK|XXX).*?(?:安全|密码|加密|认证|权限|漏洞|security|password|auth|vuln)'), "Low", None),
]

# ── 证书/密钥文件直接标记 ──
CERT_EXTENSIONS = {
    '.pem': ('cert_file', 'pem_file', 'Critical'),
    '.key': ('cert_file', 'key_file', 'Critical'),
    '.crt': ('cert_file', 'crt_file', 'High'),
    '.cer': ('cert_file', 'cer_file', 'High'),
    '.pfx': ('cert_file', 'pfx_file', 'Critical'),
    '.p12': ('cert_file', 'p12_file', 'Critical'),
    '.jks': ('cert_file', 'jks_file', 'Critical'),
    '.env': ('config_file', 'env_file', 'High'),
}

# ─────────────────── 占位符/测试值过滤 ───────────────────

PLACEHOLDER_PATTERNS = [
    re.compile(r'^x{3,}$', re.IGNORECASE),
    re.compile(r'^test', re.IGNORECASE),
    re.compile(r'^demo', re.IGNORECASE),
    re.compile(r'^sample', re.IGNORECASE),
    re.compile(r'^example', re.IGNORECASE),
    re.compile(r'^placeholder', re.IGNORECASE),
    re.compile(r'^your[_-]', re.IGNORECASE),
    re.compile(r'CHANGE_ME', re.IGNORECASE),
    re.compile(r'^fake', re.IGNORECASE),
    re.compile(r'^dummy', re.IGNORECASE),
]

KNOWN_TEST_VALUES = {
    '13800138000', '13800000000', '18888888888',
    'test@test.com', 'test@example.com', 'admin@admin.com',
    '000000000000000000', '111111111111111111',
}

# 微信官方示例 AppID
KNOWN_EXAMPLE_APPIDS = {
    'wx7c8d593b2c3a7703', 'wxd930ea5d5a258f4f', 'wx8888888888888888',
    'touristappid',
}

EXCLUDE_DIRS = {'node_modules', '.git', '__MACOSX'}

# 支持扫描的文件扩展名
SCAN_EXTENSIONS = {
    '.js', '.json', '.wxml', '.wxss', '.html', '.htm',
    '.txt', '.md', '.log', '.env', '.cfg', '.ini',
    '.yaml', '.yml', '.toml', '.xml', '.properties',
    '.ts', '.tsx', '.jsx',
}

# ─────────────────── 工具函数 ───────────────────

def is_placeholder(value):
    """检查是否是占位符/测试值"""
    clean = value.strip("'\"` ")
    if clean in KNOWN_TEST_VALUES:
        return True
    if clean in KNOWN_EXAMPLE_APPIDS:
        return True
    for pat in PLACEHOLDER_PATTERNS:
        if pat.search(clean):
            return True
    return False

def get_context(lines, line_idx, before=1, after=1):
    """获取代码上下文"""
    start = max(0, line_idx - before)
    end = min(len(lines), line_idx + after + 1)
    ctx_lines = []
    for i in range(start, end):
        prefix = ">>> " if i == line_idx else "    "
        ctx_lines.append(f"{prefix}{i+1}: {lines[i].rstrip()}")
    return "\n".join(ctx_lines)

def check_context_keywords(content, match_pos, keywords, window=200):
    """检查匹配位置附近是否有上下文关键词"""
    start = max(0, match_pos - window)
    end = min(len(content), match_pos + window)
    region = content[start:end].lower()
    return any(kw.lower() in region for kw in keywords)

def is_excluded_dir(path):
    """检查路径是否包含排除目录"""
    parts = path.replace("\\", "/").split("/")
    return any(p in EXCLUDE_DIRS for p in parts)

def get_file_size_kb(filepath):
    """获取文件大小（KB）"""
    try:
        return os.path.getsize(filepath) / 1024
    except OSError:
        return 0

def is_in_comment(line, match_pos_in_line):
    """简单判断匹配是否在注释中"""
    stripped = line.lstrip()
    if stripped.startswith('//'):
        return True
    if stripped.startswith('*') or stripped.startswith('/*'):
        return True
    # 检查匹配前是否有 //
    before = line[:match_pos_in_line]
    if '//' in before:
        return True
    return False

# ─────────────────── 主扫描逻辑 ───────────────────

def scan_file(filepath, rel_path):
    """扫描单个文件"""
    hits = []
    size_kb = get_file_size_kb(filepath)
    
    # 检查是否是证书/密钥文件
    ext = os.path.splitext(filepath)[1].lower()
    if ext in CERT_EXTENSIONS:
        cat, sub, sev = CERT_EXTENSIONS[ext]
        hits.append({
            "category": cat,
            "sub_type": sub,
            "value": f"[文件] {rel_path}",
            "line": 0,
            "context": f"发现 {ext} 格式文件",
            "severity": sev,
            "pattern": f"file_extension:{ext}",
            "is_placeholder": False
        })
    
    # 读取文件内容
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        return hits
    
    if not content.strip():
        return hits
    
    lines = content.split('\n')
    
    # 确定扫描规则子集（大文件只扫高危）
    if size_kb > 1024:
        rules = [r for r in SCAN_RULES if r[3] in ("Critical", "High")]
    elif size_kb > 500:
        rules = [r for r in SCAN_RULES if r[3] in ("Critical", "High", "Medium")]
    else:
        rules = SCAN_RULES
    
    # 逐条规则匹配
    for category, sub_type, pattern, severity, context_keywords in rules:
        matches = list(pattern.finditer(content))
        
        # 限制单条规则最大匹配数
        if len(matches) > 100:
            matches = matches[:100]
        
        for match in matches:
            value = match.group(0)
            match_pos = match.start()
            line_num = content[:match_pos].count('\n')
            line_content = lines[line_num] if line_num < len(lines) else ""
            
            # 计算匹配在行内的位置
            line_start = content.rfind('\n', 0, match_pos) + 1
            pos_in_line = match_pos - line_start
            
            # 过滤注释中的示例值
            if is_in_comment(line_content, pos_in_line):
                # 注释中的匹配降低置信度但仍记录
                pass
            
            # 检查上下文关键词要求
            if context_keywords is not None:
                if not check_context_keywords(content, match_pos, context_keywords):
                    continue  # 上下文不匹配，跳过
            
            # 占位符检测
            placeholder = is_placeholder(value)
            
            hits.append({
                "category": category,
                "sub_type": sub_type,
                "value": value,
                "line": line_num + 1,
                "context": get_context(lines, line_num),
                "severity": severity,
                "pattern": pattern.pattern[:80],
                "is_placeholder": placeholder
            })
    
    return hits

def collect_files(target_dir, inventory_path=None):
    """收集需要扫描的文件列表"""
    files = []
    
    # 如果有 file_inventory.json，从中获取文件列表
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
            if not file_inv:
                print(f"[!] 警告: file_inventory.json 中未找到文件列表，回退到目录遍历")
                raise ValueError("empty inventory")
            for category in file_inv:
                for rel in file_inv[category]:
                    if not isinstance(rel, str):
                        continue
                    clean_rel = rel.replace('[LARGE] ', '')
                    full = os.path.join(target_dir, clean_rel)
                    if os.path.isfile(full):
                        ext = os.path.splitext(clean_rel)[1].lower()
                        if ext in SCAN_EXTENSIONS or ext in CERT_EXTENSIONS:
                            files.append((full, clean_rel))
            if files:
                return files
            print(f"[!] 警告: file_inventory.json 解析后无有效文件，回退到目录遍历")
        except Exception as e:
            if str(e) != "empty inventory":
                print(f"[!] 警告: 解析 file_inventory.json 失败 ({e})，回退到目录遍历")
    
    # 回退: 目录遍历
    for root, dirs, filenames in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in SCAN_EXTENSIONS or ext in CERT_EXTENSIONS:
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
        key = (h['category'], h['sub_type'], h['value'], h['line'])
        if key not in seen:
            seen.add(key)
            deduped.append(h)
    return deduped

def main():
    if len(sys.argv) < 2:
        print("用法: python secret_scanner.py <target_dir> [--inventory <path>] [--output <dir>]")
        sys.exit(1)
    
    target_dir = sys.argv[1]
    
    # 解析 --output 参数（输出目录，默认为 target_dir）
    output_dir = target_dir
    if '--output' in sys.argv:
        idx = sys.argv.index('--output')
        if idx + 1 < len(sys.argv):
            output_dir = sys.argv[idx + 1]
    
    inventory_path = os.path.join(output_dir, 'file_inventory.json')
    if '--inventory' in sys.argv:
        idx = sys.argv.index('--inventory')
        if idx + 1 < len(sys.argv):
            inventory_path = sys.argv[idx + 1]
    
    if not os.path.isdir(target_dir):
        print(f"错误: 目录 {target_dir} 不存在")
        sys.exit(1)
    
    print(f"[*] 开始敏感信息扫描: {target_dir}")
    start_time = time.time()
    
    files = collect_files(target_dir, inventory_path)
    print(f"[*] 共发现 {len(files)} 个文件待扫描")
    
    by_file = {}
    all_hits = []
    severity_stats = defaultdict(int)
    category_stats = defaultdict(int)
    
    for full_path, rel_path in files:
        hits = scan_file(full_path, rel_path)
        
        if hits:
            hits = deduplicate_hits(hits)
            by_file[rel_path] = {
                "file_size_kb": round(get_file_size_kb(full_path), 1),
                "hit_count": len(hits),
                "hits": hits
            }
            for h in hits:
                h_copy = dict(h)
                h_copy["file"] = rel_path
                all_hits.append(h_copy)
                severity_stats[h['severity']] += 1
                category_stats[h['category']] += 1
    
    # 过滤掉确定是占位符的（但仍保留在 raw 输出中，加 is_placeholder 标记）
    non_placeholder_count = sum(1 for h in all_hits if not h.get('is_placeholder', False))
    
    elapsed = round(time.time() - start_time, 2)
    
    result = {
        "extraction_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "elapsed_seconds": elapsed,
        "total_files_scanned": len(files),
        "total_raw_hits": len(all_hits),
        "non_placeholder_hits": non_placeholder_count,
        "severity_statistics": dict(severity_stats),
        "category_statistics": dict(category_stats),
        "scan_rules_count": len(SCAN_RULES),
        "by_file": by_file,
        "all_hits": all_hits
    }
    
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, 'raw_secrets.json')
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    
    print(f"[+] 扫描完成! 耗时 {elapsed}s")
    print(f"[+] 扫描文件: {len(files)}, 总命中: {len(all_hits)}, 非占位符: {non_placeholder_count}")
    print(f"[+] 严重级别: {dict(severity_stats)}")
    print(f"[+] 分类统计: {dict(category_stats)}")
    print(f"[+] 结果已保存: {output_path}")

if __name__ == '__main__':
    main()
