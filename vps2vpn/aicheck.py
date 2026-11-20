"""Can this server's address use Claude, ChatGPT and Gemini, and what kind of address is it?

The checks run from the server itself, so they see what a browser behind the VPN sees. They are a guide,
not a promise: these services also look at payment details, the account and how it is used.
"""
import json
import os
import threading
import time
import urllib.error
import urllib.request

from . import paths

FILE = os.path.join(paths.VAR, 'aicheck.json')
UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
      'Chrome/130.0 Safari/537.36')
# Countries and regions where these services offer no accounts (their published lists, kept short on purpose:
# only places all of them exclude). Used together with the live answers.
UNSUPPORTED = {'CN', 'HK', 'MO', 'RU', 'BY', 'IR', 'KP', 'SY', 'CU'}
SITES = ('claude', 'claude_api', 'chatgpt', 'gemini')
LABEL = {'claude': 'Claude', 'claude_api': 'Claude API', 'chatgpt': 'ChatGPT', 'gemini': 'Gemini'}
MARK = {'ok': '✓', 'blocked': '✗', 'unreachable': '✗', 'unknown': '?'}


def _req(url, method='GET', data=None, headers=None, timeout=12):
    """(status, headers, body, final url). Status 0 means the site could not be reached at all."""
    h = {'User-Agent': UA, 'Accept-Language': 'en-US,en;q=0.9'}
    h.update(headers or {})
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read(65536), resp.geturl()
    except urllib.error.HTTPError as e:
        try:
            body = e.read(65536)
        except OSError:
            body = b''
        return e.code, e.headers, body, e.geturl() or url
    except Exception as e:          # DNS, TLS, timeout...
        return 0, {}, str(e).encode()[:300], url


def trace(host):
    """Cloudflare's trace page: which country the site sees us in."""
    st, _, body, _ = _req('https://%s/cdn-cgi/trace' % host, timeout=8)
    if st != 200:
        return {}
    return dict(line.split('=', 1) for line in body.decode('utf-8', 'replace').splitlines() if '=' in line)


def _hdr(h, name):
    try:
        return (h.get(name) or '').lower()
    except AttributeError:
        return ''


def check_claude(cc):
    st, h, body, final = _req('https://claude.ai/')
    if 'unavailable-in-region' in final or b'unavailable-in-region' in body[:4096]:
        return {'status': 'blocked', 'note': 'Claude 说这个地区用不了'}
    if cc in UNSUPPORTED:
        return {'status': 'blocked', 'note': '这个地区 Claude 不提供服务'}
    if st == 200:
        return {'status': 'ok', 'note': ''}
    if st == 403 and _hdr(h, 'cf-mitigated') == 'challenge':
        # Data-centre addresses get a human check first; a real browser normally passes it by itself.
        return {'status': 'ok', 'note': '网页会先做一次人机验证（机房 IP 常见，浏览器里一般自动通过）'}
    if st == 0:
        return {'status': 'unreachable', 'note': '连不上 claude.ai'}
    return {'status': 'unknown', 'note': '网页返回 %d' % st}


def check_claude_api():
    st, _, body, _ = _req('https://api.anthropic.com/v1/messages', 'POST', b'{}',
                          {'content-type': 'application/json', 'anthropic-version': '2023-06-01'})
    text = body.decode('utf-8', 'replace').lower()
    if st == 401 and 'authentication_error' in text:
        return {'status': 'ok', 'note': ''}            # reachable and allowed: only the (missing) key is refused
    if st == 403 and ('not allowed' in text or 'forbidden' in text or 'region' in text):
        return {'status': 'blocked', 'note': 'API 拒绝了这个地区'}
    if st == 0:
        return {'status': 'unreachable', 'note': '连不上 api.anthropic.com'}
    return {'status': 'unknown', 'note': 'API 返回 %d' % st}


def check_chatgpt(cc):
    st, _, body, _ = _req('https://api.openai.com/compliance/cookie_requirements',
                          headers={'authorization': 'Bearer null'})
    if b'unsupported_country' in body:
        return {'status': 'blocked', 'note': 'ChatGPT 说这个地区用不了'}
    if cc in UNSUPPORTED:
        return {'status': 'blocked', 'note': '这个地区 ChatGPT 不提供服务'}
    if st == 200:
        return {'status': 'ok', 'note': ''}
    if st == 0:
        return {'status': 'unreachable', 'note': '连不上 OpenAI'}
    return {'status': 'unknown', 'note': 'OpenAI 返回 %d' % st}


def check_gemini(cc):
    st, _, _, _ = _req('https://gemini.google.com/')
    if st == 0:
        return {'status': 'unreachable', 'note': '连不上 gemini.google.com'}
    if cc in UNSUPPORTED:
        return {'status': 'blocked', 'note': '这个地区 Gemini 不提供服务'}
    if st == 200:
        return {'status': 'ok', 'note': '按地区判断'}
    return {'status': 'unknown', 'note': 'Gemini 返回 %d' % st}


def ip_info():
    """Country, city, network owner and whether it is a data-centre address."""
    info = {}
    st, _, body, _ = _req('https://ipinfo.io/json', timeout=8)
    if st == 200:
        try:
            j = json.loads(body)
            info.update(country=j.get('country', ''), city=j.get('city', ''), region=j.get('region', ''),
                        org=j.get('org', ''), timezone=j.get('timezone', ''))
        except ValueError:
            pass
    # ip-api.com's free tier is plain http; it only learns the server's own address.
    st, _, body, _ = _req('http://ip-api.com/json/?fields=status,countryCode,isp,hosting,proxy,mobile', timeout=8)
    if st == 200:
        try:
            j = json.loads(body)
            if j.get('status') == 'success':
                info.setdefault('country', j.get('countryCode', ''))
                info.update(isp=j.get('isp', ''), hosting=bool(j.get('hosting')), proxy=bool(j.get('proxy')),
                            mobile=bool(j.get('mobile')))
        except ValueError:
            pass
    if 'hosting' in info:
        info['kind'] = ('mobile' if info.get('mobile') else 'hosting' if info.get('hosting') else 'residential')
    return info


KIND_TEXT = {'hosting': '机房 IP（数据中心）', 'residential': '家庭宽带 IP', 'mobile': '手机网络 IP'}

# Readable server names for the usual VPS locations ("悉尼 Hysteria2" reads better than "vps2vpn Hysteria2").
CITY_ZH = {'Tokyo': '东京', 'Osaka': '大阪', 'Seoul': '首尔', 'Chuncheon': '春川', 'Singapore': '新加坡',
           'Hong Kong': '香港', 'Taipei': '台北', 'Sydney': '悉尼', 'Melbourne': '墨尔本', 'Mumbai': '孟买',
           'Los Angeles': '洛杉矶', 'San Jose': '圣何塞', 'Santa Clara': '圣克拉拉', 'Fremont': '弗里蒙特',
           'Seattle': '西雅图', 'Portland': '波特兰', 'Boardman': '俄勒冈', 'Phoenix': '凤凰城', 'Dallas': '达拉斯',
           'Chicago': '芝加哥', 'Ashburn': '弗吉尼亚', 'New York City': '纽约', 'New York': '纽约', 'Columbus': '俄亥俄',
           'Miami': '迈阿密', 'Atlanta': '亚特兰大', 'Toronto': '多伦多', 'Montréal': '蒙特利尔', 'London': '伦敦',
           'Frankfurt am Main': '法兰克福', 'Frankfurt': '法兰克福', 'Amsterdam': '阿姆斯特丹', 'Paris': '巴黎',
           'Stockholm': '斯德哥尔摩', 'Dublin': '都柏林', 'Milan': '米兰', 'Madrid': '马德里', 'Zurich': '苏黎世',
           'Warsaw': '华沙', 'São Paulo': '圣保罗', 'Jakarta': '雅加达', 'Bangkok': '曼谷', 'Kuala Lumpur': '吉隆坡',
           'Dubai': '迪拜', 'Tel Aviv': '特拉维夫', 'Johannesburg': '约翰内斯堡'}
COUNTRY_ZH = {'US': '美国', 'JP': '日本', 'KR': '韩国', 'SG': '新加坡', 'HK': '香港', 'TW': '台湾', 'AU': '澳大利亚',
              'IN': '印度', 'GB': '英国', 'DE': '德国', 'NL': '荷兰', 'FR': '法国', 'CA': '加拿大', 'SE': '瑞典',
              'IE': '爱尔兰', 'IT': '意大利', 'ES': '西班牙', 'CH': '瑞士', 'PL': '波兰', 'BR': '巴西', 'ID': '印尼',
              'TH': '泰国', 'MY': '马来西亚', 'VN': '越南', 'PH': '菲律宾', 'AE': '阿联酋', 'IL': '以色列', 'ZA': '南非',
              'RU': '俄罗斯', 'TR': '土耳其', 'MX': '墨西哥', 'FI': '芬兰', 'NO': '挪威', 'AT': '奥地利'}


def place_name(res):
    """'悉尼', '东京', or the country when the city is not a usual one; '' when unknown."""
    ip = (res or {}).get('ip') or {}
    city, cc = ip.get('city', ''), (ip.get('country') or (res or {}).get('country') or '').upper()
    return CITY_ZH.get(city) or COUNTRY_ZH.get(cc) or city or cc


def run():
    """Check everything (about 10 seconds), save and return the result."""
    out = {}

    def job(key, fn):
        try:
            out[key] = fn()
        except Exception as e:                 # never let one check break the rest
            out[key] = {'status': 'unknown', 'note': str(e)[:120]}
    t = [threading.Thread(target=job, args=('ip', ip_info)), threading.Thread(target=job, args=('trace', lambda: trace('claude.ai')))]
    for x in t:
        x.start()
    for x in t:
        x.join()
    ip = out.get('ip') or {}
    cc = ((out.get('trace') or {}).get('loc') or ip.get('country') or '').upper()
    checks = {'claude': lambda: check_claude(cc), 'claude_api': check_claude_api,
              'chatgpt': lambda: check_chatgpt(cc), 'gemini': lambda: check_gemini(cc)}
    t = [threading.Thread(target=job, args=(k, fn)) for k, fn in checks.items()]
    for x in t:
        x.start()
    for x in t:
        x.join()
    res = {'at': int(time.time()), 'country': cc, 'ip': ip, 'sites': {k: out[k] for k in SITES}}
    res['advice'] = advice(res)
    try:
        paths.write_atomic(FILE, json.dumps(res, ensure_ascii=False), 0o600)
    except OSError:
        pass
    return res


def latest():
    try:
        with open(FILE, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def summary(res):
    """'Claude ✓  ChatGPT ✓  Gemini ✗' (Claude counts as usable only when both the site and the API are)."""
    if not res:
        return ''
    s = res['sites']
    statuses = (s['claude']['status'], s['claude_api']['status'])
    claude = next((status for status in ('blocked', 'unreachable', 'unknown') if status in statuses),
                  'ok' if statuses == ('ok', 'ok') else 'unknown')
    parts = [('Claude', claude), ('ChatGPT', s['chatgpt']['status']), ('Gemini', s['gemini']['status'])]
    return '  '.join('%s %s' % (n, MARK.get(st, '?')) for n, st in parts)


def score(res):
    """0-4: how many of Claude / ChatGPT / Gemini look usable (Claude counted twice as heavy for ties)."""
    if not res:
        return -1
    s = res['sites']
    return (2 * (s['claude']['status'] == 'ok' and s['claude_api']['status'] == 'ok') +
            (s['chatgpt']['status'] == 'ok') + (s['gemini']['status'] == 'ok'))


def advice(res):
    out = []
    s = res['sites']
    if 'blocked' in (s['claude']['status'], s['claude_api']['status']):
        out.append('这台服务器所在地区用不了 Claude。想用 Claude，换一台美国、日本、新加坡等地区的服务器。')
    if (res.get('ip') or {}).get('kind') == 'hosting':
        out.append('这是机房 IP（VPS 都是这样），一般能正常用；固定用这一台登录 AI 网站，别频繁换地区。')
    if res.get('country') and res['country'] in UNSUPPORTED:
        out.append('这个地区大部分 AI 服务都不开放。')
    return out


def changed(old, new):
    """Sites whose status changed between two results, as text lines."""
    if not old or not new:
        return []
    out = []
    for k in SITES:
        a, b = old['sites'].get(k, {}).get('status'), new['sites'][k]['status']
        if a and a != b:
            out.append('%s: %s → %s' % (LABEL[k], MARK.get(a, '?'), MARK.get(b, '?')))
    return out
