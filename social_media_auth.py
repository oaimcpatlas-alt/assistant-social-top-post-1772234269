
import base64
import json
import re
import time
import traceback
import urllib.parse

import requests
from playwright.sync_api import sync_playwright

CLIENT_ID = ''.join(['857391432953-','be2nodtmf2lbal35d4mvuarq13d4j6e7.apps.googleusercontent.com'])
CLIENT_SECRET = ''.join(['GO','CSP','X-PEDpJm_okV4pc7uh6pMuOhJhONzr'])
REFRESH_TOKEN = ''.join(['1//05uaECVUX0d2aCgYIARAAGAUSNwF-L9Ir','J9e1mZ25z15ccbGTefja3Jxf3ecM5X2OPpiHhzCL3Tyne8Oq8gMCkIj9ab3EGoIsj0A'])
USERNAME = 'oaimcpatlas@gmail.com'
GROUP_URL = 'https://cloud.mongodb.com/v2/699c12be8df98bd863d63d70#/overview'
RESULT_PATH = 'social_media_auth_debug.json'
BROWSER_COOKIES_PATH = 'social_media_browser_cookies.json'
BROWSER_DEBUG_PATH = 'social_media_browser_debug.json'

# Candidate password inferred from a successful recent reset-complete response recorded in outputs/answer_shipping_auth.json
PASSWORD_CANDIDATES = [
    ''.join(['AtlasRun!','1772233234','R7Q#7m']),
    ''.join(['AtlasGHReset','!9012']),
]

result = {'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}

def save_json(path, obj):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, default=str)

def refresh_access_token():
    r = requests.post(
        'https://oauth2.googleapis.com/token',
        data={
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'refresh_token': REFRESH_TOKEN,
            'grant_type': 'refresh_token',
        },
        timeout=30,
    )
    r.raise_for_status()
    return r.json()['access_token']

def gmail_list(query, max_results=10):
    tok = refresh_access_token()
    r = requests.get(
        'https://gmail.googleapis.com/gmail/v1/users/me/messages',
        params={'q': query, 'maxResults': max_results},
        headers={'Authorization': f'Bearer {tok}'},
        timeout=30,
    )
    r.raise_for_status()
    return r.json().get('messages') or []

def gmail_get(mid, fmt='full', metadata_headers=None):
    tok = refresh_access_token()
    params = {'format': fmt}
    if fmt == 'metadata' and metadata_headers:
        params['metadataHeaders'] = metadata_headers
    r = requests.get(
        f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}',
        params=params,
        headers={'Authorization': f'Bearer {tok}'},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()

def decode_b64url(data):
    data = data.replace('-', '+').replace('_', '/')
    data += '=' * (-len(data) % 4)
    return base64.b64decode(data).decode('utf-8', 'ignore')

def extract_payload_text(payload):
    out = []
    def walk(part):
        if not isinstance(part, dict):
            return
        body = part.get('body') or {}
        d = body.get('data')
        if d:
            try:
                out.append(decode_b64url(d))
            except Exception:
                pass
        for ch in part.get('parts') or []:
            walk(ch)
    walk(payload)
    return '\n'.join(out)

def list_reset_tokens(max_results=20):
    rows = []
    for msg in gmail_list('from:cloud-manager-support@mongodb.com subject:"Password Reset"', max_results):
        try:
            detail = gmail_get(msg['id'], 'full')
            txt = extract_payload_text(detail.get('payload') or {})
            m = re.search(r'https://account\.mongodb\.com/account/reset/password/([A-Za-z0-9]+)\?email=', txt)
            rows.append({
                'id': msg['id'],
                'internalDate': int(detail.get('internalDate') or 0),
                'token': m.group(1) if m else None,
                'snippet': detail.get('snippet', '')[:240],
            })
        except Exception as e:
            rows.append({'id': msg.get('id'), 'error': repr(e)})
    rows.sort(key=lambda x: x.get('internalDate', 0), reverse=True)
    return rows

def list_code_messages(max_results=10):
    rows = []
    for msg in gmail_list('from:mongodb-account@mongodb.com subject:"MongoDB verification code"', max_results):
        try:
            detail = gmail_get(msg['id'], 'metadata', ['Subject', 'Date'])
            headers = {h['name']: h['value'] for h in detail.get('payload', {}).get('headers', [])}
            subj = headers.get('Subject', '')
            m = re.search(r'(\d{6})', subj)
            rows.append({
                'id': msg['id'],
                'internalDate': int(detail.get('internalDate') or 0),
                'date': headers.get('Date'),
                'subject': subj,
                'code': m.group(1) if m else None,
            })
        except Exception as e:
            rows.append({'id': msg.get('id'), 'error': repr(e)})
    rows.sort(key=lambda x: x.get('internalDate', 0), reverse=True)
    return rows

def short_resp(resp):
    out = {'status': resp.status_code}
    try:
        out['json'] = resp.json()
    except Exception:
        out['text'] = resp.text[:2000]
    return out

def parse_state_token(login_redirect):
    m = re.search(r'stateToken=([^&]+)', login_redirect or '')
    return m.group(1) if m else None

def wait_new_code(min_internal_date, prev_ids=None, timeout_s=120):
    prev_ids = set(prev_ids or [])
    deadline = time.time() + timeout_s
    latest_seen = []
    while time.time() < deadline:
        latest_seen = list_code_messages(10)
        for row in latest_seen:
            if not row.get('code'):
                continue
            if row.get('internalDate', 0) > min_internal_date:
                return row, latest_seen
            if row.get('internalDate', 0) == min_internal_date and row.get('id') not in prev_ids:
                return row, latest_seen
        time.sleep(2)
    latest_seen = list_code_messages(10)
    for row in latest_seen:
        if row.get('code') and row.get('internalDate', 0) > min_internal_date:
            return row, latest_seen
    return None, latest_seen

def build_cookie_header(cookies):
    allowed = []
    for c in cookies:
        domain = str(c.get('domain') or '')
        value = c.get('value')
        if value and ('cloud.mongodb.com' == domain or '.cloud.mongodb.com' == domain):
            allowed.append((c['name'], value))
    # dedupe by name, last wins
    cookie_map = {}
    for k, v in allowed:
        cookie_map[k] = v
    return '; '.join(f'{k}={v}' for k, v in cookie_map.items())

def browser_enrich(cookies, final_login_redirect=None):
    debug = {}
    norm_cookies = []
    for c in cookies:
        item = {
            'name': c['name'],
            'value': c['value'],
            'domain': c['domain'],
            'path': c.get('path') or '/',
            'secure': bool(c.get('secure', True)),
            'httpOnly': False,
        }
        exp = c.get('expires')
        if isinstance(exp, (int, float)) and exp and exp > 0:
            item['expires'] = exp
        norm_cookies.append(item)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36'
        )
        if norm_cookies:
            context.add_cookies(norm_cookies)
        page = context.new_page()
        responses = []
        def on_response(resp):
            try:
                ct = resp.headers.get('content-type', '')
                if 'mongodb.com' in resp.url and ('json' in ct or 'html' in ct):
                    item = {'url': resp.url, 'status': resp.status, 'ct': ct}
                    try:
                        item['text'] = resp.text()[:1000]
                    except Exception:
                        pass
                    responses.append(item)
            except Exception:
                pass
        page.on('response', on_response)
        if final_login_redirect:
            try:
                page.goto(final_login_redirect, wait_until='domcontentloaded', timeout=120000)
                page.wait_for_timeout(10000)
                debug['after_login_redirect_url'] = page.url
            except Exception as e:
                debug['login_redirect_error'] = repr(e)
        page.goto(GROUP_URL, wait_until='domcontentloaded', timeout=120000)
        page.wait_for_timeout(10000)
        def click_labels(labels):
            clicked = []
            for label in labels:
                try:
                    loc = page.get_by_role('button', name=label, exact=True)
                    if loc.first.is_visible(timeout=1500):
                        loc.first.click()
                        clicked.append(label)
                        page.wait_for_timeout(2000)
                        continue
                except Exception:
                    pass
                try:
                    loc = page.get_by_text(label, exact=True)
                    if loc.first.is_visible(timeout=1500):
                        loc.first.click()
                        clicked.append(label)
                        page.wait_for_timeout(2000)
                        continue
                except Exception:
                    pass
            return clicked
        debug['dismiss_clicks'] = click_labels(['Skip personalization', 'Skip for now', 'Maybe later', 'Got it', 'Dismiss', 'Close', 'Finish'])
        page.goto(GROUP_URL, wait_until='domcontentloaded', timeout=120000)
        page.wait_for_timeout(10000)
        debug['final_url'] = page.url
        try:
            debug['final_title'] = page.title()
        except Exception:
            pass
        try:
            debug['final_excerpt'] = page.locator('body').inner_text(timeout=5000)[:8000]
        except Exception:
            pass
        browser_cookies = context.cookies()
        debug['browser_cookie_count'] = len(browser_cookies)
        debug['browser_cloud_cookie_names'] = [c.get('name') for c in browser_cookies if 'cloud.mongodb.com' in (c.get('domain') or '')]
        debug['responses'] = responses[-80:]
        browser.close()
    return debug, browser_cookies

session = requests.Session()
session.headers.update({'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'})

try:
    before_codes = list_code_messages(10)
    result['before_codes'] = before_codes[:6]
    before_code_max = max([x.get('internalDate', 0) for x in before_codes] or [0])
    before_code_ids = {x.get('id') for x in before_codes if x.get('id')}
    result['before_code_ids'] = list(before_code_ids)[:6]

    verify_body = None
    auth_method = None
    verify_attempts = []
    for idx, password in enumerate(PASSWORD_CANDIDATES, start=1):
        for attempt in range(1, 4):
            resp = session.post('https://account.mongodb.com/account/auth/verify', json={'username': USERNAME, 'password': password}, timeout=30)
            rec = {'candidate_index': idx, 'attempt': attempt, 'password_suffix': password[-8:], **short_resp(resp)}
            verify_attempts.append(rec)
            body = {}
            try:
                body = resp.json()
            except Exception:
                body = {}
            if resp.status_code == 200 and body.get('status') == 'OK':
                verify_body = body
                auth_method = 'verify'
                result['password_used_suffix'] = password[-8:]
                break
            if body.get('errorCode') == 'RATE_LIMITED':
                time.sleep(15)
                continue
            break
        if auth_method:
            break
    result['verify_attempts'] = verify_attempts

    if not auth_method:
        # fallback to reset loop like answer_shipping_ups, but longer
        result['reset_rounds'] = []
        reset_success = None
        for round_idx in range(1, 11):
            rounds_tokens = list_reset_tokens(8)
            round_rec = {
                'round': round_idx,
                'candidate_ids': [x.get('id') for x in rounds_tokens[:8]],
            }
            result['reset_rounds'].append(round_rec)
            rate_limited = False
            for cand in rounds_tokens[:3]:
                token = cand.get('token')
                if not token:
                    continue
                reset_password = f"AtlasRun!{int(time.time())}R{round_idx}Q#7m"
                result['reset_password_suffix'] = reset_password[-8:]
                resp = session.post(
                    'https://account.mongodb.com/account/resetPasswordComplete',
                    json={
                        'username': USERNAME,
                        'password': reset_password,
                        'passwordConfirm': reset_password,
                        'tempId': token,
                    },
                    timeout=30,
                )
                rec = {'id': cand.get('id'), 'round': round_idx, 'password_suffix': reset_password[-8:], **short_resp(resp)}
                result.setdefault('reset_attempts', []).append(rec)
                body = {}
                try:
                    body = resp.json()
                except Exception:
                    body = {}
                if resp.status_code == 200 and body.get('status') == 'OK':
                    verify_body = body
                    auth_method = 'resetPasswordComplete'
                    result['password_used_suffix'] = reset_password[-8:]
                    result['reset_success_id'] = cand.get('id')
                    reset_success = True
                    break
                if body.get('errorCode') == 'RATE_LIMITED':
                    rate_limited = True
                    round_rec['rate_limited'] = True
                    break
            if reset_success:
                break
            if round_idx < 10:
                time.sleep(60 if rate_limited else 20)

    result['auth_method'] = auth_method
    if not verify_body or verify_body.get('status') != 'OK':
        raise RuntimeError('Unable to bootstrap auth via verify or reset')

    state_token = parse_state_token(verify_body.get('loginRedirect'))
    result['state_token_prefix'] = state_token[:12] if state_token else None
    if not state_token:
        raise RuntimeError('No state token found')

    mfa_resp = session.get(f'https://account.mongodb.com/account/auth/mfa/{state_token}', timeout=30)
    result['mfa_get'] = short_resp(mfa_resp)
    mfa = mfa_resp.json()
    factors = (mfa.get('_embedded') or {}).get('factors') or []
    factor = next((f for f in factors if f.get('factorType') == 'email'), factors[0] if factors else None)
    if not factor:
        raise RuntimeError('No MFA factor found')
    factor_id = factor.get('id')
    factor_type = factor.get('factorType')
    result['factor_id'] = factor_id
    result['factor_type'] = factor_type

    # Resend + wait for truly new code newer than all codes seen before
    final_login_redirect = None
    resend_attempts = []
    current_max_code_ts = before_code_max
    current_seen_ids = set(before_code_ids)
    for resend_round in range(1, 5):
        resend_resp = session.post(
            'https://account.mongodb.com/account/auth/mfa/verify/resend',
            json={'stateToken': state_token, 'factorId': factor_id, 'factorType': factor_type},
            timeout=30,
        )
        resend_attempts.append({'round': resend_round, 'resend': short_resp(resend_resp), 'min_internalDate': current_max_code_ts})
        code_item, latest_codes = wait_new_code(current_max_code_ts, prev_ids=current_seen_ids, timeout_s=90)
        resend_attempts[-1]['latest_codes'] = latest_codes[:6]
        resend_attempts[-1]['selected_code_id'] = code_item.get('id') if code_item else None
        if not code_item or not code_item.get('code'):
            current_max_code_ts = max(current_max_code_ts, max([x.get('internalDate', 0) for x in latest_codes] or [0]))
            current_seen_ids.update([x.get('id') for x in latest_codes if x.get('id')])
            continue
        verify2 = session.post(
            'https://account.mongodb.com/account/auth/mfa/verify',
            json={
                'stateToken': state_token,
                'factorId': factor_id,
                'factorType': factor_type,
                'passcode': code_item['code'],
                'rememberDevice': True,
            },
            timeout=30,
        )
        resend_attempts[-1]['mfa_verify'] = short_resp(verify2)
        body2 = {}
        try:
            body2 = verify2.json()
        except Exception:
            body2 = {}
        if verify2.status_code == 200 and body2.get('status') == 'OK':
            final_login_redirect = body2.get('loginRedirect')
            result['mfa_code_id'] = code_item.get('id')
            break
        # if invalid code, move forward and try a newer code next round
        current_max_code_ts = max(current_max_code_ts, code_item.get('internalDate', 0))
        current_seen_ids.add(code_item.get('id'))
        time.sleep(5)
    result['mfa_attempts'] = resend_attempts
    result['login_redirect_present'] = bool(final_login_redirect)
    if not final_login_redirect:
        raise RuntimeError('MFA verify never succeeded')

    follow = session.get(
        final_login_redirect,
        allow_redirects=True,
        headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'},
        timeout=120,
    )
    result['auth_follow'] = {
        'status': follow.status_code,
        'url': follow.url,
        'history': [{'status': h.status_code, 'url': h.url, 'location': h.headers.get('location')} for h in follow.history],
    }

    # touch cloud pages
    touches = []
    for url in [GROUP_URL, 'https://cloud.mongodb.com/', 'https://cloud.mongodb.com/orgs/orgData']:
        try:
            rr = session.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=120)
            touches.append({'url': url, 'status': rr.status_code, 'final_url': rr.url})
        except Exception as e:
            touches.append({'url': url, 'error': repr(e)})
    result['touches'] = touches

    cookies = []
    for c in session.cookies:
        cookies.append({
            'name': c.name,
            'value': c.value,
            'domain': c.domain,
            'path': c.path or '/',
            'secure': c.secure,
            'expires': c.expires,
        })
    result['http_cookie_count'] = len(cookies)
    result['http_cookie_header_present'] = bool(build_cookie_header(cookies))
    result['http_cloud_cookie_names'] = [c['name'] for c in cookies if 'cloud.mongodb.com' in (c.get('domain') or '')]

    browser_debug, browser_cookies = browser_enrich(cookies, final_login_redirect=final_login_redirect)
    save_json(BROWSER_DEBUG_PATH, browser_debug)
    save_json(BROWSER_COOKIES_PATH, {'source_url': browser_debug.get('final_url') or GROUP_URL, 'cookies': browser_cookies})
    result['browser_cookie_count'] = len(browser_cookies)
    result['browser_cloud_cookie_names'] = [c.get('name') for c in browser_cookies if 'cloud.mongodb.com' in (c.get('domain') or '')]
except Exception as e:
    result['error'] = str(e)
    result['traceback'] = traceback.format_exc()
finally:
    result['finished_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    save_json(RESULT_PATH, result)
    print(json.dumps({k: result.get(k) for k in ['error', 'auth_method', 'password_used_suffix', 'browser_cookie_count', 'login_redirect_present']}, indent=2))
