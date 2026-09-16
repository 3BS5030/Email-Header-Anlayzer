# email_analysis.py
#
# Pure Python port of the Email Header Analyzer logic (no GUI, no DOM).
# Loads a .eml file and produces the same report the browser extension builds:
#   SPF / DKIM / DMARC, Received-chain reconstruction, observed source IP,
#   sender-identity differences and passive indicators.
#
# Stdlib only (email, re, ipaddress). See gui.py for the desktop interface.

import re
import base64
import email
import datetime
from email.header import decode_header

VERSION = '1.0.0'

# ---------------------------------------------------------------------------
# Header / message loading
# ---------------------------------------------------------------------------

def unfold(value):
    """Collapse folded continuation lines into a single line."""
    return re.sub(r'\r?\n[ \t]+', ' ', value or '')


def decode_encoded_words(s):
    """Decode RFC 2047 encoded words in a string ('=?utf-8?B?...?=')."""
    if not s or '=?' not in s:
        return s
    try:
        parts = decode_header(s)
    except Exception:
        return s
    out = []
    for text, charset in parts:
        if isinstance(text, bytes):
            try:
                out.append(text.decode(charset or 'utf-8', 'replace'))
            except Exception:
                out.append(text.decode('utf-8', 'replace'))
        else:
            out.append(text)
    return ''.join(out)


def parse_header_list(raw_text):
    """Split raw message text into a list of {name, value, raw} headers.

    Mirrors the JS HeaderParser.parseHeaders output: order and duplicates are
    preserved, values are unfolded (-+ and CRLF), lookups are case-insensitive.
    """
    headers = []
    normalized = re.sub(r'\r\n?', '\n', raw_text or '')
    lines = normalized.split('\n')
    current = None

    def is_hdr_line(ln):
        m = re.match(r'^([^:\s][^:]*):([\s\S]*)$', ln)
        return m

    for line in lines:
        if line.strip() == '':
            break  # end of header block
        if line[:1] in (' ', '\t'):
            if current is not None:
                current['value'] += ' ' + line.strip()
                current['raw'] += '\n' + line
            continue
        m = is_hdr_line(line)
        if not m:
            continue
        current = {
            'name': m.group(1).strip(),
            'value': m.group(2).strip(),
            'raw': line
        }
        headers.append(current)
    return headers


def parse_eml(path):
    """Read a .eml file and return {'raw', 'headers', 'subject', 'filename'}."""
    with open(path, 'rb') as f:
        data = f.read()
    try:
        raw_text = data.decode('utf-8', 'replace')
    except Exception:
        raw_text = data.decode('latin-1', 'replace')

    # Prefer our own splitter (mirrors the JS HeaderParser): values stay raw,
    # so RFC 2047 encoded words remain detectable (e.g. obfuscated names).
    headers = parse_header_list(raw_text)

    # Fall back to the stdlib parser if our splitter yielded nothing useful
    # (e.g. unusual line endings that confuse the continuation logic).
    if not headers:
        msg = email.message_from_bytes(data)
        headers = []
        for name, value in msg.items():
            headers.append({'name': name, 'value': unfold(value), 'raw': value})

    return {'raw': raw_text, 'headers': headers, 'filename': path}


def get_all(headers, name):
    target = (name or '').lower()
    return [h['value'] for h in headers if str(h.get('name', '')).lower() == target]


def get_first(headers, name):
    vals = get_all(headers, name)
    return vals[0] if vals else None


# ---------------------------------------------------------------------------
# Address parser (port of parser/addressParser.js)
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$"
)
IP_DOMAIN_RE = re.compile(r'^(?:\[[0-9]{1,3}(?:\.[0-9]{1,3}){3}\]|\[IPv6:[\w:.]+\])$')


def _split_tokens(value):
    """Split an address list on top-level commas (quote/angle/paren aware)."""
    out = []
    if not value:
        return out
    buf = ''
    quote = False
    angle = 0
    paren = 0
    i = 0
    while i < len(value):
        ch = value[i]
        if quote:
            buf += ch
            if ch == '\\' and i < len(value) - 1:
                buf += value[i + 1]
                i += 1
            elif ch == '"':
                quote = False
            i += 1
            continue
        if ch == '"':
            quote = True
            buf += ch
        elif ch == '<':
            angle += 1
            buf += ch
        elif ch == '>':
            angle = max(0, angle - 1)
            buf += ch
        elif ch == '(':
            paren += 1
            buf += ch
        elif ch == ')':
            paren = max(0, paren - 1)
            buf += ch
        elif ch == ',' and angle == 0 and paren == 0:
            out.append(buf)
            buf = ''
        else:
            buf += ch
        i += 1
    if buf.strip():
        out.append(buf)
    return out


def _strip_comments(s):
    out = ''
    depth = 0
    quote = False
    i = 0
    while i < len(s):
        ch = s[i]
        if quote:
            out += ch
            if ch == '\\' and i < len(s) - 1:
                out += s[i + 1]
                i += 1
            elif ch == '"':
                quote = False
            i += 1
            continue
        if ch == '"':
            quote = True
            out += ch
        elif ch == '(':
            depth += 1
        elif ch == ')':
            depth = max(0, depth - 1)
        elif depth == 0:
            out += ch
        i += 1
    return out


def _extract_email(token):
    t = (token or '').strip()
    if not t:
        return None
    lt = t.find('<')
    gt = t.rfind('>')
    if lt != -1 and gt > lt:
        t = t[lt + 1:gt].strip()
    else:
        mt = re.match(r'^mailto:', t, re.I)
        if mt:
            t = t[mt.end():].strip()
    t = re.sub(r'[;.,\s]+$', '', t)
    valid = bool(EMAIL_RE.match(t)) or bool(IP_DOMAIN_RE.match(t))
    return t if valid else None


def _clean_display_name(raw):
    name = _strip_comments(raw)
    lt = name.find('<')
    if lt != -1:
        name = name[:lt]
    name = name.strip(' "\t;')
    name = re.sub(r'\s+', ' ', name).strip()
    if not name:
        return None
    if '@' in name:
        return None
    if re.match(r'^\s*[<[]', name):
        return None
    decoded = decode_encoded_words(name)
    return decoded


def _parse_token(token):
    t = (token or '').strip()
    if not t:
        return None

    # RFC 5322 obsolete group syntax: "name: addr, addr;"
    gm = re.match(r'^([^:]+):([\s\S]*);?$', t)
    if gm and ';' in t and '@' in gm.group(2):
        members = [_parse_token(m) for m in _split_tokens(gm.group(2))]
        members = [x for x in members if x]
        return members[0] if members else None

    email_addr = _extract_email(t)
    if not email_addr:
        lone = EMAIL_RE.search(_strip_comments(t).strip())
        if lone:
            email_addr = lone.group(0)
    if not email_addr:
        return None

    at = email_addr.rfind('@')
    domain = email_addr[at + 1:].lower().strip('[]') if at != -1 else None
    return {
        'raw': t,
        'displayName': _clean_display_name(t),
        'email': email_addr,
        'domain': domain,
        'valid': True,
    }


def parse_address_list(value):
    result = {
        'addresses': [],
        'displayName': None,
        'email': None,
        'domain': None,
        'raw': value or '',
    }
    if not value:
        return result
    for token in _split_tokens(value):
        parsed = _parse_token(token)
        if parsed:
            result['addresses'].append(parsed)
    if result['addresses']:
        result['displayName'] = result['addresses'][0].get('displayName')
        result['email'] = result['addresses'][0].get('email')
        result['domain'] = result['addresses'][0].get('domain')
    return result


def parse_address(value):
    lst = parse_address_list(value)
    return lst['addresses'][0] if lst['addresses'] else None


def addr_key(address):
    if not address or not address.get('email'):
        return None
    return str(address['email']).lower()


def same_address(a, b):
    ka, kb = addr_key(a), addr_key(b)
    if ka is None and kb is None:
        return True
    return ka == kb


# ---------------------------------------------------------------------------
# Authentication parser (port of parser/authenticationParser.js)
# ---------------------------------------------------------------------------

PAREN_RE = re.compile(r'\(\s*([\s\S]*?)\s*\)')
METHOD_RE = re.compile(r'^([A-Za-z][A-Za-z0-9.-]*)\s*=\s*([A-Za-z0-9_/.+-]+)')
KV_RE = re.compile(r'([A-Za-z0-9][A-Za-z0-9.-]*)\s*=\s*(?:"([^"]*)"|([^;\s]+))')

KNOWN_METHODS = ['spf', 'dkim', 'dmarc', 'auth', 'iprev', 'sender-id', 'mailfrom', 'arc']


def split_top_level(text, sep=';'):
    parts = []
    depth = 0
    quote = False
    buf = ''
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            buf += ch
            if ch == '\\' and i < len(text) - 1:
                buf += text[i + 1]
                i += 1
            elif ch == '"':
                quote = False
        elif ch == '"':
            quote = True
            buf += ch
        elif ch == '(':
            depth += 1
            buf += ch
        elif ch == ')':
            depth = max(0, depth - 1)
            buf += ch
        elif ch == sep and depth == 0:
            parts.append(buf)
            buf = ''
        else:
            buf += ch
        i += 1
    if buf.strip():
        parts.append(buf)
    return parts


_PARAM_ALIAS = {
    'smtpmailfrom': 'mailfrom', 'mailfrom': 'mailfrom',
    'smtphelo': 'helo', 'helo': 'helo',
    'smtpclientip': 'clientip', 'smtpclientip1': 'clientip',
    'smtpremoteip': 'clientip', 'clientip': 'clientip',
    'smtpremoteipv6': 'clientip',
    'headerfrom': 'headerfrom', 'headerd': 'headerd',
    'headeri': 'headeri', 'headers': 'headers',
    'dnssec': 'dnssec', 'policy': 'policy', 'scope': 'scope',
    'identity': 'identity', 'receiver': 'receiver',
}


def canonical_param_key(raw_key):
    k = re.sub(r'[^a-z0-9]', '', (raw_key or '').lower())
    return _PARAM_ALIAS.get(k, k)


def parse_authentication_result(value):
    raw = (value or '').strip()
    out = {'authservId': None, 'results': [], 'raw': raw}
    if not raw:
        return out

    segments = split_top_level(raw, ';')
    if not segments:
        return out

    start = 0
    auth_raw = segments[0].strip()
    if re.match(r'^[A-Za-z][A-Za-z0-9.-]*\s*=\s*', auth_raw):
        out['authservId'] = None
        start = 0
    else:
        pm = PAREN_RE.search(auth_raw)
        if pm:
            auth_raw = PAREN_RE.sub(' ', auth_raw).strip()
        out['authservId'] = auth_raw
        start = 1

    last_result = None
    for seg in segments[start:]:
        seg = seg.strip()
        if not seg:
            continue
        m = METHOD_RE.match(seg)
        if not m:
            why = re.match(r'^reason\s*=\s*([\s\S]+)$', seg)
            if why and last_result is not None:
                prev = last_result.get('reason') or ''
                why_txt = re.sub(r';\s*$', '', why.group(1))
                last_result['reason'] = (prev + ' ' + why_txt).strip()
            continue

        method = m.group(1).lower()
        result = m.group(2).lower()
        rest = seg[m.end():]

        entry = {
            'method': method,
            'result': result,
            'params': {},
            'comment': None,
            'reason': None,
            'type': 'result',
        }

        if method == 'version':
            entry['type'] = 'version'
        elif method not in KNOWN_METHODS and not re.match(r'^(?:smtp\.|header\.|policy|dnssec)', seg):
            entry['type'] = 'statement'

        cp = PAREN_RE.search(rest)
        if cp:
            entry['comment'] = cp.group(1).strip()
            rest = PAREN_RE.sub(' ', rest)

        for kv in KV_RE.finditer(rest):
            raw_key = kv.group(1)
            raw_val = (kv.group(2) if kv.group(2) is not None else kv.group(3)).strip()
            raw_val = re.sub(r';?\s*$', '', raw_val)
            key = canonical_param_key(raw_key)
            if raw_key.lower() == 'reason':
                entry['reason'] = raw_val
            elif key == 'policy':
                entry['policy'] = raw_val
            elif key in ('scope', 'identity', 'dnssec', 'receiver'):
                entry[key] = raw_val
            else:
                entry['params'][key] = raw_val

        out['results'].append(entry)
        last_result = entry

    return out


def parse_all_authentication_results(headers):
    return [parse_authentication_result(h['value'])
            for h in headers if h.get('name', '').lower() == 'authentication-results']


def parse_received_spf(value):
    raw = (value or '').strip()
    out = {'result': None, 'comment': None, 'clientIp': None, 'envelopeFrom': None,
           'helo': None, 'receiver': None, 'scope': None, 'identity': None, 'raw': raw}
    if not raw:
        return out
    m = re.match(r'^([A-Za-z][A-Za-z0-9-]*(?:/[A-Za-z0-9-]+)?)', raw)
    if m:
        out['result'] = m.group(1).lower()
    cp = PAREN_RE.search(raw)
    if cp:
        out['comment'] = cp.group(1).strip()
        ip4 = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', out['comment'])
        ip6 = re.search(r'(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]+', out['comment'])
        if not out['clientIp']:
            out['clientIp'] = ip4.group(1) if ip4 else (ip6.group(0) if ip6 else None)
    for kv in KV_RE.finditer(raw):
        key = canonical_param_key(kv.group(1))
        val = (kv.group(2) if kv.group(2) is not None else kv.group(3)).strip()
        val = re.sub(r';?\s*$', '', val)
        if key == 'clientip':
            out['clientIp'] = val
        elif key in ('envelopefrom', 'mailfrom'):
            out['envelopeFrom'] = val
        elif key == 'helo':
            out['helo'] = val
        elif key == 'receiver':
            out['receiver'] = val
        elif key == 'scope':
            out['scope'] = val
        elif key == 'identity':
            out['identity'] = val
    return out


def parse_all_received_spf(headers):
    return [parse_received_spf(h['value'])
            for h in headers if h.get('name', '').lower() == 'received-spf']


def parse_dkim_signature(value):
    raw = (value or '').strip()
    out = {'tags': {}, 'domain': None, 'selector': None, 'algorithm': None,
           'canonicalization': None, 'raw': raw}
    if not raw:
        return out
    for part in split_top_level(raw, ';'):
        part = part.strip()
        if not part:
            continue
        eq = part.find('=')
        if eq == -1:
            continue
        key = part[:eq].strip().lower()
        val = part[eq + 1:].strip()
        val = re.sub(r';?\s*$', '', val)
        out['tags'][key] = val
    out['domain'] = out['tags'].get('d')
    out['selector'] = out['tags'].get('s')
    out['algorithm'] = out['tags'].get('a')
    out['canonicalization'] = out['tags'].get('c')
    return out


def parse_all_dkim_signatures(headers):
    return [parse_dkim_signature(h['value'])
            for h in headers if h.get('name', '').lower() == 'dkim-signature']


# ---------------------------------------------------------------------------
# MIME content + attachment extraction (port of parser/mimeParser.js +
# parser/urlExtractor.js). Uses the stdlib email package so MIME recursion,
# Content-Transfer-Encoding handling and RFC 2231 file names are free.
# ---------------------------------------------------------------------------

HTML_ATTR_URL_RE = re.compile(
    r'(?:href|src|action|background|content|data-url|cite|poster|srcset)?\s*=\s*'
    r'["\'](https?://[^"\']+)["\']', re.I)
BARE_URL_RE = re.compile(r'https?://[^\s<>"\'\[\]]+', re.I)
URL_TRAIL_RE = re.compile(r'[.,;:!?\])}]+$')
URL_ENTITIES = (('&amp;', '&'), ('&quot;', '"'), ('&#39;', "'"),
                ('&lt;', '<'), ('&gt;', '>'), ('&#x27;', "'"), ('&#39', "'"))


def _clean_up_url(url):
    u = url.strip()
    u = URL_TRAIL_RE.sub('', u)
    u = u.rstrip("'\"")
    for e, r in URL_ENTITIES:
        u = u.replace(e, r)
    m = re.match(r'^(https?://[^/?#]+)([#?]|$)', u, re.I)
    if m and not m.group(2):
        u = m.group(1) + '/'
    return u


def extract_urls(text):
    """Extract de-duplicated URLs from decoded text (plain + HTML)."""
    if not text:
        return []
    seen = set()
    out = []
    for m in BARE_URL_RE.finditer(text):
        u = _clean_up_url(m.group(0))
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    for m in HTML_ATTR_URL_RE.finditer(text):
        u = _clean_up_url(m.group(1))
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _walk_mime(part, out):
    ctype = (part.get_content_type() or 'text/plain').lower()
    cd = part.get_content_disposition()
    filename = part.get_filename()
    is_attachment = bool((cd or '').lower() == 'attachment' or filename)
    if part.is_multipart():
        for sub in part.get_payload():
            if isinstance(sub, str):
                continue
            _walk_mime(sub, out)
        return

    payload = None
    try:
        payload = part.get_payload(decode=True)
    except Exception:  # noqa: BLE001 - never crash, degrade to a text dump
        payload = None

    if is_attachment:
        disp = cd if cd in ('attachment', 'inline') else ('attachment' if filename else 'inline')
        out['attachments'].append({
            'filename': filename or None,
            'contentType': part.get('Content-Type') or None,
            'mediaType': ctype,
            'transferEncoding': (part.get('Content-Transfer-Encoding') or '7bit').lower(),
            'size': len(payload) if payload else 0,
            'disposition': disp,
            'inline': disp == 'inline',
            'description': part.get('Content-Description') or None,
            'hasData': bool(payload and len(payload)),
            'base64': base64.b64encode(payload).decode('ascii') if payload else None,
        })
        return

    if payload:
        try:
            charset = part.get_content_charset() or 'utf-8'
            text = payload.decode(charset, 'replace')
        except Exception:  # noqa: BLE001
            text = payload.decode('utf-8', 'replace')
    else:
        text = str(part.get_payload() or '')
    if ctype == 'text/html':
        out['html'] = (out['html'] or '') + '\n' + text
    elif ctype == 'text/plain':
        out['plainText'] = (out['plainText'] or '') + '\n' + text


def parse_mime(raw_text):
    """Decode an email body: {contentType, plainText, html, text, links, attachments}.

    Mirrors ns.MimeParser.parse + ns.UrlExtractor.extract used by the browser
    extension. attachrments carry 'base64' payloads so the GUI can offer real
    save-to-disk links without holding decoded blobs in memory.
    """
    out = {'contentType': None, 'plainText': None, 'html': None,
           'text': '', 'links': [], 'attachments': []}
    raw = raw_text or ''
    if not raw:
        return out
    try:
        msg = email.message_from_string(raw)
        out['contentType'] = msg.get('Content-Type') or None
        _walk_mime(msg, out)
    except Exception:  # noqa: BLE001 - degrade to a single plain-text blob
        pass
    if out['plainText'] is None and out['html'] is None:
        out['plainText'] = raw

    texts = [t for t in (out['plainText'], out['html']) if t]
    out['text'] = '\n'.join(texts)
    out['links'] = extract_urls('\n'.join(texts))
    return out


# ---------------------------------------------------------------------------
# Received parser (port of parser/receivedParser.js)
# ---------------------------------------------------------------------------

V4_RE = re.compile(r'\b(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\b')
TIMESTAMP_RE = re.compile(
    r'((?:[A-Za-z]{3,9},?\s+)?\d{1,2}\s+[A-Za-z]{3,9}\s+\d{2,4}\s+\d{1,2}:\d{2}(?::\d{2})?\s*'
    r'(?:[+-]\d{4}|\b[A-Za-z]{1,5}\b)?(?:\s*\([^)]*\))?)'
)
BRACKET_RE = re.compile(r'\[([^\]]*)\]')
HEX_RUN_RE = re.compile(r'[0-9A-Fa-f:.]+')

KEYWORDS = {'from', 'by', 'via', 'with', 'id', 'for', 'return-path'}


def split_outer_semi(text):
    depth = 0
    quote = False
    last = -1
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == '\\':
                i += 1
            elif ch == '"':
                quote = False
        elif ch == '"':
            quote = True
        elif ch == '(':
            depth += 1
        elif ch == ')':
            depth = max(0, depth - 1)
        elif ch == ';' and depth == 0:
            last = i
        i += 1
    if last == -1:
        return {'before': text.strip(), 'after': ''}
    return {'before': text[:last].strip(), 'after': text[last + 1:].strip()}


def tokenize(s):
    tokens = []
    cur = ''
    i = 0

    def flush():
        nonlocal cur
        if cur:
            tokens.append(cur.strip())
            cur = ''

    while i < len(s):
        ch = s[i]
        if ch == '(':
            flush()
            depth = 0
            j = i
            while j < len(s):
                if s[j] == '(':
                    depth += 1
                if s[j] == ')':
                    depth -= 1
                j += 1
                if depth <= 0:
                    break
            tokens.append(s[i:j])
            i = j
            continue
        if ch.isspace():
            flush()
            i += 1
            continue
        cur += ch
        i += 1
    flush()
    return tokens


def _strip_parens(tok):
    if tok and tok[0] == '(' and tok[-1] == ')':
        return tok[1:-1]
    return tok


def _is_bracket_literal(tok):
    return bool(tok) and tok[0] == '[' and tok[-1] == ']'


def normalize_ip(ip):
    if not ip:
        return None
    v = str(ip).strip()
    if v and v[0] == '[' and v[-1] == ']':
        v = v[1:-1]
    v = re.sub(r'^IPv6:', '', v, flags=re.I)
    v = re.sub(r'^inet6[:\s]+', '', v, flags=re.I)
    v = re.sub(r'%[A-Za-z0-9._-]+$', '', v)
    if not v:
        return None
    return v.lower()


def ip_type(ip):
    return 'ipv6' if ip and ':' in ip else 'ipv4'


def _count_hex_groups(s):
    if not s:
        return 0
    s = re.sub(r'\d{1,3}(?:\.\d{1,3}){3}$', 'x', s)
    groups = [g for g in s.split(':') if g]
    for g in groups:
        if not re.match(r'^[0-9A-Fa-f]{1,4}$', g) and g != 'x':
            return -1
    return len(groups)


def _plausible_ipv6(s):
    if not s:
        return False
    v = s.strip()
    if ':' not in v:
        return False
    parts = v.split('::')
    if len(parts) == 1:
        return _count_hex_groups(v) == 8
    if len(parts) != 2:
        return False
    l = _count_hex_groups(parts[0])
    r = _count_hex_groups(parts[1])
    if l == -1 or r == -1:
        return False
    return l + r <= 7


def extract_ips(s):
    """Extract IPv4 + IPv6 addresses from a string (bracket literals first)."""
    out = []
    seen = set()
    text = str(s or '')
    masked = text

    def add(ip, typ):
        if not ip or ip in seen:
            return
        seen.add(ip)
        out.append({'ip': ip, 'type': typ, 'raw': ip})

    spans = []
    for m in BRACKET_RE.finditer(text):
        content = m.group(1)
        if ':' not in content:
            continue
        norm = normalize_ip(content)
        if norm and _plausible_ipv6(norm):
            add(norm, 'ipv6')
            spans.append((m.start(), m.end()))
    if spans:
        chunks = []
        cur = 0
        for s0, e0 in spans:
            if s0 > cur:
                chunks.append(text[cur:s0])
            cur = e0
        chunks.append(text[cur:])
        masked = ' '.join(chunks)

    for m in V4_RE.finditer(masked):
        add(m.group(0), 'ipv4')
    for m in HEX_RUN_RE.finditer(masked):
        run = m.group(0)
        if ':' not in run:
            continue
        if _plausible_ipv6(run):
            add(run, 'ipv6')
    return out


LOOKS_IPV4 = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
LOOKS_IPV6 = re.compile(r'^[0-9a-fA-F:]+$')


def looks_like_ip(s):
    return bool(LOOKS_IPV4.match(s)) or (':' in s and bool(LOOKS_IPV6.match(s)))


def normalize_addr_literal(tok):
    inner = tok[1:-1]
    inner = re.sub(r'^IPv6:', '', inner, flags=re.I)
    n = normalize_ip(inner)
    if not looks_like_ip(n):
        return None
    return n


RFC1918_MSG = {
    (10, None): 'Private IPv4 (10.0.0.0/8, RFC 1918)',
    (127, None): 'IPv4 loopback (127.0.0.0/8)',
    (169, 254): 'IPv4 link-local (169.254.0.0/16)',
}


def private_ip_info(ip):
    n = normalize_ip(ip)
    if not n:
        return {'isPrivate': False, 'description': None}

    if ':' in n:
        if n == '::1':
            return {'isPrivate': True, 'description': 'IPv6 loopback (::1)'}
        if n == '::':
            return {'isPrivate': True, 'description': 'IPv6 unspecified (::)'}
        if re.match(r'^fc[0-9a-f]|^fd[0-9a-f]', n):
            return {'isPrivate': True, 'description': 'IPv6 unique local (fc00::/7)'}
        if re.match(r'^fe[89ab][0-9a-f]', n):
            return {'isPrivate': True, 'description': 'IPv6 link-local (fe80::/10)'}
        if n.startswith('2001:db8'):
            return {'isPrivate': False, 'description': 'IPv6 documentation range (2001:db8::/32)'}
        m = re.search(r'::ffff:(\d{1,3}(?:\.\d{1,3}){3})$', n)
        if m:
            return private_ip_info(m.group(1))
        return {'isPrivate': False, 'description': None}

    parts = [int(x) for x in n.split('.')]
    if len(parts) != 4 or any(x < 0 or x > 255 for x in parts):
        return {'isPrivate': False, 'description': None}
    a, b = parts[0], parts[1]
    if a == 10:
        return {'isPrivate': True, 'description': 'Private IPv4 (10.0.0.0/8, RFC 1918)'}
    if a == 172 and 16 <= b <= 31:
        return {'isPrivate': True, 'description': 'Private IPv4 (172.16.0.0/12, RFC 1918)'}
    if a == 192 and b == 168:
        return {'isPrivate': True, 'description': 'Private IPv4 (192.168.0.0/16, RFC 1918)'}
    if a == 127:
        return {'isPrivate': True, 'description': 'IPv4 loopback (127.0.0.0/8)'}
    if a == 169 and b == 254:
        return {'isPrivate': True, 'description': 'IPv4 link-local (169.254.0.0/16)'}
    if a == 100 and 64 <= b <= 127:
        return {'isPrivate': True, 'description': 'Carrier-grade NAT (100.64.0.0/10)'}
    if a == 0:
        return {'isPrivate': True, 'description': 'This network (0.0.0.0/8)'}
    if a == 192 and b == 0 and parts[2] == 0:
        return {'isPrivate': True, 'description': 'IETF reserved (192.0.0.0/24)'}
    if a == 192 and b == 0 and parts[2] == 2:
        return {'isPrivate': False, 'description': 'Documentation (TEST-NET-1, 192.0.2.0/24)'}
    if a == 198 and b in (18, 19):
        return {'isPrivate': True, 'description': 'Benchmarking range (198.18.0.0/15)'}
    if a == 198 and b == 51 and parts[2] == 100:
        return {'isPrivate': False, 'description': 'Documentation (TEST-NET-2, 198.51.100.0/24)'}
    if a == 203 and b == 0 and parts[2] == 113:
        return {'isPrivate': False, 'description': 'Documentation (TEST-NET-3, 203.0.113.0/24)'}
    if 224 <= a <= 239:
        return {'isPrivate': True, 'description': 'Multicast (224.0.0.0/4)'}
    if a >= 240:
        return {'isPrivate': True, 'description': 'Reserved (240.0.0.0/4)'}
    return {'isPrivate': False, 'description': None}


def _parse_date(s):
    if not s:
        return None
    try:
        import email.utils
        dt = email.utils.parsedate_to_datetime(s)
        return dt.astimezone(datetime.timezone.utc).isoformat() if dt else None
    except Exception:
        return None


def parse_received(value):
    out = {
        'fromHost': None, 'fromHelo': None, 'fromIp': None, 'fromIpType': None,
        'fromComment': None, 'byHost': None, 'byIp': None, 'byComment': None,
        'viaHost': None, 'viaComment': None, 'withProto': None, 'protoComment': None,
        'id': None, 'forAddr': None, 'timestamp': '', 'timestampDate': None,
        'comment': None, 'malformed': [], 'raw': (value or '').strip(),
    }
    if not out['raw']:
        out['malformed'].append('empty Received header')
        return out

    text = out['raw']
    split = split_outer_semi(text)
    main = split['before']
    out['timestamp'] = split['after']
    if out['timestamp']:
        tm = TIMESTAMP_RE.search(out['timestamp'])
        if tm:
            out['timestampDate'] = _parse_date(tm.group(1))

    tokens = tokenize(main)
    i = [0]

    def current():
        return tokens[i[0]] if i[0] < len(tokens) else None

    def advance():
        i[0] += 1

    def peek_is_keyword():
        tok = current()
        return tok is not None and tok.lower() in KEYWORDS

    def capture_one_or_comment():
        res = {'value': None, 'comment': None}
        if i[0] >= len(tokens):
            return res
        tok = tokens[i[0]]
        if tok.startswith('('):
            res['comment'] = _strip_parens(tok)
            advance()
            return res
        res['value'] = tok
        advance()
        if i[0] < len(tokens) and tokens[i[0]].startswith('('):
            res['comment'] = _strip_parens(tokens[i[0]])
            advance()
        return res

    while i[0] < len(tokens):
        tok = tokens[i[0]]
        lower = tok.lower()

        if lower == 'from':
            advance()
            if i[0] >= len(tokens):
                break
            from_tok = tokens[i[0]]
            advance()
            if from_tok.startswith('('):
                out['fromComment'] = _strip_parens(from_tok)
                continue
            if _is_bracket_literal(from_tok):
                out['fromHost'] = from_tok
                literal = normalize_addr_literal(from_tok)
                if literal:
                    out['fromIp'] = literal
                    out['fromIpType'] = 'ipv6' if ':' in literal else 'ipv4'
                else:
                    out['malformed'].append('invalid address literal: ' + from_tok)
            else:
                out['fromHost'] = from_tok
            if i[0] < len(tokens) and tokens[i[0]].startswith('('):
                out['fromComment'] = _strip_parens(tokens[i[0]])
                advance()
            continue

        if lower == 'by':
            advance()
            by = capture_one_or_comment()
            if by['value']:
                if _is_bracket_literal(by['value']):
                    stripped = re.sub(r'^\[|\]$', '', by['value'])
                    stripped = re.sub(r'^IPv6:', '', stripped, flags=re.I)
                    bn = normalize_ip(stripped)
                    if looks_like_ip(bn):
                        out['byIp'] = bn
                        out['byHost'] = re.sub(r'^\[|\]$', '', by['value'])
                    else:
                        out['byHost'] = re.sub(r'^\[|\]$', '', by['value'])
                else:
                    out['byHost'] = by['value']
            if by['comment']:
                out['byComment'] = by['comment']
            continue

        if lower == 'via':
            advance()
            via = capture_one_or_comment()
            if via['value']:
                out['viaHost'] = via['value']
            if via['comment']:
                out['viaComment'] = via['comment']
            continue

        if lower == 'with':
            advance()
            w = capture_one_or_comment()
            if w['value']:
                out['withProto'] = w['value']
            if w['comment']:
                out['protoComment'] = w['comment']
            continue

        if lower == 'id':
            advance()
            idt = capture_one_or_comment()
            if idt['value']:
                out['id'] = idt['value']
            continue

        if lower == 'for':
            advance()
            parts = []
            while i[0] < len(tokens) and not tokens[i[0]].startswith('(') and not peek_is_keyword():
                parts.append(tokens[i[0]])
                advance()
            if i[0] < len(tokens) and tokens[i[0]].startswith('('):
                out['forAddr'] = _strip_parens(tokens[i[0]])
                advance()
            elif parts:
                out['forAddr'] = ' '.join(parts)
            continue

        if lower == 'return-path':
            advance()
            advance()
            continue

        out['malformed'].append('unexpected token: ' + tok)
        advance()

    # Derive connection source IP for this hop from the from-clause.
    from_clause = ' '.join(x for x in [out['fromComment'], out['fromHost']] if x)
    ips = extract_ips(from_clause)
    if not out['fromIp'] and ips:
        v4match = next((x['ip'] for x in ips if x['type'] == 'ipv4'), None)
        v6match = next((x['ip'] for x in ips if x['type'] == 'ipv6'), None)
        if v4match:
            out['fromIp'] = v4match
            out['fromIpType'] = 'ipv4'
        elif v6match:
            out['fromIp'] = v6match
            out['fromIpType'] = 'ipv6'

    helo_candidate = None
    if out['fromComment']:
        for tk in out['fromComment'].split():
            tk = re.sub(r'^\[|\]$', '', tk)
            tk = re.sub(r'^IPv6:', '', tk, flags=re.I)
            if not tk:
                continue
            if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', tk):
                continue
            if ':' in tk:
                continue
            if tk == 'unknown' or re.match(r'^(HELO|EHLO)$', tk, re.I):
                continue
            helo_candidate = tk
            break
    if not out['fromHelo']:
        out['fromHelo'] = (helo_candidate or
                           (out['fromHost'] if out['fromHost'] and not _is_bracket_literal(out['fromHost'])
                            and out['fromHost'] != 'unknown' else None))

    if not out['byIp'] and out['byComment']:
        by_ips = extract_ips(out['byComment'])
        if by_ips:
            out['byIp'] = by_ips[0]['ip']

    return out


def parse_all_received(headers):
    return [parse_received(h['value'])
            for h in headers if h.get('name', '').lower() == 'received']


# ---------------------------------------------------------------------------
# Routing analyzer (port of analyzer/routingAnalyzer.js)
# ---------------------------------------------------------------------------

def routing_analyze(headers, hops=None):
    if hops is None:
        hops = parse_all_received(headers)
    hops = list(hops)
    indicators = []
    hop_count = len(hops)

    reversed_hops = list(reversed(hops))
    earliest = reversed_hops[0] if reversed_hops else None

    source = {
        'ip': None, 'ipType': None, 'host': None, 'helo': None, 'ts': None,
        'raw': None, 'privateInfo': None, 'determined': False,
        'confidence': 'unknown', 'reason': None,
    }
    if not earliest:
        source['reason'] = 'No Received headers found in this message.'
        indicators.append(_reg('no-received', 'info', 'No Received headers',
                               'This message contains no Received: header chain, so no routing information is available.'))
    else:
        s_ip = earliest.get('fromIp')
        source['raw'] = earliest.get('raw')
        source['ts'] = earliest.get('timestampDate') or earliest.get('timestamp') or None
        from_host = earliest.get('fromHost')
        source['host'] = earliest.get('fromHelo') or (from_host if (from_host and from_host[0] != '[') else None)
        source['helo'] = earliest.get('fromHelo')
        if s_ip:
            source['ip'] = s_ip
            source['ipType'] = earliest.get('fromIpType') or ip_type(s_ip)
            source['privateInfo'] = private_ip_info(s_ip)
            source['determined'] = True
            source['confidence'] = 'high' if hop_count >= 2 else 'limited'
            source['reason'] = (
                'IP observed in the earliest Received header, logged by the first MTA in the chain.'
                if hop_count >= 2 else
                'Only one Received header present; this IP is what the single receiving MTA logged for the connection '
                '(for webmail this is the provider MTA, not the end-user device).'
            )
        else:
            source['ip'] = None
            source['confidence'] = 'unknown'
            source['determined'] = False
            source['reason'] = (
                'The earliest Received header is malformed/unrecognised and no source IP could be extracted.'
                if earliest.get('malformed') else
                'Insufficient/ambiguous Received headers — the earliest hop does not expose a client IP.'
            )

    if source['ip'] and source['privateInfo'] and source['privateInfo']['isPrivate']:
        indicators.append(_reg('private-source-ip', 'info', 'Private / reserved source IP',
                               'Observed source IP %s is %s. This often indicates an internal hop or a webmail provider queue, not a direct internet sender.'
                               % (source['ip'], source['privateInfo']['description'])))
    if hop_count == 1 and source['ip']:
        indicators.append(_reg('single-hop', 'info', 'Single-hop Received chain',
                               'Only one Received header. The observed IP is the inbound MTA\u2019s record of the submission connection, '
                               'which for Gmail/Outlook/Yahoo is the webmail provider\u2019s server, not your correspondent\u2019s device.'))

    nodes = []
    intermediates = []
    mismatch_flags = 0

    for idx, hop in enumerate(reversed_hops):
        is_last = idx == len(reversed_hops) - 1
        role = 'destination' if is_last else 'mta'

        if idx >= 1:
            prev = reversed_hops[idx - 1]
            prev_by_host = re.sub(r'^\[|\]$', '', prev.get('byHost') or '') or None
            prev_by_ip = prev.get('byIp')
            cur_from_host = re.sub(r'^\[|\]$', '', hop.get('fromHost') or '') or None
            cur_from_ip = hop.get('fromIp')
            host_match = bool(prev_by_host and cur_from_host and
                              normalize_ip(prev_by_host) == normalize_ip(cur_from_host))
            ip_match = bool(prev_by_ip and cur_from_ip and
                            normalize_ip(prev_by_ip) == normalize_ip(cur_from_ip))
            if (prev_by_host or prev_by_ip) and (cur_from_host or cur_from_ip) and not host_match and not ip_match:
                mismatch_flags += 1

        node = {
            'role': role,
            'host': re.sub(r'^\[|\]$', '', hop.get('byHost') or '') or None,
            'ip': hop.get('byIp'),
            'ts': hop.get('timestampDate') or hop.get('timestamp') or '',
            'raw': hop.get('raw'),
            'fromHost': re.sub(r'^\[|\]$', '', hop.get('fromHost') or '') or None,
            'fromIp': hop.get('fromIp'),
            'withProto': hop.get('withProto'),
        }
        nodes.append(node)

        if role == 'mta':
            intermediates.append({
                'position': idx,
                'host': node['host'],
                'ip': node['ip'],
                'fromHost': node['fromHost'],
                'fromIp': node['fromIp'],
                'toHost': (reversed_hops[idx].get('byHost') or '') if idx < len(reversed_hops) else '',
                'ts': node['ts'],
                'raw': node['raw'],
                'malformed': (hop.get('malformed') and len(hop.get('malformed'))) or None,
            })

    destination_host = nodes[-1]['host'] if nodes else None
    destination_ip = nodes[-1]['ip'] if nodes else None

    if mismatch_flags > 0:
        indicators.append(_reg('routing-inconsistency', 'warning' if mismatch_flags >= 2 else 'info',
                               'Routing inconsistency',
                               '%d hop(s) where the connecting host/IP do not clearly match the previous hop\u2019s receiving MTA. '
                               'This can be legitimate (multiple interfaces/helo) or indicate header forgeries.' % mismatch_flags))

    malformed_count = sum(1 for h in hops if h.get('malformed'))
    if malformed_count:
        indicators.append(_reg('malformed-received', 'warning', 'Malformed Received header',
                               '%d Received header(s) could not be fully parsed. Confidence in the chain is reduced. See raw headers.'
                               % malformed_count))

    nodes_for_ui = []
    if source['ip'] or source['host']:
        nodes_for_ui.append({
            'role': 'source',
            'host': source['host'] or 'Unknown',
            'ip': source['ip'] or '',
            'ts': source['ts'] or '',
            'raw': source['raw'],
            'note': (source['privateInfo']['description']
                     if source['ip'] and source['privateInfo'] and source['privateInfo']['isPrivate'] else None),
        })
    nodes_for_ui.extend(nodes)

    return {
        'hopCount': hop_count,
        'source': source,
        'nodes': nodes_for_ui,
        'intermediates': intermediates,
        'destination': {'host': destination_host, 'ip': destination_ip},
        'order': 'newest-first-in-file; reversed-for-analysis',
        'indicators': indicators,
        'parseErrors': malformed_count,
    }


# ---------------------------------------------------------------------------
# Authentication analyzer (port of analyzer/authenticationAnalyzer.js)
# ---------------------------------------------------------------------------

TWO_LEVEL_PUBLIC_SUFFIX = set([
    'com.au', 'org.au', 'net.au', 'edu.au', 'gov.au',
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk',
    'co.in', 'net.in', 'org.in',
    'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'ad.jp', 'ed.jp',
    'co.nz', 'org.nz', 'net.nz', 'govt.nz', 'ac.nz',
    'com.br', 'net.br', 'org.br',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn',
    'com.mx', 'org.mx', 'net.mx', 'gob.mx',
    'co.kr', 'or.kr', 'ne.kr', 're.kr', 'go.kr',
    'com.tw', 'org.tw', 'net.tw', 'edu.tw',
    'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg',
    'co.za', 'org.za', 'net.za', 'gov.za',
    'com.hk', 'org.hk', 'net.hk', 'gov.hk', 'edu.hk',
])


def registrable_domain(host):
    if not host:
        return None
    h = str(host).lower().strip()
    h = re.sub(r'^\[|\]$', '', h)
    h = re.sub(r'^IPv6:', '', h, flags=re.I)
    if not h:
        return None
    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', h) or ':' in h:
        return h
    parts = h.split('.')
    if len(parts) <= 2:
        return h
    sl = parts[-2]
    last = parts[-1]
    count = 2
    if sl + '.' + last in TWO_LEVEL_PUBLIC_SUFFIX and len(parts) >= 3:
        count = 3
    return '.'.join(parts[-count:])


def domain_of(email_or_domain):
    v = str(email_or_domain or '')
    if not v:
        return None
    at = v.rfind('@')
    if at != -1:
        return v[at + 1:].lower()
    return v.lower().strip()


def normalize_result(res):
    return str(res or '').lower().strip()


def status_for_result(result):
    r = normalize_result(result)
    if r == 'pass':
        return 'pass'
    if r == 'fail':
        return 'fail'
    if r in ('softfail', 'neutral', 'policy', 'none'):
        return 'warning'
    if r in ('permerror', 'temperror'):
        return 'unknown'
    if r in ('not_available', '', 'null'):
        return 'na'
    return 'unknown'


def same_base(a, b):
    da = registrable_domain(a)
    db = registrable_domain(b)
    if not da or not db:
        return False
    return da == db


def auth_analyze(headers, auth_results=None, dkim_sigs=None, received_spf=None, hops=None):
    if auth_results is None:
        auth_results = parse_all_authentication_results(headers)
    if dkim_sigs is None:
        dkim_sigs = parse_all_dkim_signatures(headers)
    if received_spf is None:
        received_spf = parse_all_received_spf(headers)
    if hops is None:
        hops = parse_all_received(headers)

    indicators = []
    final_by_host = hops[0].get('byHost') if hops and hops[0].get('byHost') else None

    primary_auth = None
    for ar in auth_results:
        if final_by_host and ar['authservId'] and same_base(ar['authservId'], final_by_host):
            primary_auth = ar
            break
    if not primary_auth and auth_results:
        primary_auth = auth_results[0]

    primary_results = primary_auth['results'] if primary_auth else []

    def find_method(results, method):
        best = None
        for r in results:
            if r.get('method') != method:
                continue
            if not best:
                best = r
            ar = r
            if final_by_host and r.get('authservId') and same_base(r.get('authservId'), final_by_host):
                return r
        return best

    # --- SPF ---------------------------------------------------------------
    spf_entry = find_method(primary_results, 'spf')
    spf_run = {'result': 'not_available', 'status': 'na', 'domain': None, 'clientIp': None,
               'scope': None, 'envelopeFrom': None, 'helo': None, 'comment': None, 'raw': None,
               'source': None, 'clientIpSource': None}
    if spf_entry:
        spf_run['result'] = normalize_result(spf_entry['result'])
        spf_run['status'] = status_for_result(spf_run['result'])
        spf_run['scope'] = spf_entry.get('scope')
        if spf_entry['params'].get('mailfrom'):
            spf_run['envelopeFrom'] = spf_entry['params']['mailfrom']
        if spf_entry['params'].get('helo'):
            spf_run['helo'] = spf_entry['params']['helo']
        if spf_entry['params'].get('clientip'):
            spf_run['clientIp'] = normalize_ip(spf_entry['params']['clientip'])
        spf_run['clientIpSource'] = 'auth-results' if spf_run['clientIp'] else None
        spf_run['comment'] = spf_entry.get('comment')
        spf_run['raw'] = primary_auth['raw']
        if spf_entry['params'].get('mailfrom'):
            spf_run['domain'] = domain_of(spf_entry['params']['mailfrom'])
        elif spf_entry['params'].get('helo'):
            spf_run['domain'] = domain_of(spf_entry['params']['helo'])

    rspf = received_spf[0] if received_spf else None
    if rspf and rspf.get('result'):
        if spf_run['result'] == 'not_available':
            spf_run['result'] = normalize_result(rspf['result'])
            spf_run['status'] = status_for_result(spf_run['result'])
            spf_run['source'] = 'received-spf'
        if not spf_run['clientIp']:
            spf_run['clientIp'] = normalize_ip(rspf.get('clientIp'))
            spf_run['clientIpSource'] = 'received-spf'
        if not spf_run['envelopeFrom']:
            spf_run['envelopeFrom'] = rspf.get('envelopeFrom')
        if not spf_run['helo']:
            spf_run['helo'] = rspf.get('helo')
        if not spf_run['scope']:
            spf_run['scope'] = rspf.get('scope')
        if not spf_run['comment']:
            spf_run['comment'] = rspf.get('comment')
        if not spf_run['raw']:
            spf_run['raw'] = rspf.get('raw')
        if not spf_run['domain']:
            spf_run['domain'] = domain_of(rspf.get('envelopeFrom'))
    if not spf_run['domain'] and spf_run['envelopeFrom']:
        spf_run['domain'] = domain_of(spf_run['envelopeFrom'])

    if not spf_run['clientIp'] and hops:
        fp = hops[-1].get('fromIp')
        if fp:
            spf_run['clientIp'] = normalize_ip(fp)
            spf_run['clientIpSource'] = 'received-chain'

    # --- DKIM --------------------------------------------------------------
    dkim_entry = find_method(primary_results, 'dkim')
    dkim_sig = dkim_sigs[0] if dkim_sigs else None
    dkim_run = {'result': 'not_available', 'status': 'na', 'domain': None, 'selector': None,
                'algorithm': None, 'canonicalization': None, 'comment': None, 'raw': None,
                'source': None, 'signaturePresent': bool(dkim_sig)}
    if dkim_entry:
        dkim_run['result'] = normalize_result(dkim_entry['result'])
        dkim_run['status'] = status_for_result(dkim_run['result'])
        dkim_run['source'] = 'auth-results'
        dk_dom = dkim_entry['params'].get('headerd') or dkim_entry['params'].get('headeri')
        if dk_dom:
            dk_dom = str(dk_dom).lstrip('@').lower()
            if dk_dom:
                dkim_run['domain'] = dk_dom
        dkim_run['selector'] = dkim_entry['params'].get('headers')
        dkim_run['comment'] = dkim_entry.get('comment')
        dkim_run['raw'] = primary_auth['raw']
    if dkim_sig:
        if dkim_run['result'] == 'not_available':
            dkim_run['raw'] = dkim_sig['raw']
        dkim_run['domain'] = dkim_run['domain'] or dkim_sig['domain']
        dkim_run['selector'] = dkim_run['selector'] or dkim_sig['selector']
        dkim_run['algorithm'] = dkim_sig['algorithm']
        dkim_run['canonicalization'] = dkim_sig['canonicalization']
    if dkim_run['result'] == 'not_available' and dkim_sig:
        dkim_run['status'] = 'unknown'

    # --- DMARC -------------------------------------------------------------
    dmarc_entry = find_method(primary_results, 'dmarc')
    dmarc_run = {'result': 'not_available', 'status': 'na', 'policy': None, 'domain': None,
                 'spfAlignment': None, 'dkimAlignment': None, 'comment': None, 'raw': None}
    if dmarc_entry:
        dmarc_run['result'] = normalize_result(dmarc_entry['result'])
        dmarc_run['status'] = status_for_result(dmarc_run['result'])
        dmarc_run['domain'] = domain_of(dmarc_entry['params'].get('headerfrom') or '')
        dmarc_run['policy'] = dmarc_entry.get('policy')
        dmarc_run['comment'] = dmarc_entry.get('comment')
        dmarc_run['raw'] = primary_auth['raw']
        if not dmarc_run['policy']:
            pm = re.search(r'(?:^|\s)p\s*=\s*([a-z]+)', (dmarc_entry.get('comment') or ''), re.I)
            if pm:
                dmarc_run['policy'] = pm.group(1).lower()

    from_domain = None
    try:
        from_addr = parse_address(get_first(headers, 'from'))
        if from_addr and from_addr.get('domain'):
            from_domain = from_addr['domain'].lower()
    except Exception:
        pass

    if dmarc_run['domain'] or from_domain:
        eval_domain = dmarc_run['domain'] or from_domain
        spf_dom = spf_run['domain']
        dkim_dom = dkim_run['domain']
        dmarc_run['spfAlignment'] = ('pass' if same_base(spf_dom, eval_domain) else 'fail') if spf_dom else None
        dmarc_run['dkimAlignment'] = ('pass' if same_base(dkim_dom, eval_domain) else 'fail') if dkim_dom else None
        if not dmarc_run['domain']:
            dmarc_run['domain'] = eval_domain

    declarations = [{
        'authservId': ar['authservId'],
        'raw': ar['raw'],
        'results': [{'method': r['method'], 'result': normalize_result(r['result']),
                     'params': r['params'], 'comment': r.get('comment'),
                     'reason': r.get('reason')} for r in ar['results']],
    } for ar in auth_results]

    # --- Indicators --------------------------------------------------------
    if spf_run['result'] == 'fail':
        indicators.append(_reg('spf-failure', 'warning', 'SPF FAIL',
                               'SPF check failed for %s. The sending host is not authorized by the domain policy.' % (spf_run['domain'] or 'the message')))
    if dkim_run['result'] == 'fail':
        indicators.append(_reg('dkim-failure', 'warning', 'DKIM FAIL',
                               'DKIM signature verification failed for %s.' % (dkim_run['domain'] or 'the message')))
    if dmarc_run['result'] == 'fail':
        indicators.append(_reg('dmarc-failure', 'warning', 'DMARC FAIL',
                               'DMARC alignment/verification failed for %s.' % (dmarc_run['domain'] or 'the message')))
    if spf_run['result'] in ('softfail', 'neutral'):
        indicators.append(_reg('spf-soft', 'info', 'SPF not definitive',
                               'SPF result is %s — not a hard failure but not an authorization either.' % spf_run['result'].upper()))
    if not auth_results:
        indicators.append(_reg('missing-auth-results', 'warning', 'No Authentication-Results',
                               'The message has no Authentication-Results header, so no DKIM/SPF/DMARC verdicts from the receiving provider are available.'))
    if dkim_sig and dkim_run['result'] == 'not_available':
        indicators.append(_reg('dkim-unverified', 'info', 'DKIM signature not verified',
                               'A DKIM-Signature header exists (d=%s, s=%s) but no auth service verified it.'
                               % (dkim_sig.get('domain') or '?', dkim_sig.get('selector') or '?')))
    if len(auth_results) >= 2:
        indicators.append(_reg('multiple-auth-results', 'info', 'Multiple Authentication-Results',
                               '%d Authentication-Results headers present — check all declarations in the raw headers.' % len(auth_results)))
    if final_by_host and primary_auth and primary_auth['authservId'] and not same_base(primary_auth['authservId'], final_by_host):
        indicators.append(_reg('authserv-mismatch', 'info', 'Auth service / final MTA mismatch',
                               'The primary auth service "%s" does not share a base domain with the final receiving MTA "%s".'
                               % (primary_auth['authservId'], final_by_host)))
    indicators.append({
        'id': 'dmarc-policy-report',
        'severity': 'info',
        'title': 'DMARC policy: ' + (dmarc_run['policy'] or 'not stated'),
        'message': ('A DMARC record policy of "%s" applies to %s.' % (dmarc_run['policy'].upper(), dmarc_run['domain'] or 'the From domain')
                    if dmarc_run['policy'] else
                    'No explicit DMARC policy was reported by the receiving provider.'),
    })

    return {
        'spf': spf_run,
        'dkim': dkim_run,
        'dmarc': dmarc_run,
        'declarations': declarations,
        'indicators': indicators,
        'finalByHost': final_by_host,
        'primaryAuthservId': primary_auth['authservId'] if primary_auth else None,
    }


# ---------------------------------------------------------------------------
# Sender / mismatch analyzer (port of analyzer/mismatchAnalyzer.js)
# ---------------------------------------------------------------------------

UA_HEADERS = ['user-agent', 'x-mailer', 'x-mimeole', 'x-mail-user-agent']


def _addr_text(addr):
    if not addr:
        return None
    if addr.get('displayName') and addr.get('email'):
        return '%s <%s>' % (addr['displayName'], addr['email'])
    return addr.get('email') or addr.get('displayName')


def sender_analyze(headers):
    indicators = []
    from_addr = parse_address(get_first(headers, 'from'))
    sender_addr = parse_address(get_first(headers, 'sender'))
    reply_list = parse_address_list(get_first(headers, 'reply-to'))
    reply_to = reply_list['addresses'][0] if reply_list['addresses'] else None

    return_path_raw = get_first(headers, 'return-path')
    return_path = None
    if (return_path_raw is not None and return_path_raw.strip() not in ('', '<>')
            and '<>' not in return_path_raw.lower()):
        return_path = parse_address(return_path_raw)

    ua_values = []
    for h in UA_HEADERS:
        for v in get_all(headers, h):
            v = v.strip()
            if v and v not in ua_values:
                ua_values.append(v)
    user_agent = ' \u00b7 '.join(ua_values) if ua_values else None

    differences = []
    from_display = _addr_text(from_addr) or 'Not available'

    def diff(kind, sev, title, message):
        differences.append({'kind': kind, 'severity': sev, 'title': title, 'message': message})

    if from_addr and reply_to and not same_address(from_addr, reply_to):
        diff('from-replyto', 'info', 'From / Reply-To difference',
             'From: %s  \u2192  Reply-To: %s. Replies to this message would go to a different address. '
             'This is common in newsletters and legitimate mailing setups, but is also used in scams.'
             % (from_display, _addr_text(reply_to)))
    if from_addr and return_path and not same_address(from_addr, return_path):
        diff('from-returnpath', 'info', 'From / Return-Path difference',
             'From: %s  \u2192  Return-Path: %s. Bounces would be sent to a different address than the visible From. '
             'Legitimate (e.g. mailing lists) or suspicious depending on context.' % (from_display, _addr_text(return_path)))
    if sender_addr and from_addr and not same_address(from_addr, sender_addr) and _addr_text(sender_addr) != '<>':
        diff('from-sender', 'info', 'From / Sender difference',
             'The RFC2224 "Sender:" header (%s) differs from "From:" (%s). '
             'Legal for mailing-list software; also a spoofing technique.' % (_addr_text(sender_addr), from_display))
    if reply_to and return_path and not same_address(reply_to, return_path):
        diff('replyto-returnpath', 'info', 'Reply-To / Return-Path difference',
             'Reply-To (%s) and Return-Path (%s) differ.' % (_addr_text(reply_to), _addr_text(return_path)))

    if from_addr and reply_to and not same_address(from_addr, reply_to):
        indicators.append(_reg('from-replyto-mismatch', 'warning', 'Reply-To mismatch',
                               'Reply-To points to %s instead of the From address %s.'
                               % ((reply_to.get('email') or 'a different address'), from_addr['email'])))
    if from_addr and return_path and not same_address(from_addr, return_path):
        indicators.append(_reg('from-returnpath-mismatch', 'info', 'Return-Path differs from From',
                               'Return-Path (%s) does not match From (%s).'
                               % ((return_path.get('email') or 'unknown'), from_addr['email'])))
    if not ua_values:
        indicators.append(_reg('missing-user-agent', 'info', 'No User-Agent / mailer header',
                               'No User-Agent, X-Mailer, X-MimeOLE or X-Mail-User-Agent header present. '
                               'This says nothing about the sender\u2019s browser/OS.'))

    raw_from = get_first(headers, 'from') or ''
    encoded_from = bool(re.search(r'=\?[^?]+\?[bBqQ]\?', raw_from)) or \
        bool(from_addr and from_addr.get('email') and re.search(r'=\?[^?]+\?[bBqQ]\?', from_addr.get('email') or ''))
    if encoded_from:
        indicators.append(_reg('obfuscated-display', 'info', 'Encoded display name',
                               'The From display name uses RFC 2047 encoding (often used to disguise spoofed names).'))

    return {
        'from': from_addr,
        'sender': sender_addr,
        'replyTo': reply_to,
        'replyToList': reply_list['addresses'],
        'returnPath': return_path,
        'returnPathRaw': return_path_raw,
        'to': parse_address_list(get_first(headers, 'to'))['addresses'],
        'cc': parse_address_list(get_first(headers, 'cc'))['addresses'],
        'date': get_first(headers, 'date'),
        'subject': get_first(headers, 'subject'),
        'messageId': get_first(headers, 'message-id'),
        'userAgent': user_agent,
        'uaValues': ua_values,
        'differences': differences,
        'indicators': indicators,
    }


# ---------------------------------------------------------------------------
# Report builder (mirror of content/app.js buildReport)
# ---------------------------------------------------------------------------

def build_report(parsed, source='eml-file'):
    headers = parsed['headers']
    auth_results = parse_all_authentication_results(headers)
    dkim_sigs = parse_all_dkim_signatures(headers)
    received_spf = parse_all_received_spf(headers)
    hops = parse_all_received(headers)

    auth = auth_analyze(headers, auth_results, dkim_sigs, received_spf, hops)
    routing = routing_analyze(headers, hops)
    sender = sender_analyze(headers)

    content = parse_mime(parsed.get('raw') or '')

    raw = parsed.get('raw') or ''
    blank = raw.find('\n\n')
    if blank == -1:
        blank = raw.find('\r\n\r\n')
    raw_header_block = raw[:blank].strip() if blank != -1 else ''

    indicators = auth['indicators'] + routing['indicators'] + sender['indicators']

    def _addr_json(a):
        if not a:
            return None
        return {'displayName': a.get('displayName'), 'email': a.get('email'), 'domain': a.get('domain')}

    report = {
        'meta': {
            'tool': 'Email Header Analyzer',
            'version': VERSION,
            'analyzedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'source': source,
            'fileName': parsed.get('filename'),
            'messageId': sender['messageId'],
        },
        'authentication': {
            'spf': {k: spf_v(k, auth['spf']) for k in
                    ('status', 'result', 'domain', 'clientIp', 'scope', 'envelopeFrom', 'helo', 'clientIpSource', 'source')},
            'dkim': {k: auth['dkim'].get(k) for k in
                     ('status', 'result', 'domain', 'selector', 'algorithm', 'canonicalization', 'signaturePresent', 'source')},
            'dmarc': {k: auth['dmarc'].get(k) for k in
                      ('status', 'result', 'policy', 'domain', 'spfAlignment', 'dkimAlignment')},
            'declarations': auth['declarations'],
            'primaryAuthservId': auth['primaryAuthservId'],
        },
        'sender': {
            'from': _addr_json(sender['from']),
            'senderAddr': _addr_json(sender['sender']),
            'replyTo': _addr_json(sender['replyTo']),
            'returnPath': _addr_json(sender['returnPath']),
            'to': [_addr_json(a) for a in sender['to']],
            'cc': [_addr_json(a) for a in sender['cc']],
            'date': sender['date'],
            'subject': sender['subject'],
            'messageId': sender['messageId'],
            'userAgent': sender['userAgent'],
        },
        'routing': {
            'sourceIp': routing['source'].get('ip') or None,
            'sourceHost': routing['source'].get('host') or None,
            'sourceHelo': routing['source'].get('helo'),
            'confidence': routing['source'].get('confidence'),
            'reason': routing['source'].get('reason'),
            'destination': routing['destination'],
            'hopCount': routing['hopCount'],
        },
        'mailFlow': [
            {'role': n['role'], 'host': n.get('host'), 'ip': n.get('ip'), 'timestamp': n.get('ts')}
            for n in routing['nodes']
        ],
        'capsules': {
            'auth': auth,
            'routing': routing,
            'sender': sender,
        },
        'content': content,
        'warnings': indicators,
        'rawHeaders': raw_header_block,
    }
    return report


def spf_v(k, d):
    if k == 'status':
        return d.get('status')
    if k == 'clientIp':
        return d.get('clientIp')
    if k == 'clientIpSource':
        return d.get('clientIpSource')
    return d.get(k)


def load_and_analyze(path):
    parsed = parse_eml(path)
    return build_report(parsed)


def analyze_raw(raw_text, filename=None):
    """Analyze raw message text directly (no file I/O). Useful for tests."""
    return build_report({'headers': parse_header_list(raw_text),
                         'raw': raw_text, 'filename': filename})


# ---------------------------------------------------------------------------
# Text/JSON export of the report
# ---------------------------------------------------------------------------

def analysis_text(report):
    L = []
    L.append('EMAIL HEADER ANALYZER — export')
    L.append('Analyzed: %s' % report['meta']['analyzedAt'])
    L.append('Message-ID: %s' % (report['meta']['messageId'] or 'n/a'))
    L.append('')
    L.append('AUTHENTICATION')
    spf = report['authentication']['spf']
    dkim = report['authentication']['dkim']
    dmarc = report['authentication']['dmarc']
    L.append('  SPF   : %s  domain=%s%s' % (
        (spf['result'] or 'n/a').upper(), spf.get('domain') or 'n/a',
        '  client-ip=' + spf['clientIp'] if spf.get('clientIp') else ''))
    L.append('  DKIM  : %s  d=%s%s' % (
        (dkim['result'] or 'n/a').upper(), dkim.get('domain') or 'n/a',
        '  s=' + dkim['selector'] if dkim.get('selector') else ''))
    L.append('  DMARC : %s  p=%s  domain=%s' % (
        (dmarc['result'] or 'n/a').upper(), dmarc.get('policy') or 'n/a', dmarc.get('domain') or 'n/a'))
    L.append('')
    L.append('SENDER')
    L.append('  From        : %s' % _addr_json_line(report['sender']['from']))
    L.append('  Reply-To    : %s' % _addr_json_line(report['sender']['replyTo']))
    L.append('  Return-Path : %s' % _addr_json_line(report['sender']['returnPath']))
    L.append('  Source IP   : %s' % (report['routing']['sourceIp'] or 'Unknown'))
    L.append('  Source Host : %s' % (report['routing']['sourceHost'] or 'Unknown'))
    L.append('  User Agent  : %s' % (report['sender']['userAgent'] or 'Not available'))
    L.append('')
    content = report.get('content') or {}
    L.append('CONTENT')
    L.append('  Type  : %s' % (content.get('contentType') or 'not determined'))
    attachments = content.get('attachments') or []
    if attachments:
        L.append('  Attachments (%d):' % len(attachments))
        for a in attachments:
            L.append('    \u2022 %s%s%s%s' % (
                a.get('filename') or '(unnamed)',
                '  (%s)' % _fmt_bytes(a.get('size')) if a.get('size') else '',
                '  ' + (a.get('mediaType') or '') if a.get('mediaType') else '',
                '  [' + a['disposition'] + ']' if a.get('disposition') else ''))
    else:
        L.append('  Attachments: none')
    links = content.get('links') or []
    if links:
        L.append('  Links (%d):' % len(links))
        for l in links:
            L.append('    \u2022 %s' % l)
    else:
        L.append('  Links: none')
    L.append('')
    L.append('MAIL FLOW')
    if report['mailFlow']:
        for i, n in enumerate(report['mailFlow']):
            L.append('  [%s] %s%s%s' % (
                n['role'], n.get('host') or '?', '  ' + (n.get('ip') or '') if n.get('ip') else '',
                '  ' + str(n['timestamp']) if n.get('timestamp') else ''))
            if i < len(report['mailFlow']) - 1:
                L.append('     \u2193')
    else:
        L.append('  not reconstructed')
    L.append('')
    L.append('INDICATORS')
    if report['warnings']:
        for w in report['warnings']:
            L.append('  [%s] %s — %s' % (str(w['severity']).upper(), w['title'], w['message']))
    else:
        L.append('  none')
    return '\n'.join(L)


def _addr_json_line(a):
    if not a:
        return 'n/a'
    return ('%s <%s>' % (a['displayName'], a['email'])) if a.get('displayName') else a['email']


def _fmt_bytes(n):
    n = int(n or 0)
    if n < 1024:
        return '%d B' % n
    if n < 1048576:
        return '%.1f KB' % (n / 1024)
    return '%.2f MB' % (n / 1048576)


def _reg(i, severity, title, message):
    return {'id': i, 'severity': severity, 'title': title, 'message': message}