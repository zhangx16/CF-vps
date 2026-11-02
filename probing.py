"""Bounded HTTPS observations. Evidence describes responses, never proves Reality."""
import asyncio
import ipaddress
import re
import socket
import ssl
import time

PRIMARY_SNI = 'www.cloudflare.com'
VERIFY_SNI = 'one.one.one.one'
TRACE_PATH = '/cdn-cgi/trace'
_CTX = None


def ssl_context():
    global _CTX
    if _CTX is None:
        _CTX = ssl.create_default_context()
        _CTX.check_hostname = False
        _CTX.verify_mode = ssl.CERT_NONE
        _CTX.set_alpn_protocols(['http/1.1'])
    return _CTX


def parse_trace_body(text):
    values = {}
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        if sep and key.strip() in ('fl', 'colo', 'loc', 'h', 'ip'):
            values[key.strip()] = value.strip()
    return values


def valid_trace(status, trace, sni):
    try:
        ipaddress.ip_address(trace.get('ip', ''))
    except ValueError:
        return False
    return (status == 200 and bool(trace.get('fl'))
            and bool(re.fullmatch('[A-Z]{3}', trace.get('colo', '')))
            and bool(re.fullmatch('[A-Z]{2}', trace.get('loc', '')))
            and trace.get('h', '').lower().rstrip('.') == sni.lower().rstrip('.'))


async def observe(ip, port, sni, timeout):
    start = time.monotonic()
    writer = None
    sock = None
    stage = 'connect'
    result = dict(is_cf=False, trace_valid=False, server='', cf_ray='', trace={},
                  http_status=None, err='', error_kind='', request_ms=None,
                  connect_ms=None, tls_ms=None, ttfb_ms=None, head='')

    async def exchange():
        nonlocal writer, sock, stage
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        await asyncio.get_running_loop().sock_connect(sock, (ip, port))
        connected = time.monotonic()
        result['connect_ms'] = round((connected - start) * 1000, 1)
        stage = 'tls'
        reader, writer = await asyncio.open_connection(sock=sock, ssl=ssl_context(), server_hostname=sni, limit=65536)
        sock = None  # The transport now owns the socket.
        result['tls_ms'] = round((time.monotonic() - connected) * 1000, 1)
        stage = 'http'
        writer.write((f'GET {TRACE_PATH} HTTP/1.1\r\nHost: {sni}\r\n'
                      'User-Agent: cf-vps/2.0\r\nAccept: */*\r\nAccept-Encoding: identity\r\n'
                      'Connection: close\r\n\r\n').encode())
        await writer.drain()
        first = await reader.readexactly(1)
        result['ttfb_ms'] = round((time.monotonic() - start) * 1000, 1)
        head = first + await reader.readuntil(b'\r\n\r\n')
        if len(head) > 65536:
            raise ValueError('HTTP headers too large')
        text = head.decode('latin1')
        status_line = text.split('\r\n', 1)[0]
        if not re.fullmatch(r'HTTP/1\.[01] [0-9]{3}(?: .*)?', status_line):
            raise ValueError('Invalid HTTP status')
        result['http_status'] = int(status_line.split(' ', 2)[1])
        headers = {}
        for line in text.split('\r\n')[1:]:
            key, sep, value = line.partition(':')
            if sep:
                headers[key.lower()] = value.strip()
        body = bytearray()
        if 'chunked' in headers.get('transfer-encoding', '').lower():
            for _ in range(4096):
                size = int((await reader.readuntil(b'\r\n')).split(b';')[0], 16)
                if size == 0:
                    break
                if not 0 <= size <= 65536 - len(body):
                    raise ValueError('Response too large')
                body.extend(await reader.readexactly(size))
                if await reader.readexactly(2) != b'\r\n':
                    raise ValueError('Invalid chunk framing')
            else:
                raise ValueError('Too many chunks')
        elif 'content-length' in headers:
            size = int(headers['content-length'])
            if not 0 <= size <= 65536:
                raise ValueError('Response too large')
            body.extend(await reader.readexactly(size))
        else:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > 65536:
                    raise ValueError('Response too large')
        result.update(server=headers.get('server', ''), cf_ray=headers.get('cf-ray', ''),
                      trace=parse_trace_body(body.decode('utf-8', 'ignore')), head=text)
        result['trace_valid'] = valid_trace(result['http_status'], result['trace'], sni)
        result['is_cf'] = (result['trace_valid'] or 'cloudflare' in result['server'].lower() or bool(result['cf_ray'])
                           or ('colo' in result['trace'] and 'fl' in result['trace']))

    try:
        await asyncio.wait_for(exchange(), timeout)
    except asyncio.TimeoutError:
        result.update(err='TimeoutError', error_kind=f'{stage}_timeout')
    except ConnectionRefusedError:
        result.update(err='ConnectionRefusedError', error_kind='connection_refused')
    except ssl.SSLError as exc:
        result.update(err=type(exc).__name__, error_kind='tls_error')
    except (ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
        result.update(err=type(exc).__name__, error_kind=f'{stage}_error')
    except OSError as exc:
        result.update(err=type(exc).__name__, error_kind=f'{stage}_error')
    finally:
        result['request_ms'] = round((time.monotonic() - start) * 1000, 1)
        if sock is not None:
            sock.close()
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 0.25)
            except (Exception, asyncio.CancelledError):
                pass
    return result


async def probe_once(ip, port, sni, timeout):
    """Legacy tuple interface retained for the original CLI."""
    r = await observe(ip, port, sni, timeout)
    return r['is_cf'], r['server'], r['cf_ray'], r['trace'], r['head'], r['err'], r['request_ms'] if not r['err'] else ''


async def probe(ip, port, timeout, sem, attempts=1, pace=None, stopping=None):
    async def request(sni):
        observation = None
        for attempt in range(attempts):
            if stopping and stopping():
                raise asyncio.CancelledError()
            if attempt:
                await asyncio.sleep(min(0.25 * 2 ** (attempt - 1), 2))
            if pace:
                await pace()
            observation = await observe(ip, port, sni, timeout)
            if not observation['err'] or observation['error_kind'] == 'connection_refused':
                break
        return observation

    async with sem:
        first = await request(PRIMARY_SNI)
        result = dict(ip=ip, port=port, status='hit' if first['is_cf'] else 'closed_or_error' if first['err'] else 'open_not_cf',
                      evidence='suspected' if first['is_cf'] else 'none', server=first['server'], cf_ray=first['cf_ray'],
                      colo=first['trace'].get('colo', ''), loc=first['trace'].get('loc', ''),
                      trace_ip=first['trace'].get('ip', ''), verified='', verification='not_run',
                      latency_ms=first['request_ms'] if not first['err'] else '', request_ms=first['request_ms'],
                      connect_ms=first['connect_ms'], tls_ms=first['tls_ms'], ttfb_ms=first['ttfb_ms'],
                      http_status=first['http_status'], err=first['err'], error_kind=first['error_kind'])
        if first['trace_valid']:
            result['evidence'] = 'trace_valid'
        if first['is_cf']:
            second = await request(VERIFY_SNI)
            result.update(verify_cf_ray=second['cf_ray'], verify_colo=second['trace'].get('colo', ''),
                          verify_error=second['error_kind'], verify_http_status=second['http_status'])
            if second['err']:
                result['verification'] = 'error'
            elif first['trace_valid'] and second['trace_valid']:
                result.update(evidence='dual_verified', verified='1', verification='confirmed')
            else:
                result.update(verified='0', verification='not_confirmed')
        return result
