"""Single host registry and read-only conversation evidence (R06 A/H).

Only public user/assistant messages are read. Configuration and credentials are
never opened. A generated receipt is never evidence that a card was delivered.
"""
import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import time


# entry_root is the native harness root; the installer adds skills/<plugin>.
# An unknown/unverified discovery root is deliberately not guessed.
HOSTS = {
    'codex': {'entry_root': None, 'session_root': '.codex/sessions', 'adapter': 'codex', 'entry_enabled': False},
    'pi': {'entry_root': '.pi/agent', 'env': 'PI_CODING_AGENT_DIR', 'session_root': '.pi/agent/sessions', 'adapter': 'pi', 'entry_enabled': True},
    'deepseek-harness': {'entry_root': '.dsh', 'env': 'DSH_HOME', 'session_root': '.dsh/sessions', 'adapter': None, 'entry_enabled': True},
    'claude-code': {'label': 'Claude Desktop（Claude Code）', 'aliases': ('claude',), 'entry_root': '.claude', 'env': 'CLAUDE_CONFIG_DIR', 'session_root': '.claude/projects', 'adapter': 'claude', 'entry_enabled': False},
    'opencode': {'entry_root': '.config/opencode', 'session_root': None, 'adapter': None, 'entry_enabled': False},
    'cursor-cli': {'entry_root': '.cursor', 'session_root': None, 'adapter': None, 'entry_enabled': False},
    'qoder': {'entry_root': '.qoder', 'session_root': None, 'adapter': None, 'entry_enabled': False},
    'qoder-cn': {'entry_root': '.qoder-cn', 'session_root': None, 'adapter': None, 'entry_enabled': False},
    **{name: {'entry_root': None, 'session_root': None, 'adapter': None, 'entry_enabled': False}
       for name in ('grok', 'hermes', 'omp', 'antigravity', 'kiro-cli', 'codebuddy', 'kimi-code', 'workbuddy', 'zcode')},
}


def entry_specs():
    return tuple((name, row['entry_root'], row.get('env')) for name, row in HOSTS.items()
                 if row['entry_enabled'] and row['entry_root'])


def current_host():
    # A harness hint selects a parser, never permission to skip verification.
    name = os.environ.get('STARSKY_HOST_ID') or os.environ.get('CODEXHOST_HARNESS_ID') or (
        'claude-code' if os.environ.get('CLAUDE_CODE_SESSION_ID') else 'codex')
    return next((key for key, row in HOSTS.items() if name in row.get('aliases', ())), name)


def _session_root(harness):
    row = HOSTS.get(harness, {})
    if not row.get('session_root') or not row.get('adapter'):
        return None
    if harness == 'codex':
        return Path(os.environ.get('CODEX_HOME', Path.home() / '.codex')) / 'sessions'
    if row.get('env') and os.environ.get(row['env']):
        return Path(os.environ[row['env']]) / ('projects' if harness == 'claude-code' else 'sessions')
    return Path.home() / row['session_root']


def _rows(path):
    rows = []
    with path.open(encoding='utf-8-sig') as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except (ValueError, TypeError):
                # Concurrently written trailing fragments are not evidence.
                if not line.endswith('\n'):
                    break
                raise ValueError('会话记录中间存在无效 JSON，暂不核对步骤卡')
    return rows


def _text(content):
    if isinstance(content, str):
        return content
    return '\n'.join(str(part.get('text', '')) for part in (content or [])
                     if isinstance(part, dict) and part.get('type') in {'text', 'output_text', 'input_text'})


def _timestamp_ns(value):
    try:
        if isinstance(value, (int, float)):
            return int(value * (1_000_000 if value > 1e12 else 1_000_000_000))
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return int(parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).timestamp() * 1_000_000_000)
    except (TypeError, ValueError, OverflowError):
        return None


def _covers(root, cwd, session_id):
    """The conversation may read this case: the case sits inside its working folder, or it is a new case the
    same conversation created right beside that folder (Codex opened inside an older case, user asked for a
    new one, 3.0.23 test). A neighbour counts only when its own workflow_state.yaml already names this
    conversation; a shared parent folder alone proves nothing."""
    root, cwd = Path(root).resolve(), Path(cwd).resolve()
    if root.is_relative_to(cwd):
        return True
    if not session_id or root.parent != cwd.parent:
        return False
    try:
        return session_id in (root / 'workflow_state.yaml').read_text(encoding='utf-8-sig')
    except OSError:
        return False


def _session(root):
    """(harness, path, rows, identity) of the current conversation's own transcript, or None."""
    harness = current_host()
    directory = _session_root(harness)
    if directory is None or not directory.is_dir():
        return None
    session_id = (os.environ.get('STARSKY_SESSION_ID') or
                  (os.environ.get('CODEX_THREAD_ID') if harness == 'codex' else None) or
                  (os.environ.get('CLAUDE_CODE_SESSION_ID') if harness == 'claude-code' else None))
    # A shared cwd and a recent mtime do not identify the active conversation.
    # Pi callers without a verified native ID use the current Host thread below.
    if not session_id:
        return None
    candidates = directory.rglob(session_id + '.jsonl' if harness == 'claude-code' else '*' + session_id + '*.jsonl')
    for path in sorted(candidates, key=lambda p: p.stat().st_mtime_ns, reverse=True):
        if path.is_symlink():
            continue
        rows = _rows(path)
        if not rows: continue
        header = next((row for row in rows if row.get('cwd')), {}) if harness == 'claude-code' else rows[0]
        meta = header.get('payload', {}) if harness == 'codex' else header
        cwd = meta.get('cwd')
        if not cwd or not _covers(root, cwd, session_id):
            continue
        identity = (meta.get('sessionId') or path.stem) if harness == 'claude-code' else meta.get('id') or meta.get('session_id')
        if identity != session_id:
            continue
        if harness == 'claude-code' and any(row.get('sessionId') not in {None, session_id} for row in rows):
            continue
        return harness, path, rows, identity
    return None


_WALL = re.compile(r'^Wall time: [\d.]+ seconds\nOutput:\n?')


def _output_text(output):
    if isinstance(output, list):
        output = '\n'.join(str(part.get('text', '')) for part in output if isinstance(part, dict) and 'text' in part)
    elif isinstance(output, dict):
        output = json.dumps(output, ensure_ascii=False)
    return _WALL.sub('', str(output if output is not None else ''))


# ───────────────────────── Codex code mode ─────────────────────────
# Codex desktop with code mode runs every MCP call inside an `exec` script (`await tools.mcp__<server>__<tool>(args)`).
# The rollout then holds a `custom_tool_call` (the script, recorded by the host) and a `custom_tool_call_output`
# (whatever the script printed with text()). The reply is NOT the host's raw tool result: the model chose what to print.
# So a code-mode reply is archived only when the recorded script provably prints nothing but the call's own result;
# anything else is reported as "called, reply not attributable" and never as a verified reply.

class _Dynamic(Exception):
    """A script construct this reader does not evaluate."""


_JS_ESCAPES = {'n': '\n', 't': '\t', 'r': '\r', 'b': '\b', 'f': '\f', 'v': '\v', '0': '\0'}
_JS_CALL = re.compile(r'\btools\s*\.\s*(mcp__[A-Za-z0-9_\-]+)\s*\(')
# This is a small accepting grammar, not a JavaScript evaluator. Every token must
# belong to a supported statement. Unknown syntax invalidates the ENTIRE script,
# including earlier prints: later declarations can shadow/hoist host builtins.
_JS_RESERVED = set(('await break case catch class const continue debugger default delete do else enum export extends '
                    'false finally for function if import in instanceof let new null return super switch this throw '
                    'true try typeof var void while with yield implements interface package private protected public '
                    'static arguments eval tools text JSON Promise undefined NaN Infinity').split())
_JS_TOOL_NAME = re.compile(r'mcp__[A-Za-z0-9_-]+__[A-Za-z0-9_]+\Z')


def _split_tool(name):
    # Claude's magpie transport wraps a complete MCP name. Do not guess a name
    # from a shortened prefix/hash: there is no reversible tool registry here.
    if name.startswith('mcp__magpie__'):
        name = name[len('mcp__magpie__'):]
    if (not _JS_TOOL_NAME.fullmatch(name) or
            re.search(r'(?:__|_)[0-9a-fA-F]{8,}(?:__|$)', name)):
        return None, None
    server, tool = name[5:].split('__', 1)
    if '__' in tool:
        return None, None
    return server, tool


def _js_ws(text, i):
    while i < len(text):
        if text[i] in ' \t\r\n\v\f﻿  ':
            i += 1
        elif text.startswith('//', i):
            j = text.find('\n', i)
            i = len(text) if j < 0 else j + 1
        elif text.startswith('/*', i):
            j = text.find('*/', i + 2)
            if j < 0:
                raise _Dynamic('unterminated_comment')
            i = j + 2
        else:
            break
    return i


def _js_string(text, i):
    quote, out = text[i], []
    i += 1
    while i < len(text):
        ch = text[i]
        if ch == quote:
            return ''.join(out), i + 1
        if ch == '\\':
            nxt = text[i + 1:i + 2]
            if nxt in ('u', 'x'):
                size = 4 if nxt == 'u' else 2
                raw = text[i + 2:i + 2 + size]
                if len(raw) != size or not re.fullmatch('[0-9a-fA-F]+', raw):
                    raise _Dynamic('unsupported_escape')
                code = int(raw, 16)
                if 0xD800 <= code <= 0xDFFF:
                    raise _Dynamic('unsupported_escape')
                out.append(chr(code))
                i += size + 2
                continue
            if nxt not in _JS_ESCAPES and nxt not in ('\\', '"', "'", '`', '$'):
                raise _Dynamic('unsupported_escape')
            if nxt == '0' and text[i + 2:i + 3].isdigit():
                raise _Dynamic('unsupported_escape')
            out.append(_JS_ESCAPES.get(nxt, nxt))
            i += 2
            continue
        if (quote == '`' and text.startswith('${', i)) or ch in '\r\n  ':
            raise _Dynamic('unsupported_string')
        out.append(ch)
        i += 1
    raise _Dynamic('unterminated_string')


class _CodeModeParser:
    def __init__(self, source):
        self.source, self.i = source, 0
        self.env, self.results, self.groups = {}, {}, {}
        self.names, self.calls, self.plan = set(), [], []

    def match(self, pattern):
        self.i = _js_ws(self.source, self.i)
        hit = re.match(pattern, self.source[self.i:])
        if hit:
            self.i += hit.end()
        return hit

    def expect(self, pattern):
        hit = self.match(pattern)
        if not hit:
            raise _Dynamic('unsupported_syntax')
        return hit

    def name(self):
        return self.expect(r'[A-Za-z_$][A-Za-z0-9_$]*').group()

    def reserve(self, name):
        if name in _JS_RESERVED or name in self.names:
            raise _Dynamic('reserved_or_rebound_name')
        self.names.add(name)

    def end_statement(self):
        before = self.i
        self.i = _js_ws(self.source, self.i)
        if self.match(';') or self.i == len(self.source) or self.source[self.i:self.i + 1] == '}':
            return
        # Only unambiguous ASI between supported statements. Expressions cannot
        # continue here; the next statement still must be consumed in full.
        if '\n' in self.source[before:self.i] or '\r' in self.source[before:self.i]:
            return
        raise _Dynamic('unsupported_syntax')

    def value(self):
        self.i = _js_ws(self.source, self.i)
        ch = self.source[self.i:self.i + 1]
        if ch in ('"', "'", '`'):
            value, self.i = _js_string(self.source, self.i)
            return value
        if self.match(r'\{'):
            out = {}
            if self.match(r'\}'):
                return out
            while True:
                self.i = _js_ws(self.source, self.i)
                if self.source[self.i:self.i + 1] in ('"', "'"):
                    key, self.i = _js_string(self.source, self.i)
                else:
                    key = self.name()
                if key == '__proto__' or key in out:
                    raise _Dynamic('unsafe_object_key')
                if self.match(':'):
                    out[key] = self.value()
                elif key in self.env:
                    out[key] = self.env[key]
                else:
                    raise _Dynamic('args_not_static')
                if self.match(r'\}'):
                    return out
                self.expect(',')
                if self.match(r'\}'):
                    return out
        if self.match(r'\['):
            out = []
            if self.match(r'\]'):
                return out
            while True:
                out.append(self.value())
                if self.match(r'\]'):
                    return out
                self.expect(',')
                if self.match(r'\]'):
                    return out
        number = self.match(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?(?![\w$.])')
        if number:
            raw = number.group()
            value = float(raw) if re.search('[.eE]', raw) else int(raw)
            if not -9007199254740991 <= value <= 9007199254740991:
                raise _Dynamic('unsafe_number')
            return value
        name = self.name()
        if name in ('true', 'false', 'null'):
            return {'true': True, 'false': False, 'null': None}[name]
        if name in self.env:
            return self.env[name]
        raise _Dynamic('args_not_static')

    def call(self):
        self.expect(r'tools\b')
        self.expect(r'\.')
        name = self.name()
        server, tool = _split_tool(name)
        if server is None:
            raise _Dynamic('bad_tool_name')
        self.expect(r'\(')
        if self.match(r'\)'):
            args = {}
        else:
            args = self.value()
            self.expect(r'\)')
        if not isinstance(args, dict):
            raise _Dynamic('args_not_static')
        call = dict(server=server, tool=tool, args=args, args_status='static', order=len(self.calls))
        self.calls.append(call)
        return call

    def emission(self, loop=None):
        self.expect(r'text\b')
        self.expect(r'\(')
        self.expect(r'JSON\b')
        self.expect(r'\.')
        self.expect(r'stringify\b')
        self.expect(r'\(')
        if loop:
            self.expect(re.escape(loop[0]) + r'\b')
            plan = [(c, 'settled' if loop[1][1] else 'result') for c in loop[1][0]]
        elif self.match(r'await\b'):
            plan = [(self.call(), 'result')]
        else:
            name = self.name()
            if name not in self.results:
                raise _Dynamic('unrecognized_output')
            form = 'result'
            if self.match(r'\.'):
                projection = self.expect(r'(?:structuredContent|content)\b').group()
                form = 'structured' if projection == 'structuredContent' else 'content'
                if self.match(r'\?\?'):
                    self.expect(re.escape(name) + r'\b')
                    self.expect(r'\.')
                    self.expect(('content' if projection == 'structuredContent' else 'structuredContent') + r'\b')
                    form += '_or_content' if projection == 'structuredContent' else '_or_structured'
            plan = [(self.results[name], form)]
        if self.match(','):
            self.expect(r'null\b')
            self.expect(',')
            # Fixed indentation only; no replacer or executable formatting args.
            self.expect(r'(?:10|[0-9])(?![\w.])')
        self.expect(r'\)')
        self.expect(r'\)')
        self.end_statement()
        self.plan.extend(plan)

    def parse(self):
        while _js_ws(self.source, self.i) < len(self.source):
            if self.match(';'):
                continue
            if self.match(r'(?:const|let|var)\b'):
                name = self.name()
                self.reserve(name)
                self.expect('=')
                if self.match(r'await\b'):
                    if self.match(r'Promise\b'):
                        self.expect(r'\.')
                        settled = self.expect(r'(?:allSettled|all)\b').group() == 'allSettled'
                        self.expect(r'\(')
                        self.expect(r'\[')
                        members = [self.call()]
                        while self.match(','):
                            if self.match(r'(?=\])'):
                                break
                            members.append(self.call())
                        self.expect(r'\]')
                        self.expect(r'\)')
                        self.groups[name] = (members, settled)
                    else:
                        self.results[name] = self.call()
                else:
                    self.env[name] = self.value()
                self.end_statement()
            elif self.match(r'for\b'):
                self.expect(r'\(')
                self.expect(r'(?:const|let)\b')
                name = self.name()
                self.reserve(name)
                self.expect(r'of\b')
                group = self.name()
                if group not in self.groups:
                    raise _Dynamic('unsupported_syntax')
                self.expect(r'\)')
                braced = bool(self.match(r'\{'))
                self.emission((name, self.groups[group]))
                if braced:
                    self.expect(r'\}')
            elif self.match(r'(?=text\b)'):
                self.emission()
            elif self.match(r'await\b'):
                self.call()
                self.end_statement()
            else:
                raise _Dynamic('unsupported_syntax')
        return {'calls': self.calls, 'emissions': len(self.plan), 'emit_plan': self.plan,
                'attributable': True, 'reason': None}


def _mentioned_calls(source):
    """Diagnostic candidates only. Strings/comments never become call evidence."""
    masked, i = list(source), 0
    while i < len(source):
        try:
            j = _js_ws(source, i)
            if j == i and source[i] in ('"', "'", '`'):
                _, j = _js_string(source, i)
            if j != i:
                masked[i:j] = ' ' * (j - i)
                i = j
            else:
                i += 1
        except _Dynamic:
            # Do not search inside an unparseable literal or trailing comment.
            masked[i:] = ' ' * (len(source) - i)
            break
    text = ''.join(masked)
    calls = []
    for hit in _JS_CALL.finditer(text):
        server, tool = _split_tool(hit.group(1))
        calls.append(dict(server=server, tool=tool, args=None, args_status='unverified', order=len(calls)))
    return calls


def analyze_code_mode_script(source):
    """Accept only fully consumed static call/print templates; never execute JS.

    Attributable means a script's print is structurally linked to a result. The
    host records printed output, not the underlying MCP transport: this remains
    weaker evidence than host_native. Projections are linked but incomplete.
    """
    try:
        return _CodeModeParser(source).parse()
    except (_Dynamic, IndexError, RecursionError, ValueError) as error:
        return {'calls': _mentioned_calls(source), 'emissions': 0, 'emit_plan': [],
                'attributable': False, 'reason': str(error) if isinstance(error, _Dynamic) else 'unparsable_script'}


def _printed_parts(output):
    """(header, [printed text parts]) of a code-mode output, or (None, None) when it is not that shape."""
    if isinstance(output, str):
        output = [{'type': 'input_text', 'text': output}]
    if (not isinstance(output, list) or not output or
            any(not isinstance(part, dict) or part.get('type') not in {'text', 'input_text', 'output_text'} or
                not isinstance(part.get('text'), str) for part in output)):
        return None, None
    texts = [part['text'] for part in output]
    head = re.match(r'^Script (\w+)\s*\nWall time[^\n]*\nOutput:\n?', texts[0])
    if not head:
        return None, None
    rest = texts[0][head.end():]
    return head.group(1), ([rest] if rest.strip() else []) + texts[1:]


def _is_truncated(text):
    # Host truncation can preserve valid JSON around a removed middle section.
    return bool(re.search(r'Warning: truncated output|Total output lines:|\[.*?truncated.*?\]|'
                          r'<truncated>|[.…]{3}\s*\d+\s*(?:tokens|characters)\s*truncated', str(text), re.I))


def _content_text(content):
    return '\n'.join(str(p.get('text', '')) for p in content if isinstance(p, dict) and p.get('type') == 'text')


def _printed_json(printed):
    # JSON.stringify cannot emit duplicate object keys, NaN or Infinity. Reject
    # these instead of silently selecting a field or accepting an impossible print.
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError('duplicate_json_key')
            out[key] = value
        return out

    def number(raw):
        value = float(raw)
        if not -float('inf') < value < float('inf'):
            raise ValueError('nonfinite_json_number')
        return value

    return json.loads(printed, object_pairs_hook=unique, parse_float=number, parse_constant=number)


def _code_mode_reply(printed, form):
    """-> (response text, failed, problem). problem is set when the printed text cannot be this call's reply."""
    if form not in {'result', 'settled'}:
        return None, False, 'incomplete_projection'
    if _is_truncated(printed):
        return None, False, 'truncated'
    try:
        value = _printed_json(printed)
    except (ValueError, RecursionError):
        return None, False, 'not_json'
    failed = False
    if form == 'settled':
        if (not isinstance(value, dict) or value.get('status') not in ('fulfilled', 'rejected') or
                set(value) != ({'status', 'value'} if value.get('status') == 'fulfilled' else {'status', 'reason'})):
            return None, False, 'not_settled_entry'
        if value['status'] == 'rejected':
            reason = value.get('reason')
            return (reason if isinstance(reason, str) else json.dumps(reason, ensure_ascii=False)), True, None
        value = value.get('value')
    failed = isinstance(value, dict) and bool(value.get('isError'))
    if isinstance(value, dict) and isinstance(value.get('content'), list):
        text = _content_text(value['content'])
        return (text if text.strip() else printed), failed, None
    if isinstance(value, list) and all(isinstance(p, dict) for p in value):
        return _content_text(value) or printed, False, None
    return printed, failed, None


def _native_reply(raw, output):
    """Keep the entire host result; response remains the old text consumption view."""
    response = _output_text(output)
    value = output
    if isinstance(output, str) or isinstance(output, list):
        try:
            value = json.loads(response)
        except (ValueError, TypeError):
            pass
    failed = bool(raw.get('is_error') or raw.get('isError'))
    if isinstance(value, dict):
        failed = failed or bool(value.get('isError') or value.get('is_error'))
    return dict(response=response, raw_response=raw, isError=failed, reply_failed=failed,
                reply_complete=True, evidence='host_native', evidence_note='宿主直接记录工具调用和完整结果')


def mcp_scan(root, since_ns=None):
    """Everything the current conversation's own record says about MCP calls, with diagnostics (read-only).

    {session: bool, host, error, calls: [...], unattributed: [...], pending: [...], unsupported: [...]}
    calls carry a full reply and `evidence`: host_native (host-recorded call + result) or code_mode_passthrough
    (host-recorded script that prints exactly the call's own result). unattributed = the call is visibly in the
    record but its reply cannot be proven to be its own."""
    scan = {'session': False, 'host': None, 'error': None, 'calls': [], 'unattributed': [], 'pending': [], 'unsupported': []}
    try:
        found = _session(root)
    except (OSError, ValueError) as error:
        scan['error'] = str(error)
        return scan
    if not found:
        return scan
    harness, _, rows, identity = found
    scan.update(session=True, host=harness, session_id=identity)
    native, results, scripts, outputs = [], {}, [], {}
    ambiguous = set()

    def record(bucket, call_id, value):
        if not call_id:
            return
        if call_id in bucket and bucket[call_id] != value:
            ambiguous.add(call_id)
        else:
            bucket[call_id] = value

    for item in rows:
        payload = item.get('payload', {}) if harness == 'codex' else item
        stamp = _timestamp_ns(item.get('timestamp'))
        if harness == 'codex' and item.get('type') == 'response_item':
            kind = payload.get('type')
            namespace = str(payload.get('namespace') or '')
            if kind == 'function_call' and namespace.startswith('mcp__'):
                try:
                    args = json.loads(payload.get('arguments') or '{}')
                except ValueError:
                    continue
                server, tool = _split_tool(namespace + '__' + str(payload.get('name') or ''))
                if server is None or not isinstance(args, dict) or not payload.get('call_id'):
                    scan['unsupported'].append({'call_id': payload.get('call_id'), 'time_ns': stamp,
                                                'name': namespace + '__' + str(payload.get('name')), 'reason': 'bad_tool_name_or_args'})
                    continue
                native.append({'server': server, 'tool': tool, 'args': args,
                               'time_ns': stamp, 'call_id': payload.get('call_id')})
            elif kind == 'function_call_output':
                record(results, payload.get('call_id'), _native_reply(payload, payload.get('output')))
            elif kind == 'custom_tool_call' and 'mcp__' in str(payload.get('input') or ''):
                if payload.get('name') == 'exec' and payload.get('call_id'):
                    scripts.append({'call_id': payload.get('call_id'), 'source': str(payload.get('input')), 'time_ns': stamp})
                else:
                    scan['unsupported'].append({'call_id': payload.get('call_id'), 'time_ns': stamp, 'reason': 'unknown_script_runner'})
            elif kind == 'custom_tool_call_output':
                record(outputs, payload.get('call_id'), payload.get('output'))
        elif harness == 'claude-code':
            msg = item.get('message') or {}
            if (item.get('isSidechain') or item.get('isMeta') or item.get('isApiErrorMessage') or
                    msg.get('model') == '<synthetic>'):
                continue
            for part in msg.get('content') or []:
                if not isinstance(part, dict):
                    continue
                name = str(part.get('name') or '')
                if (part.get('type') == 'tool_use' and name.startswith('mcp__') and
                        item.get('type') == 'assistant' and msg.get('role') == 'assistant'):
                    server, tool = _split_tool(name)
                    args = part.get('input', {})
                    if server is None or not isinstance(args, dict) or not part.get('id'):
                        scan['unsupported'].append({'call_id': part.get('id'), 'time_ns': stamp,
                                                    'name': name, 'reason': 'bad_tool_name_or_args'})
                        continue
                    native.append({'server': server, 'tool': tool, 'args': args,
                                   'time_ns': stamp, 'call_id': part.get('id')})
                elif (part.get('type') == 'tool_result' and item.get('type') == 'user' and
                      msg.get('role') == 'user'):
                    record(results, part.get('tool_use_id'), _native_reply(part, part.get('content')))
    inside = lambda call: since_ns is None or (call['time_ns'] or 0) >= since_ns
    scan['unsupported'] = [row for row in scan['unsupported'] if inside(row)]
    seen = {}
    for call in native + scripts:
        record(seen, call['call_id'], call)
    emitted = set()
    for call in native:
        if not inside(call) or call['call_id'] in emitted:
            continue
        emitted.add(call['call_id'])
        if call['call_id'] in ambiguous:
            scan['unattributed'].append(dict(call, reason='conflicting_call_id'))
        elif call['call_id'] in results:
            reply = results[call['call_id']]
            if _is_truncated(reply['response']):
                scan['unattributed'].append(dict(call, **dict(reply, reply_complete=False), reason='truncated'))
            else:
                scan['calls'].append(dict(call, **reply))
        else:
            scan['pending'].append(dict(call, reason='no_result_yet'))
    for script in scripts:
        if not inside(script) or script['call_id'] in emitted:
            continue
        emitted.add(script['call_id'])
        digest = hashlib.sha256(script['source'].encode('utf-8')).hexdigest()
        analysis = analyze_code_mode_script(script['source'])
        if script['call_id'] in ambiguous:
            scan['unsupported'].append(dict(script, reason='conflicting_call_id'))
            continue
        if any(c['server'] is None for c in analysis['calls']):
            scan['unsupported'].append({'call_id': script['call_id'], 'time_ns': script['time_ns'], 'reason': 'bad_tool_name'})
            continue
        if not analysis['calls']:
            # A script that merely mentions "mcp__" (grep, docs) is not an MCP call; only a tools.<mcp> use we cannot read is.
            if re.search(r'\btools\s*(?:\.\s*mcp__|\[)', script['source']):
                scan['unsupported'].append({'call_id': script['call_id'], 'time_ns': script['time_ns'], 'reason': analysis['reason']})
            continue
        base = [{'server': c['server'], 'tool': c['tool'], 'args': c['args'], 'time_ns': script['time_ns'],
                 'call_id': f"{script['call_id']}#{c['order']}", 'script_call_id': script['call_id'], 'script_sha256': digest,
                 'evidence': 'code_mode_call_only', 'args_status': c['args_status']} for c in analysis['calls']]
        if script['call_id'] not in outputs:
            scan['pending'] += [dict(row, reason='no_result_yet') for row in base]
            continue
        status, parts = _printed_parts(outputs[script['call_id']])
        if status is None:
            scan['unattributed'] += [dict(row, reason='output_format_unknown') for row in base]
            continue
        if status != 'completed':
            scan['unattributed'] += [dict(row, reason='script_' + status.lower()) for row in base]
            continue
        if not analysis['attributable']:
            scan['unattributed'] += [dict(row, reason=analysis['reason']) for row in base]
            continue
        if len(parts) != analysis['emissions']:
            scan['unattributed'] += [dict(row, reason='output_count_mismatch') for row in base]
            continue
        replied, prints, conflicts = set(), {}, set()
        for index, (call, form) in enumerate(analysis['emit_plan']):
            key = (call['order'], form)
            if key in prints and prints[key] != parts[index]:
                conflicts.add(call['order'])
            prints[key] = parts[index]
        for index, (call, form) in enumerate(analysis['emit_plan']):
            row = base[call['order']]
            if call['order'] in replied:
                continue
            # A complete print can supply the evidence even if a projection was
            # also printed. No projected print on its own is an entire result.
            if form not in {'result', 'settled'} and any(
                    c['order'] == call['order'] and f in {'result', 'settled'} for c, f in analysis['emit_plan']):
                continue
            replied.add(call['order'])
            response, failed, problem = _code_mode_reply(parts[index], form)
            problem = 'conflicting_prints' if call['order'] in conflicts else problem
            if problem or call['args_status'] != 'static':
                scan['unattributed'].append(dict(row, reason=problem or 'args_not_static', emit_form=form,
                                                 raw_output=parts[index], reply_complete=False))
                continue
            scan['calls'].append(dict(row, response=response, raw_output=parts[index], raw_response=json.loads(parts[index]),
                                      evidence='code_mode_passthrough', emit_form=form, reply_failed=failed, isError=failed,
                                      reply_complete=True, evidence_note='宿主仅记录脚本打印；静态模板透传，证据弱于 host_native，非原生 MCP 传输回包',
                                      printed_sha256=hashlib.sha256(parts[index].encode('utf-8')).hexdigest()))
        scan['unattributed'] += [dict(row, reason='no_output_emit') for row in base if row['call_id'].rsplit('#', 1)[1] not in {str(i) for i in replied}]
    scan['calls'].sort(key=lambda row: (row['time_ns'] or 0))
    return scan


def mcp_calls(root, since_ns=None):
    """MCP calls this conversation actually made, with their full results, oldest first (read-only).

    [{server, tool, args, response, raw_response, time_ns, call_id, evidence, ...}].
    response is the legacy text view; raw_response keeps the complete host result
    (or complete printed JSON), and code-mode raw_output keeps its original print.
    A code_mode_passthrough print is weaker evidence than a host_native result.
    Use mcp_scan() to also see incomplete projections and unsupported scripts."""
    return mcp_scan(root, since_ns)['calls']


def _native(root):
    found = _session(root)
    if not found:
        return None
    harness, path, rows, identity = found
    # Pi appends branches to one file. Only the active leaf's ancestry counts.
    active = None
    if harness == 'pi':
        indexed = {r['id']: r for r in rows if r.get('id') and r.get('type') != 'session'}
        leaf = next((r['id'] for r in reversed(rows) if r.get('id') in indexed), None)
        active = set()
        while leaf and leaf not in active:
            active.add(leaf)
            leaf = indexed.get(leaf, {}).get('parentId')
    messages, controls, model = [], [], ''
    for index, item in enumerate(rows):
        if harness == 'pi' and item.get('id') not in active:
            continue
        payload = item.get('payload', {}) if harness == 'codex' else item
        stamp = _timestamp_ns(item.get('timestamp'))
        if harness == 'codex' and item.get('type') == 'response_item' and payload.get('type') in {'function_call', 'custom_tool_call'}:
            controls.append({'index': index, 'id': payload.get('call_id') or payload.get('id'),
                             'kind': 'tool_call', 'time_ns': stamp})
        if harness == 'codex' and item.get('type') == 'turn_context':
            model = payload.get('model') or model
        if harness == 'codex' and (item.get('type') != 'response_item' or payload.get('type') != 'message'):
            continue
        msg = payload if harness == 'codex' else payload.get('message', {})
        role = msg.get('role')
        if role not in {'user', 'assistant'}:
            continue
        if harness == 'claude-code' and (item.get('isSidechain') or item.get('isMeta') or
                item.get('isApiErrorMessage') or msg.get('model') == '<synthetic>' or
                (role == 'user' and isinstance(msg.get('content'), list) and
                 not any(part.get('type') in {'text', 'image'} for part in msg['content'] if isinstance(part, dict)))):
            continue
        if msg.get('model'):
            model = '/'.join(str(msg.get(k, '')) for k in ('provider', 'model')).strip('/')
        text = _text(msg.get('content'))
        if harness == 'codex':
            final = msg.get('phase') == 'final_answer'
        elif harness == 'claude-code':
            final = (bool(text.strip()) and msg.get('stop_reason') in {'end_turn', 'stop_sequence'}
                     and not item.get('isApiErrorMessage') and msg.get('model') != '<synthetic>')
        else:
            final = msg.get('stopReason', msg.get('stop_reason')) in {'stop', 'end_turn'}
        if text.strip() and not item.get('isApiErrorMessage'):
            controls.append({'index': index, 'id': msg.get('id') or item.get('uuid') or item.get('id'),
                             'kind': role + '_reply', 'time_ns': stamp})
        if harness != 'codex' and role == 'assistant':
            for part in msg.get('content', []) if isinstance(msg.get('content'), list) else []:
                if isinstance(part, dict) and part.get('type') in {'toolCall', 'tool_use'}:
                    controls.append({'index': index, 'id': part.get('id'), 'kind': 'tool_call', 'time_ns': stamp})
        messages.append({'index': index, 'role': role, 'text': text, 'phase': msg.get('phase'),
                         'final': final, 'model': model,
                         'final_known': ('phase' in msg if harness == 'codex' else
                                         'stopReason' in msg or 'stop_reason' in msg)})
    return {'kind': 'native', 'harness': harness, 'session_path': str(path), 'session_id': identity,
            'offset': len(rows), 'messages': messages, 'control_events': controls}


def _host_turns(root):
    cli = os.environ.get('CODEXHOST_CLI_PATH')
    thread = os.environ.get('CODEXHOST_THREAD_ID') or os.environ.get('CODEX_THREAD_ID')
    if (not cli or not thread or not os.environ.get('CODEXHOST_RUNTIME_ENDPOINT')
            or not _covers(root, Path.cwd(), thread)):
        return None
    try:
        rows, cursor, seen = [], None, set()
        for _ in range(20):
            command = [cli, 'thread', 'read', thread, '--view', 'messages', '--limit', '100', '--format', 'compact']
            if cursor: command += ['--cursor', cursor]
            result = subprocess.run(command, capture_output=True, text=True, encoding='utf8', timeout=10)
            value = json.loads(result.stdout)
            if result.returncode or value.get('harnessId') != current_host(): return None
            rows.extend(value.get('messages', []))
            if not value.get('hasMore'): break
            cursor = value.get('nextCursor')
            if not cursor or cursor in seen: return None
            seen.add(cursor)
        else: return None  # An incomplete page cannot prove a current user turn.
        messages = []
        for n, row in enumerate(rows):
            role = 'assistant' if row.get('role') == 'agent' else row.get('role')
            if role not in {'assistant', 'user'}:
                continue
            messages.append(dict(row, index=n, role=role,
                                 final_known=row.get('phase') not in {None, 'final'}))
        return {'kind': 'host_turn', 'harness': value.get('harnessId', current_host()),
                'session_id': thread, 'offset': len(rows),
                'messages': messages, 'control_events': [{'index': row['index'], 'kind': row['role'] + '_reply',
                    'id': row.get('id'), 'time_ns': _timestamp_ns(row.get('timestamp'))} for row in messages]}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def _context(root):
    try:
        native = _native(root)
    except (OSError, ValueError):
        native = None
    return native or _host_turns(root)


def visibility_boundary(root):
    context = _context(root)
    return ({k: v for k, v in context.items() if k not in {'messages', 'control_events'}} if context else
            {'kind': 'unavailable', 'harness': current_host(), 'offset': 0})


def _clean(line):
    return re.sub(r'\s+', '', line.replace('**', '').replace('`', '')).strip()


def _card_matches(text, card):
    if '旧任务恢复卡' in card or all(token in card for token in ('【本步结论】', '【模型建议】', '【下一步】')):
        return text.strip() == card.strip()
    lines = card.strip().splitlines()
    if not lines:
        return False
    headings = [line for line in text.splitlines() if re.search(r'S[1-5]\s*·\s*\d+/\d+', line)]
    conclusion = next((line for line in lines if '🎯' in line), None)
    return (len(headings) == 1 and _clean(text.splitlines()[0]) == _clean(lines[0])
            and conclusion is not None and any(_clean(line) == _clean(conclusion) for line in text.splitlines()))


def _card_in_reply(text, card):
    """One of several cards in a single reply: its own first line and 🎯 line are present, in order."""
    lines = card.strip().splitlines()
    conclusion = next((line for line in lines if '🎯' in line), None)
    if not lines or conclusion is None:
        return False
    cleaned = [_clean(line) for line in text.splitlines()]
    try:
        start = cleaned.index(_clean(lines[0]))
    except ValueError:
        return False
    return _clean(conclusion) in cleaned[start:]


def latest_user_message(root):
    """The user's most recent message as the host recorded it (never the assistant's own text)."""
    context = _context(root)
    if not context:
        return None
    users = [m for m in context['messages'] if m['role'] == 'user' and m.get('text', '').strip()]
    if not users:
        return None
    return {'index': users[-1]['index'], 'text': users[-1]['text'],
            'kind': context['kind'], 'session_id': context.get('session_id')}


def _same_session(boundary, context):
    return boundary.get('kind') == context['kind'] and boundary.get('session_id') == context.get('session_id')


def visible_cards_in_reply(root, cards, boundary):
    """Continuous run: every card must appear, in order, in final replies after the boundary.

    Returns (proof, missing) where missing lists the cards not yet shown."""
    context = _context(root)
    if not context:
        raise ValueError('读不到本宿主会话记录：不推进。请先恢复当前会话读取能力，再核对连续跑的步骤卡。')
    # A new window or host starts its own transcript: cards re-posted there count from its start (S1-R23).
    floor = boundary['offset'] if _same_session(boundary, context) else 0
    finals = [row for row in context['messages'] if row['index'] >= floor and row['role'] == 'assistant'
              and (row.get('final') if context['kind'] == 'native' else not row.get('final_known'))]
    missing, shown = [], None
    for card in cards:
        row = next((r for r in finals if _card_in_reply(r.get('text', ''), card)), None)
        if row is None:
            missing.append(card)
        else:
            shown = row
    proof = None
    if shown is not None and not missing:
        proof = {k: v for k, v in context.items() if k not in {'messages', 'offset', 'control_events'}} | {
            'evidence': 'continuous_final', 'message_index': shown['index'], 'model': shown.get('model', ''),
            'ack_context_offset': context['offset'], 'ack_process': os.getpid(), 'ack_parent': os.getppid(),
            'ack_time_ns': time.time_ns()}
    return proof, missing


def visible_card(root, card, boundary):
    context = _context(root)
    if not context:
        raise ValueError('读不到本宿主会话记录：不推进。请先恢复当前会话读取能力，再补发本步最终卡；降级回合取证还需等待用户下一条消息。')
    floor = boundary['offset'] if _same_session(boundary, context) else 0
    for row in reversed(context['messages']):
        if row['index'] < floor or row['role'] != 'assistant' or not _card_matches(row.get('text', ''), card):
            continue
        if context['kind'] == 'native' and row.get('final'):
            evidence = 'native_session_final'
        elif not row.get('final_known') and next((m['role'] for m in context['messages']
                if m['index'] > row['index']), None) == 'user':
            # Unknown transcript formats degrade to a verified subsequent user turn.
            evidence = 'host_user_turn'
        else:
            continue
        return {k: v for k, v in context.items() if k not in {'messages', 'offset', 'control_events'}} | {
            'evidence': evidence, 'message_index': row['index'], 'model': row.get('model', ''),
            'ack_context_offset': context['offset'],
            'ack_process': os.getpid(), 'ack_parent': os.getppid(), 'ack_time_ns': time.time_ns()}
    raise ValueError('本步步骤卡尚未在对话正式回复中出现；请单独补发一张卡，commentary 和回执文件不算出卡证据')


def require_separate_invocation(proof, root):
    context = _context(root)
    if not context:
        raise ValueError('读不到当前会话，暂不推进；恢复本宿主会话读取能力后重试 begin')
    same_context = all(context.get(key) == proof.get(key) for key in ('kind', 'harness', 'session_id'))
    ack_time = proof.get('ack_time_ns')
    if not isinstance(ack_time, int) or ack_time <= 0:
        raise ValueError('旧回执缺少 ack 时间，请补发并重新核对步骤卡')
    # Offsets belong to one transcript. A new session may continue an already
    # verified card, provided its actual control event happened after the ack.
    floor = proof.get('ack_context_offset') if same_context else None
    for event in context.get('control_events', []):
        if floor is not None and event['index'] < floor: continue
        stamp = event.get('time_ns')
        if stamp is not None and stamp > ack_time:
            return
        if context['kind'] == 'host_turn' and floor is not None and stamp is None:
            return  # A newly appended public reply; the Host API exposes no tools.
    if not same_context:
        raise ValueError('当前会话尚无可证明晚于 ack 的真实调用或回复；请在提供时间戳的本机会话重试，或回到原已核对会话继续 begin')
    raise ValueError('禁止在同一条宿主命令中 ack 后紧跟 begin；ack 后尚无新的真实工具调用或回复，请在独立调用中继续。只有公开回合可读时，先回复本次核对结果。')
