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
        output = '\n'.join(str(part.get('text', '')) for part in output if isinstance(part, dict))
    return _WALL.sub('', str(output or ''))


def mcp_calls(root, since_ns=None):
    """MCP calls this conversation actually made, with their full results, oldest first (read-only).

    [{server, tool, args, response, time_ns, call_id}]; response is the result text exactly as the host
    recorded it. Lets native tools save responses themselves instead of the assistant pasting them."""
    found = _session(root)
    if not found:
        return []
    harness, _, rows, _ = found
    calls, results = [], {}
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
                calls.append({'server': namespace[5:], 'tool': payload.get('name'), 'args': args,
                              'time_ns': stamp, 'call_id': payload.get('call_id')})
            elif kind == 'function_call_output':
                results[payload.get('call_id')] = _output_text(payload.get('output'))
        elif harness == 'claude-code':
            for part in (item.get('message') or {}).get('content') or []:
                if not isinstance(part, dict):
                    continue
                name = str(part.get('name') or '')
                if part.get('type') == 'tool_use' and name.startswith('mcp__') and name.count('__') >= 2:
                    _, server, tool = name.split('__', 2)
                    calls.append({'server': server, 'tool': tool, 'args': part.get('input') or {},
                                  'time_ns': stamp, 'call_id': part.get('id')})
                elif part.get('type') == 'tool_result':
                    results[part.get('tool_use_id')] = _output_text(part.get('content'))
    return [dict(call, response=results[call['call_id']]) for call in calls
            if call['call_id'] in results and (since_ns is None or (call['time_ns'] or 0) >= since_ns)]


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
