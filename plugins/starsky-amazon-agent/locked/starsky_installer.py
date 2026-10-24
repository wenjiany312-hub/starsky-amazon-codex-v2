"""Starsky Codex installer. Never logs credentials or deletes user workspaces."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import tomllib
import urllib.request
import uuid
import zipfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from host_support import HOSTS, entry_specs

PRODUCT = 'starsky-codex'
MARKET = 'starskycodex'
PLUGIN = 'starsky-amazon-agent'
REPO = 'wenjiany312-hub/starsky-amazon-codex-releases'
CONTACT = '公众号「跨境者说干货」后台，或知识星球「星空的跨境圈子」私信坚哥'
# One installer for every host. A bundle without host.json is the Codex edition, unchanged.
HOST = 'codex'
LICENSE_PREFIX = 'SKYC1'
MEMBER_BRANCH = 'codex/member-updates'
APP_DIR = '.starsky-codex'
LABEL = 'Starsky Codex'
# Paid channel: the plugin is delivered through a Git marketplace, so Codex's own Upgrade button pulls new
# releases ({'url': https git URL, 'ref': branch}). The repo holds only a thin entry, the encrypted payload and
# per-member encrypted grants; git_unlock.py opens a new release locally with the machine's activation.
GIT_MARKETPLACE = None


def _load_host():
    global HOST, PRODUCT, MARKET, PLUGIN, REPO, LICENSE_PREFIX, MEMBER_BRANCH, APP_DIR, LABEL, GIT_MARKETPLACE
    path = Path(__file__).with_name('host.json')
    if not path.is_file():
        return
    data = json.loads(path.read_text(encoding='utf-8'))
    HOST, PRODUCT, MARKET, PLUGIN = data['host'], data['product'], data['market'], data['plugin']
    REPO, LICENSE_PREFIX, MEMBER_BRANCH = data['repo'], data['license_prefix'], data['member_branch']
    APP_DIR, LABEL = data['app_dir'], data['label']
    GIT_MARKETPLACE = data.get('git_marketplace')


_load_host()
# Existing date-only SKYC1 licenses were issued by the Beijing-based maintainer.
# Keep that calendar meaning on every host, including before/after local midnight.
LICENSE_TIMEZONE = timezone(timedelta(hours=8))


def license_today():
    return datetime.now(LICENSE_TIMEZONE).date()


class InstallError(RuntimeError):
    pass


def app_home():
    return Path(os.environ.get('STARSKY_HOME', str(Path.home() / APP_DIR))).resolve()


def codex_home():
    return Path(os.environ.get('CODEX_HOME', str(Path.home() / '.codex'))).resolve()


def b64decode(text):
    return base64.b64decode(text + '=' * (-len(text) % 4), altchars=b'-_', validate=True)


def verify_signature_stdlib(data, signature, public):
    """Strict RSA PKCS#1 v1.5 / SHA-256 verification before dependencies exist.

    RFC 8017 sections 8.2.2 and 9.2. Verification only; no private-key operations.
    Accept only the RSA SubjectPublicKeyInfo format emitted by the release builder.
    """
    try:
        match = re.fullmatch(rb'\s*-----BEGIN PUBLIC KEY-----\s+([A-Za-z0-9+/=\s]+)-----END PUBLIC KEY-----\s*', public)
        if not match:
            raise ValueError('public format')
        der = base64.b64decode(re.sub(rb'\s+', b'', match.group(1)), validate=True)
        def tlv(raw, offset, tag):
            if offset + 2 > len(raw) or raw[offset] != tag:
                raise ValueError('DER tag')
            length = raw[offset + 1]; start = offset + 2
            if length & 128:
                count = length & 127
                if not 1 <= count <= 4 or start + count > len(raw) or raw[start] == 0:
                    raise ValueError('DER length')
                length = int.from_bytes(raw[start:start + count], 'big'); start += count
                if length < 128:
                    raise ValueError('DER noncanonical')
            end = start + length
            if end > len(raw):
                raise ValueError('DER truncated')
            return raw[start:end], end
        spki, end = tlv(der, 0, 0x30)
        if end != len(der): raise ValueError('DER trailing')
        algorithm, offset = tlv(spki, 0, 0x30)
        if algorithm != bytes.fromhex('06092a864886f70d0101010500'):
            raise ValueError('not RSA')
        bits, end = tlv(spki, offset, 0x03)
        if end != len(spki) or not bits or bits[0] != 0: raise ValueError('bit string')
        numbers, end = tlv(bits[1:], 0, 0x30)
        if end != len(bits) - 1: raise ValueError('RSA trailing')
        modulus, offset = tlv(numbers, 0, 0x02)
        exponent, end = tlv(numbers, offset, 0x02)
        if end != len(numbers): raise ValueError('RSA integers')
        def positive(raw):
            if not raw or raw[0] & 128 or (len(raw) > 1 and raw[0] == 0 and not raw[1] & 128):
                raise ValueError('DER integer')
            return int.from_bytes(raw, 'big')
        n, e = positive(modulus), positive(exponent)
        if not 2048 <= n.bit_length() <= 8192 or n % 2 != 1 or e != 65537:
            raise ValueError('RSA parameters')
        size = (n.bit_length() + 7) // 8
        number = int.from_bytes(signature, 'big')
        if len(signature) != size or number >= n: raise ValueError('RSA signature')
        digest_info = bytes.fromhex('3031300d060960864801650304020105000420') + hashlib.sha256(data).digest()
        expected = b'\x00\x01' + b'\xff' * (size - len(digest_info) - 3) + b'\x00' + digest_info
        if not hmac.compare_digest(pow(number, e, n).to_bytes(size, 'big'), expected):
            raise ValueError('signature')
    except Exception as exc:
        raise InstallError('签名无效或内容被修改，请从官方公开发布页重新下载。') from exc


def verify_signature(data, signature, public):
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:
        return verify_signature_stdlib(data, signature, public)
    try:
        key = serialization.load_pem_public_key(public)
        key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:
        raise InstallError('签名无效或内容被修改，请从官方公开发布页重新下载。') from exc


def verify_license(code, public, device, today=None, allow_expired=False):
    try:
        prefix, raw, signature = code.strip().split('.')
        if prefix != LICENSE_PREFIX: raise ValueError('prefix')
        data = b64decode(raw)
        verify_signature(data, b64decode(signature), public)
        obj = json.loads(data)
        today = today if today is not None else license_today()
        if obj.get('product') != PRODUCT or obj.get('device') != device:
            raise InstallError('授权不属于本产品或本机，请联系坚哥重新签发。')
        if not obj.get('id') or date.fromisoformat(obj['issued']) > today:
            raise InstallError('授权签发日期无效（按北京时间 UTC+08:00 校验，请核对本机时间或联系作者）。')
        if date.fromisoformat(obj['expires']) < date.fromisoformat(obj['issued']):
            raise InstallError('授权起止日期无效。')
        if not allow_expired and date.fromisoformat(obj['expires']) < today:
            raise InstallError('授权已到期：旧版仍可使用，安装/更新新版前请联系坚哥续费。')
        return obj
    except InstallError:
        raise
    except Exception as exc:
        raise InstallError(f'无法解析授权码，请完整粘贴 {LICENSE_PREFIX}. 开头的授权码。') from exc


def fingerprint():
    system = platform.system()
    if system == 'Windows':
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Cryptography', 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                identity = winreg.QueryValueEx(k, 'MachineGuid')[0]
        except OSError as exc:
            raise InstallError('无法读取 Windows 设备标识，请先联系作者诊断。') from exc
    elif system == 'Darwin':
        output = run_checked(['/usr/sbin/ioreg', '-rd1', '-c', 'IOPlatformExpertDevice'])
        match = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', output)
        if not match: raise InstallError('无法读取 Mac 设备标识。')
        identity = match.group(1)
    else:
        raise InstallError('当前发布仅支持 Windows 和 macOS。')
    return hashlib.sha256((PRODUCT + '|' + system + '|' + identity).encode()).hexdigest()[:32].upper()


def run_checked(command, **kwargs):
    operation = kwargs.pop('operation', '')
    context = operation + '：' if operation else ''
    try:
        result = subprocess.run([str(x) for x in command], capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=kwargs.pop('timeout', 180), **kwargs)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError(f'{context}命令未完成：{Path(str(command[0])).name}；请检查环境或网络后重试。') from exc
    if result.returncode:
        # Do not echo arbitrary subprocess output: it may contain user configuration.
        raise InstallError(f'{context}命令失败：{Path(str(command[0])).name}，退出码 {result.returncode}。有效版本未更新。')
    return result.stdout


def verify_file(path, expected):
    path = Path(path)
    if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise InstallError(f'文件 {path.name} 的 SHA-256 清单无效，停止安装。请重新下载并解压官方 ZIP。')
    try:
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise InstallError(f'文件 {path.name} 缺失或无法读取，停止安装。请重新解压官方 ZIP。') from exc
    if actual != expected:
        raise InstallError(f'文件 {path.name} 完整性校验失败（SHA-256 不匹配），停止安装。'
                           '请重新下载并解压官方 ZIP，不要修改包内脚本。')


def safe_member(name):
    if '\\' in name or ':' in name or '\x00' in name:
        raise InstallError('安装包包含非法路径。')
    p = PurePosixPath(name)
    reserved = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1,10)), *(f'LPT{i}' for i in range(1,10))}
    if p.is_absolute() or '..' in p.parts or not p.parts or any(x.rstrip(' .') != x or x.split('.')[0].upper() in reserved for x in p.parts):
        raise InstallError('安装包包含越界或保留路径。')
    return p


def safe_extract(archive, destination):
    destination = Path(destination)
    if destination.exists(): raise InstallError('解压目标已存在，拒绝覆盖。')
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist(); seen=set()
        if sum(i.file_size for i in infos) > 250_000_000 or len(infos) > 10000:
            raise InstallError('安装包超出体积或文件数量限制。')
        for i in infos:
            p=safe_member(i.filename); name=str(p).casefold()
            if name in seen or stat.S_ISLNK(i.external_attr >> 16):
                raise InstallError('安装包包含重名路径或符号链接。')
            seen.add(name)
        destination.mkdir(parents=True)
        for i in infos:
            target=destination.joinpath(*PurePosixPath(i.filename).parts)
            if i.is_dir(): target.mkdir(parents=True,exist_ok=True);continue
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(z.read(i))
            if target.suffix in {'.sh','.command'} and os.name != 'nt':target.chmod(0o755)


_INSTALL_RECORD_WRITE = threading.local()


def _write_stamp(path):
    info=Path(path).stat()
    return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)


def _owns_install_write(path, receipt):
    return (receipt.get('published') is not None and Path(path).exists()
            and _write_stamp(path)==receipt['published'])


def atomic_json(path, value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    try:
        with temp.open('w',encoding='utf-8') as output:
            output.write(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
            output.flush();os.fsync(output.fileno())
        if os.name != 'nt':temp.chmod(0o600)
        receipt=getattr(_INSTALL_RECORD_WRITE,'current',None)
        if receipt is not None and receipt[0]==path:
            # Capture this writer's actual file before publication. Even a
            # corrupt JSON write belongs to the transaction; a later user edit
            # changes the file identity/mtime and must not be rolled back.
            receipt[1]['published']=_write_stamp(temp)
        os.replace(temp,path)
    finally:
        if temp.exists():temp.unlink()


RETIRED_BUSINESS_ENTRIES = ('scripts/s1_flow.py', 'scripts/workflow_flow.py', 'scripts/read_context.py')


def _retirement_block(active, old):
    return (f'星空已更新到 {active}，但本机还没完成解锁，当前仍是 {old}。'
            '请用支持权限申请的模型重新说『启动星空』并允许，或运行安装包里的『安装与更新』。')


def _no_reparse(path):
    """Check lexical ancestors BEFORE resolve; junctions count as links on Windows."""
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        if part.is_symlink():
            raise InstallError('安装管理路径含符号链接。')
        if part.exists() and getattr(part.lstat(), 'st_file_attributes', 0) & 0x400:
            raise InstallError('安装管理路径含重解析点。')
    return path


def _retirement_guard(record, active, old, host):
    # No imports of historical helpers, including on import by another module.
    # Bind X to the verified upgrade target, even if a crash leaves current.json
    # old/missing/malformed. This entry always stops; no record can enable it.
    return ("# STARSKY_RETIRED_ENTRY_V1: original retained by the installer journal\n"
            f"raise SystemExit({_retirement_block(active, old)!r})\n").encode('utf8')


def _prepare_retired_entries(state, host):
    """Only three managed old entry paths change; archives are immutable evidence.

    A prepared journal is durable before any guard write. A retry accepts only
    its original or last recorded guard hash and never archives a stub as code.
    """
    active = state.get('plugin_version')
    if not active or not state.get('source'):
        return [], {}
    root = app_home()
    previous = read_json(root / 'current.json', {})
    roots = set()
    for record in (previous, previous.get('previous_state', {}), state.get('previous_state', {})):
        if isinstance(record, dict):
            for field in ('source', 'home'):
                if record.get(field):
                    roots.add(Path(os.path.abspath(record[field])))
    versions = root / 'marketplace/versions'
    # One bounded installer-owned level, never a recursive search of user data.
    try:
        _no_reparse(versions)
        if versions.exists():
            for version in versions.iterdir():
                _no_reparse(version)
                if version.is_dir():
                    roots.add(version / 'plugins' / PLUGIN)
    except Exception as exc:
        raise InstallError(_retirement_block(active, previous.get('plugin_version') or '未知旧版')) from exc
    protected = {Path(os.path.abspath(state[k])) for k in ('source', 'home') if state.get(k)}
    cache = ((codex_home() if host == 'codex' else Path(os.environ.get('CLAUDE_CONFIG_DIR', str(Path.home() / '.claude'))))
             / 'plugins/cache' / ('starsky' + host) / PLUGIN)
    writes, records = [], {}
    journals = set(state.get('retirement_journals', []))
    old_label = previous.get('plugin_version') or previous.get('version') or '未知旧版'
    try:
        for folder in sorted(roots):
            if folder in protected:
                continue
            _no_reparse(folder)
            if not folder.exists():
                continue
            # Thin host roots with no business scripts have nothing to retire.
            # Check their scripts location for links even when it is dangling.
            _no_reparse(folder / 'scripts')
            if not (folder / 'scripts').exists():
                continue
            in_source = (folder.is_relative_to(versions) and len(folder.relative_to(versions).parts) == 3
                         and folder.parts[-2:] == ('plugins', PLUGIN))
            in_cache = folder.is_relative_to(cache) and len(folder.relative_to(cache).parts) == 1
            if not in_source and not in_cache:
                raise InstallError('旧入口不在安装器管理范围。')
            manifest_path = folder / ('.' + host + '-plugin/plugin.json')
            _no_reparse(manifest_path)
            manifest = read_json(manifest_path, {})
            old = manifest.get('version')
            if manifest.get('name') != PLUGIN or not isinstance(old, str) or not old:
                raise InstallError('旧入口清单身份无效。')
            old_label = old
            if old == active:
                continue
            identity = hashlib.sha256((host + '|' + str(folder)).encode('utf8')).hexdigest()
            archive_root = root / 'retired-entries' / identity
            journal_path = archive_root / 'journal.json'
            _no_reparse(journal_path)
            saved = read_json(journal_path, {})
            if journal_path.exists() and (saved.get('root') != str(folder) or saved.get('host') != host
                                         or saved.get('old_plugin_version') != old or saved.get('schema') != 1):
                raise InstallError('旧入口归档身份不一致。')
            saved_entries = {e['relative']: e for e in saved.get('entries', [])}
            entries = []
            guard = _retirement_guard(root / 'current.json', active, old, host)
            guard_sha = hashlib.sha256(guard).hexdigest()
            for relative in RETIRED_BUSINESS_ENTRIES:
                path = folder / relative
                _no_reparse(path)
                if not path.exists():
                    if relative in saved_entries:
                        raise InstallError('已登记旧入口缺失。')
                    continue  # Older thin host entries need not carry business controllers.
                raw = path.read_bytes()
                actual = hashlib.sha256(raw).hexdigest()
                archive = archive_root / (Path(relative).name + '.original')
                _no_reparse(archive)
                prior = saved_entries.get(relative)
                if prior:
                    if prior.get('path') != str(path) or prior.get('archive') != str(archive):
                        raise InstallError('旧入口归档路径不一致。')
                    original_sha = prior['original_sha256']
                    if actual not in (original_sha, prior['guard_sha256'], *prior.get('previous_guard_sha256', [])):
                        raise InstallError('旧入口已被并发修改。')
                    if not archive.is_file() or hashlib.sha256(archive.read_bytes()).hexdigest() != original_sha:
                        raise InstallError('旧入口原始归档校验失败。')
                else:
                    if raw.startswith(b'# STARSKY_RETIRED_ENTRY_V1'):
                        raise InstallError('旧入口已被阻断但缺少可验证原始归档。')
                    original_sha = actual
                    archive.parent.mkdir(parents=True, exist_ok=True)
                    # Exclusive creation preserves an orphan archive after a process
                    # loss between writing the original and its prepared journal.
                    temporary=archive.with_name('.original-'+uuid.uuid4().hex+'.tmp')
                    try:
                        with temporary.open('xb') as output:
                            output.write(raw); output.flush(); os.fsync(output.fileno())
                        try:os.link(temporary,archive)  # Atomic, exclusive publication.
                        except FileExistsError:pass
                    finally:temporary.unlink(missing_ok=True)
                    if archive.read_bytes() != raw:
                        raise InstallError('旧入口原始归档不一致。')
                history = sorted(set([*prior.get('previous_guard_sha256', []), prior['guard_sha256']]) - {guard_sha}) if prior else []
                entries.append({'relative': relative, 'path': str(path), 'archive': str(archive),
                                'original_sha256': original_sha, 'guard_sha256': guard_sha,
                                'previous_guard_sha256': history})
                if raw != guard:
                    writes.append((path, raw, guard))
            if not entries:
                continue
            journal = {'schema': 1, 'host': host, 'root': str(folder), 'old_plugin_version': old,
                       'active_plugin_version': active, 'status': 'committed', 'entries': entries}
            if saved.get('record_bindings') and saved.get('active_plugin_version') == active:
                journal['record_bindings'] = saved['record_bindings']
            if saved != journal:
                # Prepared includes every original/archive binding before writes.
                atomic_json(journal_path, {**journal, 'status': 'prepared'})
                if read_json(journal_path, {}) != {**journal, 'status': 'prepared'}:
                    raise InstallError('旧入口准备记录读回不一致。')
            records[journal_path] = journal
            journals.add(str(journal_path))
        if journals:
            state['retirement_journals'] = sorted(journals)
        return writes, records
    except Exception as exc:
        raise InstallError(_retirement_block(active, old_label)) from exc


def persist_install_state(state, *, host='codex', extra_records=None, runtime=False):
    """Commit the host's records together; restore exact prior bytes on failure.

    A record write is not an installation success until every copy reads back.
    Claude deliberately has no Codex mirror. Optional installer-owned records
    participate without logging their contents (including an existing activation).
    """
    if state.get('source') and state.get('plugin_version'):
        from sandbox_support import check_dependencies, check_files, FILE_MANIFEST
        source=Path(state['source'])
        if (source/FILE_MANIFEST).is_file():
            checked=check_files(source)
            if host=='claude':check_files(state.get('home',source),expected=checked['manifest'])
            check_dependencies(state.get('python') or sys.executable)
        folder=Path(state['source'])
        _no_reparse(folder)
        _no_reparse(folder/('.claude-plugin' if host=='claude' else '.codex-plugin')/'plugin.json')
        actual=read_json(folder/('.claude-plugin' if host=='claude' else '.codex-plugin')/'plugin.json',{})
        if not folder.is_dir() or actual.get('version')!=state['plugin_version'] or actual.get('name',PLUGIN)!=PLUGIN:
            raise InstallError('实际插件清单与安装记录版本不一致，安装未完成。')
    paths=[app_home()/'current.json']
    if host=='codex':paths.append(codex_home()/'starsky-codex.json')
    elif host!='claude':raise InstallError('未知安装宿主。')
    for path in paths:_no_reparse(path)
    original_records = {path:path.read_bytes() if path.exists() else None for path in paths}
    entries={}
    for saved in [*(read_json(paths[-1],{}).get('host_entries',[]) if host=='codex' else []),
                  *state.get('host_entries',[])]:
        key=(saved.get('harness'),saved.get('path'))
        if key in entries and entries[key].get('sha256')!=saved.get('sha256'):
            saved={**saved,'registration_conflict':True}
        entries[key]=dict(saved)
    entry_writes=[]
    if entries:
        state['host_entries']=refresh_registered_host_entries({**state,'host_entries':list(entries.values())},planned=entry_writes)
    retirement_writes, retirement_records = _prepare_retired_entries(state, host)
    entry_writes.extend(retirement_writes)
    records={path:state for path in paths}
    records.update(extra_records or {})
    records.update(retirement_records)
    receipt_path=app_home()/'runtime/sandbox-ready.json'
    receipt=read_json(receipt_path,{})
    if state.get('plugin_version') and host=='claude':
        records[receipt_path]={'schema':2,'host':'claude','applicable':False,'plugin_version':state['plugin_version']}
    elif state.get('plugin_version') and isinstance(receipt.get('schema'),int) and receipt['schema']>=2:
        records[receipt_path]={**receipt,'plugin_version':state['plugin_version']}
    before={path:path.read_bytes() if path.exists() else None for path in records}
    before.update(original_records)
    def verify_retired_guards(pending=()):
        # A same-version repair may plan zero writes. Its already-installed
        # guards are still part of the transaction and must be read back.
        for journal in retirement_records.values():
            for entry in journal['entries']:
                path=Path(entry['path'])
                if path in pending:continue
                try:
                    _no_reparse(path)
                    if hashlib.sha256(path.read_bytes()).hexdigest()!=entry['guard_sha256']:
                        raise InstallError('退役入口在核验期间变化，未覆盖。')
                except (OSError,InstallError) as exc:
                    raise InstallError(_retirement_block(state['plugin_version'],journal['old_plugin_version'])) from exc
    changed=bool(entry_writes) or any(read_json(path,{})!=value for path,value in records.items())
    if not changed:
        verify_retired_guards()
        return False
    bindings = []
    for path,value in records.items():
        if path in retirement_records:continue
        raw=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').replace('\n',os.linesep).encode('utf8')
        bindings.append({'path':str(path),'before_sha256':hashlib.sha256(before[path]).hexdigest() if before[path] is not None else None,
                         'after_sha256':hashlib.sha256(raw).hexdigest()})
    for path,journal in retirement_records.items():
        if not journal.get('record_bindings'):
            journal['record_bindings']=bindings
            prepared={**journal,'status':'prepared'}
            try:
                atomic_json(path,prepared)
                if read_json(path,{})!=prepared:raise InstallError('退役事务记录读回失败。')
            except Exception as exc:
                raise InstallError(_retirement_block(state['plugin_version'],journal['old_plugin_version'])) from exc
            before[path]=path.read_bytes()
    # Register original bytes before any destination write, including absent
    # files. Publication receipts distinguish our writes from independent edits.
    written_entries={path:{'before':old,'published':None} for path,old,_ in entry_writes}
    written_records={path:{'before':before[path],'published':None} for path in records}
    try:
        verify_retired_guards({path for path,_,_ in retirement_writes})
        for path,old,raw in entry_writes:
            _no_reparse(path)
            if (path.read_bytes() if path.exists() else None)!=old:raise InstallError('兼容入口在安装期间变化，未覆盖。')
            path.parent.mkdir(parents=True, exist_ok=True)
            temp=path.with_name('.SKILL.'+uuid.uuid4().hex+'.tmp')
            try:
                with temp.open('wb') as output:
                    output.write(raw);output.flush();os.fsync(output.fileno())
                _no_reparse(path)
                if (path.read_bytes() if path.exists() else None)!=old:raise InstallError('兼容入口在安装期间变化，未覆盖。')
                written_entries[path]['published']=_write_stamp(temp)
                os.replace(temp,path)
                if path.read_bytes()!=raw:raise InstallError('兼容入口读回不一致。')
            finally:temp.unlink(missing_ok=True)
        for path,value in records.items():
            _no_reparse(path)
            if (path.read_bytes() if path.exists() else None)!=before[path]:
                raise InstallError('安装记录在安装期间变化，未覆盖。')
            expected=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').replace('\n',os.linesep).encode('utf8')
            prior_write=getattr(_INSTALL_RECORD_WRITE,'current',None)
            _INSTALL_RECORD_WRITE.current=(path,written_records[path])
            try:
                atomic_json(path,value)
                if path.read_bytes()!=expected:raise InstallError('安装记录读回不一致。')
            finally:
                _INSTALL_RECORD_WRITE.current=prior_write
        if any(read_json(path,{})!=value for path,value in records.items()):
            raise InstallError('安装记录读回不一致。')
        if any(path.read_bytes()!=raw for path,_,raw in entry_writes):
            raise InstallError('兼容入口读回不一致。')
        verify_retired_guards()
    except Exception as exc:
        failures=[]
        # Records roll back BEFORE originals can become executable again. If
        # any active record was edited or cannot restore, guards remain closed.
        for path,receipt in written_records.items():
            try:
                _no_reparse(path)
                if not _owns_install_write(path,receipt):continue
                data=receipt['before']
                if data is None:path.unlink(missing_ok=True)
                else:
                    temp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.restore')
                    try:
                        temp.write_bytes(data)
                        if os.name!='nt':temp.chmod(0o600)
                        if not _owns_install_write(path,receipt):continue
                        os.replace(temp,path)
                    finally:temp.unlink(missing_ok=True)
            except (OSError,InstallError):failures.append(path.name)
        try:
            active_restored = all((path.read_bytes() if path.exists() else None)==before[path] for path in paths)
        except OSError:
            active_restored = False
        retired_paths = {path for path,_,_ in retirement_writes}
        for path,receipt in written_entries.items():
            if path in retired_paths and not active_restored:continue
            try:
                # Never undo a user edit made during installation or rollback.
                _no_reparse(path)
                if not _owns_install_write(path,receipt):continue
                if receipt['before'] is None:
                    path.unlink(missing_ok=True)
                    continue
                temp=path.with_name('.SKILL.'+uuid.uuid4().hex+'.restore')
                try:
                    temp.write_bytes(receipt['before'])
                    _no_reparse(path)
                    if not _owns_install_write(path,receipt):continue
                    os.replace(temp,path)
                finally:temp.unlink(missing_ok=True)
            except (OSError,InstallError):failures.append(path.name)
        try:previous=json.loads(original_records[paths[0]] or b'{}')
        except (ValueError,TypeError):previous={}
        message=_retirement_block(state.get('plugin_version') or state.get('version','未知版本'),
            previous.get('plugin_version') or previous.get('version') or '未知旧版')
        if failures:message+='旧记录恢复未完成，请重试安装与更新。'
        raise InstallError(message) from exc
    return True


def previous_install_identity(state):
    return {k:state[k] for k in ('version','plugin_version','home','source','launcher','python','config','installed_at') if k in state}


def verify_install_identity(meta, source, loaded=None, *, host='codex'):
    """Use signed release metadata and real manifests, never a newest-directory guess."""
    source=Path(source)
    for plugin in (source, Path(loaded) if loaded is not None else source):
        manifest=read_json(plugin/('.claude-plugin' if host=='claude' else '.codex-plugin')/'plugin.json',{})
        if manifest.get('version')!=meta['plugin_version'] or manifest.get('name',PLUGIN)!=PLUGIN:
            raise InstallError('实际插件清单与发行版本不一致，安装未完成。')
    saved=read_json(source.parents[1]/'source.json',{})
    if saved.get('payload_sha256')!=meta['files']['payload.enc']:
        raise InstallError('解密源身份与已验证发行包不一致。')
    from sandbox_support import check_files
    checked=check_files(source,required=saved.get('runtime_manifest_required',False))
    if loaded is not None and host=='claude' and checked.get('manifest'):
        check_files(loaded,expected=checked['manifest'])
    return meta['plugin_version']


def migrate_config(target, sources):
    target=Path(target)
    if target.exists():return 'preserved'
    for source in sources:
        if source and Path(source).is_file():
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(source,target)
            if os.name != 'nt':target.chmod(0o600)
            if target.read_bytes()!=Path(source).read_bytes():raise InstallError('配置迁移校验失败。')
            return 'migrated'
    return 'missing'


def _toml_table_rx(name):
    return re.compile(r'(?m)^\['+re.escape(name)+r'\][^\r\n]*(?:\r?\n|$)(?:(?!\s*\[)[^\r\n]*(?:\r?\n|$))*')


def replace_toml_section(text, name, section):
    # Keep unrelated tables byte-for-byte; fail closed on duplicate/invalid TOML.
    tomllib.loads(text)
    rx=_toml_table_rx(name)
    if rx.search(text):result=rx.sub(lambda _:section.rstrip()+'\n\n',text,count=1)
    else:result=text.rstrip()+'\n\n'+section.rstrip()+'\n'
    tomllib.loads(result)
    return result


def remove_toml_section(text, name):
    tomllib.loads(text)
    result=_toml_table_rx(name).sub('',text,count=1)
    tomllib.loads(result)
    return result


SIF_SERVER_NAMES = frozenset({'sif_mcp', 'sif-mcp', 'sif'})

# rc.24: screenshot showed 5 legacy `type = "stdio"` warnings on user machines
# (1688/ads/selection/promotion/sif). New writes no longer emit it; this sweeps
# leftovers on install/update without touching unknown user keys like features.*.
MANAGED_MCP_TABLES = ('1688_scraper', 'ads_knowledge_base', 'selection_knowledge_base', 'promotion_knowledge_base')

def clean_managed_mcp_types():
    cfg = codex_home() / 'config.toml'
    if not cfg.exists():
        return 0
    try:
        text = cfg.read_text(encoding='utf-8-sig')
    except OSError:
        return 0
    if 'type' not in text:
        return 0
    try:
        before = tomllib.loads(text) if text.strip() else {}
    except Exception:
        return 0
    servers = before.get('mcp_servers', {}) if isinstance(before, dict) else {}
    cleaned = 0
    result = text
    for key in MANAGED_MCP_TABLES:
        if not isinstance(servers.get(key), dict) or servers[key].get('type') != 'stdio':
            continue
        result = _toml_table_rx('mcp_servers.' + key).sub(
            lambda m: re.sub(r'(?m)^[ \t]*type[ \t]*=[ \t]*[\"\']stdio[\"\'][ \t]*(?:#[^\r\n]*)?\r?\n', '', m.group()),
            result, count=1)
        cleaned += 1
    if not cleaned:
        return 0
    try:
        tomllib.loads(result)
    except Exception:
        return 0
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    try:
        shutil.copy2(cfg, cfg.with_name('config.toml.bak-starsky-cleantype-' + stamp))
    except OSError:
        pass
    temp = cfg.with_name('config.toml.' + uuid.uuid4().hex + '.tmp')
    temp.write_text(result, encoding='utf8')
    os.replace(temp, cfg)
    return cleaned


def _toml_server_key(header):
    if not header.startswith('mcp_servers.'):
        return None, None
    rest = header[len('mcp_servers.'):]
    if rest.startswith(('"', "'")):
        end = rest.find(rest[0], 1)
        if end < 0:
            return None, None
        return rest[1:end], rest[end + 1:]
    key, sep, nested = rest.partition('.')
    return key, ('.' + nested if sep else '')


def sif_toml_headers(text):
    headers = []
    for match in re.finditer(r'(?m)^\[([^\]\n]+)\]', text):
        key, nested = _toml_server_key(match.group(1))
        if key in SIF_SERVER_NAMES:
            headers.append((match.group(1), key, nested))
    return headers


def apply_sif_http():
    """SIF is the official HTTP endpoint. An existing SIF entry is never rewritten; a new one is
    registered only when the user already holds a key in the environment."""
    cfg = codex_home() / 'config.toml'
    text = cfg.read_text(encoding='utf-8-sig') if cfg.exists() else ''
    servers = tomllib.loads(text).get('mcp_servers', {})
    if any(name in SIF_SERVER_NAMES for name in servers):
        print('SIF：保留已有连接和认证配置。')
        return None
    key_name = sif_key_available()
    if not key_name:
        print('SIF 尚未配置：未找到 SIF_MCP_TOKEN 或 SIF_MCP_SECRET_KEY；请先按说明设置本机环境变量。')
        return None
    section = ('[mcp_servers.sif_mcp]\nurl = "https://mcp.sif.com/mcp"\n'
               'env_http_headers = { "secret-key" = '+json.dumps(key_name)+' }\n'
               'enabled = true\nstartup_timeout_sec = 30\ntool_timeout_sec = 180\n')
    updated = replace_toml_section(text, 'mcp_servers.sif_mcp', section)
    cfg.parent.mkdir(parents=True, exist_ok=True)
    if cfg.exists():
        shutil.copy2(cfg, cfg.with_name('config.toml.bak-starsky-sif-'+uuid.uuid4().hex))
    temp = cfg.with_name('config.toml.'+uuid.uuid4().hex+'.tmp')
    temp.write_text(updated, encoding='utf8')
    os.replace(temp, cfg)
    print('SIF：已登记官方 HTTP 直连；请重开 Codex，在新会话调用 ping。')
    return None


def sif_key_available():
    names = ('SIF_MCP_TOKEN', 'SIF_MCP_SECRET_KEY')
    for name in names:
        if os.environ.get(name, '').strip():
            return name
    if os.name == 'nt':
        import winreg
        for name in names:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment') as handle:
                    if str(winreg.QueryValueEx(handle, name)[0]).strip():
                        return name
            except OSError:
                pass
    return None


def validate_ads_kb(source, python):
    """Validate a distributable snapshot through its actual read-only MCP status."""
    source = Path(source)
    required_files = ('server.py', 'kb.py', 'kb/kb_manifest.yaml', 'kb/learning_plan.yaml',
                      'kb/taxonomy.yaml', 'kb/knowledge_pack_for_ads.yaml', 'kb/sources/manifest.yaml')
    missing = [name for name in required_files if not (source / name).is_file()]
    if missing or not any((source / 'kb/cards').glob('KC-*.md')):
        raise InstallError('广告知识库快照不完整，未安装：'+', '.join(missing or ['kb/cards/KC-*.md']))
    messages = [
        {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
            'protocolVersion': '2025-03-26', 'capabilities': {}, 'clientInfo': {'name': 'starsky-installer', 'version': '1'}}},
        {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'kb_status', 'arguments': {}}},
    ]
    output = run_checked([python, '-B', source / 'server.py', '--kb', source / 'kb'],
                         input=''.join(json.dumps(m)+'\n' for m in messages), timeout=30,
                         env={**os.environ, 'PYTHONUTF8': '1', 'PYTHONDONTWRITEBYTECODE': '1'})
    try:
        replies = [json.loads(line) for line in output.splitlines() if line.strip()]
        reply = next(m for m in replies if m.get('id') == 2)
        result = reply.get('result') or {}
        if reply.get('error') or result.get('isError'):
            raise ValueError('status failed')
        status = json.loads(result['content'][0]['text'])
        completion = status.get('curriculum_completion')
        if not isinstance(completion, str) or not re.fullmatch(r'\d+/[1-9]\d*', completion):
            raise ValueError('curriculum unavailable')
        if not (status.get('stats') or {}).get('cards'):
            raise ValueError('no cards')
    except (ValueError, KeyError, IndexError, StopIteration, TypeError) as exc:
        raise InstallError('广告知识库 kb_status 实测失败，未通过完整快照校验。请重新下载修复版。') from exc
    return status


def ads_kb_section(python, dest):
    script = Path(dest) / 'server.py'
    kb = Path(dest) / 'kb'
    return (
        '[mcp_servers.ads_knowledge_base]\n'
        'command = ' + json.dumps(str(python)) + '\n'
        'args = ' + json.dumps([str(script), '--kb', str(kb)]) + '\n'
        'cwd = ' + json.dumps(str(dest)) + '\n'
        'enabled = true\n'
        'required = false\n'
        'startup_timeout_sec = 60\n'
        'tool_timeout_sec = 120\n\n'
        '[mcp_servers.ads_knowledge_base.env]\n'
        'PYTHONUTF8 = "1"\n'
    )


def apply_ads_kb(source, python, required=False):
    """Copy the bundled ads knowledge snapshot outside the plugin cache."""
    server = Path(source) / 'server.py'
    kb = Path(source) / 'kb'
    if not server.is_file() or not (kb / 'kb_manifest.yaml').is_file():
        if required:
            raise InstallError('插件包缺少广告知识库快照，请使用含 ads-kb 的星空版本。')
        return None
    dest = codex_home() / 'mcp/starsky-ads-kb'
    if dest.exists() and not (dest / '.starsky-managed').exists():
        message = '已有非星空受管的广告知识库目录，拒绝覆盖。'
        if required:
            raise InstallError(message)
        print(message)
        return None
    validate_ads_kb(source, python)
    dest.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:6]
    for src in [server, Path(source) / 'kb.py', Path(source) / 'smoke_test.py']:
        if not src.is_file():
            continue
        target = dest / src.name
        if target.exists():
            backup = dest / '_backup' / stamp
            backup.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, backup / src.name)
        shutil.copy2(src, target)
    kb_dest = dest / 'kb'
    if kb_dest.exists():
        backup = dest / '_backup' / stamp / 'kb'
        if backup.exists():
            shutil.rmtree(backup)
        shutil.copytree(kb_dest, backup)
        shutil.rmtree(kb_dest)
    shutil.copytree(kb, kb_dest, ignore=shutil.ignore_patterns('sessions', 'extracted', 'raw', '__pycache__'))
    validate_ads_kb(dest, python)
    (dest / '.starsky-managed').write_text('managed-by=starsky-codex\n', encoding='utf8')
    cfg = codex_home() / 'config.toml'
    text = cfg.read_text(encoding='utf-8-sig') if cfg.exists() else ''
    if text.strip():
        tomllib.loads(text)
        text = remove_toml_section(text, 'mcp_servers.ads_knowledge_base.env')
        text = remove_toml_section(text, 'mcp_servers.ads_knowledge_base')
    updated = text.rstrip()
    if updated:
        updated += '\n\n'
    updated += ads_kb_section(python, dest).rstrip() + '\n'
    tomllib.loads(updated)
    cfg.parent.mkdir(parents=True, exist_ok=True)
    if cfg.exists():
        shutil.copy2(cfg, cfg.with_name('config.toml.bak-starsky-adskb-' + stamp))
    temp = cfg.with_name('config.toml.' + uuid.uuid4().hex + '.tmp')
    temp.write_text(updated, encoding='utf8')
    os.replace(temp, cfg)
    return dest


def validate_selection_kb(source, python):
    """Validate a distributable selection snapshot through its actual read-only MCP status."""
    source = Path(source)
    required_files = ('server.py', 'kb.py', 'kb/kb_manifest.yaml', 'kb/learning_plan.yaml',
                      'kb/taxonomy.yaml', 'kb/knowledge_pack_for_selection.yaml', 'kb/sources/manifest.yaml')
    missing = [name for name in required_files if not (source / name).is_file()]
    if missing or not any((source / 'kb/cards').glob('KC-*.md')):
        raise InstallError('选品知识库快照不完整，未安装：'+', '.join(missing or ['kb/cards/KC-*.md']))
    messages = [
        {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
            'protocolVersion': '2025-03-26', 'capabilities': {}, 'clientInfo': {'name': 'starsky-installer', 'version': '1'}}},
        {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'kb_status', 'arguments': {}}},
    ]
    output = run_checked([python, '-B', source / 'server.py', '--kb', source / 'kb'],
                         input=''.join(json.dumps(m)+'\n' for m in messages), timeout=30,
                         env={**os.environ, 'PYTHONUTF8': '1', 'PYTHONDONTWRITEBYTECODE': '1'})
    try:
        replies = [json.loads(line) for line in output.splitlines() if line.strip()]
        reply = next(m for m in replies if m.get('id') == 2)
        result = reply.get('result') or {}
        if reply.get('error') or result.get('isError'):
            raise ValueError('status failed')
        status = json.loads(result['content'][0]['text'])
        completion = status.get('curriculum_completion')
        if not isinstance(completion, str) or not re.fullmatch(r'\d+/[1-9]\d*', completion):
            raise ValueError('curriculum unavailable')
        if not (status.get('stats') or {}).get('cards'):
            raise ValueError('no cards')
    except (ValueError, KeyError, IndexError, StopIteration, TypeError) as exc:
        raise InstallError('选品知识库 kb_status 实测失败，未通过完整快照校验。请重新下载修复版。') from exc
    return status


def selection_kb_section(python, dest):
    script = Path(dest) / 'server.py'
    kb = Path(dest) / 'kb'
    return (
        '[mcp_servers.selection_knowledge_base]\n'
        'command = ' + json.dumps(str(python)) + '\n'
        'args = ' + json.dumps([str(script), '--kb', str(kb)]) + '\n'
        'cwd = ' + json.dumps(str(dest)) + '\n'
        'enabled = true\n'
        'required = false\n'
        'startup_timeout_sec = 60\n'
        'tool_timeout_sec = 120\n\n'
        '[mcp_servers.selection_knowledge_base.env]\n'
        'PYTHONUTF8 = "1"\n'
    )


def apply_selection_kb(source, python, required=False):
    """Copy the bundled selection knowledge snapshot outside the plugin cache."""
    server = Path(source) / 'server.py'
    kb = Path(source) / 'kb'
    if not server.is_file() or not (kb / 'kb_manifest.yaml').is_file():
        if required:
            raise InstallError('插件包缺少选品知识库快照，请使用含 selection-kb 的星空版本。')
        return None
    dest = codex_home() / 'mcp/starsky-selection-kb'
    if dest.exists() and not (dest / '.starsky-managed').exists():
        message = '已有非星空受管的选品知识库目录，拒绝覆盖。'
        if required:
            raise InstallError(message)
        print(message)
        return None
    validate_selection_kb(source, python)
    dest.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:6]
    for src in [server, Path(source) / 'kb.py', Path(source) / 'smoke_test.py']:
        if not src.is_file():
            continue
        target = dest / src.name
        if target.exists():
            backup = dest / '_backup' / stamp
            backup.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, backup / src.name)
        shutil.copy2(src, target)
    kb_dest = dest / 'kb'
    if kb_dest.exists():
        backup = dest / '_backup' / stamp / 'kb'
        if backup.exists():
            shutil.rmtree(backup)
        shutil.copytree(kb_dest, backup)
        shutil.rmtree(kb_dest)
    shutil.copytree(kb, kb_dest, ignore=shutil.ignore_patterns('sessions', 'extracted', 'raw', '__pycache__'))
    validate_selection_kb(dest, python)
    (dest / '.starsky-managed').write_text('managed-by=starsky-codex\n', encoding='utf8')
    cfg = codex_home() / 'config.toml'
    text = cfg.read_text(encoding='utf-8-sig') if cfg.exists() else ''
    if text.strip():
        tomllib.loads(text)
        text = remove_toml_section(text, 'mcp_servers.selection_knowledge_base.env')
        text = remove_toml_section(text, 'mcp_servers.selection_knowledge_base')
    updated = text.rstrip()
    if updated:
        updated += '\n\n'
    updated += selection_kb_section(python, dest).rstrip() + '\n'
    tomllib.loads(updated)
    cfg.parent.mkdir(parents=True, exist_ok=True)
    if cfg.exists():
        shutil.copy2(cfg, cfg.with_name('config.toml.bak-starsky-selectionkb-' + stamp))
    temp = cfg.with_name('config.toml.' + uuid.uuid4().hex + '.tmp')
    temp.write_text(updated, encoding='utf8')
    os.replace(temp, cfg)
    return dest


def validate_promotion_kb(source, python):
    """Validate a distributable promotion snapshot through its actual read-only MCP status."""
    source = Path(source)
    required_files = ('server.py', 'kb.py', 'kb/kb_manifest.yaml', 'kb/learning_plan.yaml',
                      'kb/taxonomy.yaml', 'kb/knowledge_pack_for_promotion.yaml', 'kb/sources/manifest.yaml')
    missing = [name for name in required_files if not (source / name).is_file()]
    if missing or not any((source / 'kb/cards').glob('PK-*.md')):
        raise InstallError('产品推广知识库快照不完整，未安装：'+', '.join(missing or ['kb/cards/PK-*.md']))
    messages = [
        {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
            'protocolVersion': '2025-03-26', 'capabilities': {}, 'clientInfo': {'name': 'starsky-installer', 'version': '1'}}},
        {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'kb_status', 'arguments': {}}},
    ]
    output = run_checked([python, '-B', source / 'server.py', '--kb', source / 'kb'],
                         input=''.join(json.dumps(m)+'\n' for m in messages), timeout=30,
                         env={**os.environ, 'PYTHONUTF8': '1', 'PYTHONDONTWRITEBYTECODE': '1'})
    try:
        replies = [json.loads(line) for line in output.splitlines() if line.strip()]
        reply = next(m for m in replies if m.get('id') == 2)
        result = reply.get('result') or {}
        if reply.get('error') or result.get('isError'):
            raise ValueError('status failed')
        status = json.loads(result['content'][0]['text'])
        if not (status.get('stats') or {}).get('cards'):
            raise ValueError('no cards')
    except (ValueError, KeyError, IndexError, StopIteration, TypeError) as exc:
        raise InstallError('产品推广知识库 kb_status 实测失败，未通过完整快照校验。请重新下载修复版。') from exc
    return status


def promotion_kb_section(python, dest):
    script = Path(dest) / 'server.py'
    kb = Path(dest) / 'kb'
    return (
        '[mcp_servers.promotion_knowledge_base]\n'
        'command = ' + json.dumps(str(python)) + '\n'
        'args = ' + json.dumps([str(script), '--kb', str(kb)]) + '\n'
        'cwd = ' + json.dumps(str(dest)) + '\n'
        'enabled = true\n'
        'required = false\n'
        'startup_timeout_sec = 60\n'
        'tool_timeout_sec = 120\n\n'
        '[mcp_servers.promotion_knowledge_base.env]\n'
        'PYTHONUTF8 = "1"\n'
    )


def apply_promotion_kb(source, python, required=False):
    """Copy the bundled promotion knowledge snapshot outside the plugin cache."""
    server = Path(source) / 'server.py'
    kb = Path(source) / 'kb'
    if not server.is_file() or not (kb / 'kb_manifest.yaml').is_file():
        if required:
            raise InstallError('插件包缺少产品推广知识库快照，请使用含 promotion-kb 的星空版本。')
        return None
    dest = codex_home() / 'mcp/starsky-promotion-kb'
    if dest.exists() and not (dest / '.starsky-managed').exists():
        message = '已有非星空受管的产品推广知识库目录，拒绝覆盖。'
        if required:
            raise InstallError(message)
        print(message)
        return None
    validate_promotion_kb(source, python)
    dest.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:6]
    for src in [server, Path(source) / 'kb.py', Path(source) / 'smoke_test.py']:
        if not src.is_file():
            continue
        target = dest / src.name
        if target.exists():
            backup = dest / '_backup' / stamp
            backup.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, backup / src.name)
        shutil.copy2(src, target)
    kb_dest = dest / 'kb'
    if kb_dest.exists():
        backup = dest / '_backup' / stamp / 'kb'
        if backup.exists():
            shutil.rmtree(backup)
        shutil.copytree(kb_dest, backup)
        shutil.rmtree(kb_dest)
    shutil.copytree(kb, kb_dest, ignore=shutil.ignore_patterns('sessions', 'extracted', 'raw', '__pycache__'))
    validate_promotion_kb(dest, python)
    (dest / '.starsky-managed').write_text('managed-by=starsky-codex\n', encoding='utf8')
    cfg = codex_home() / 'config.toml'
    text = cfg.read_text(encoding='utf-8-sig') if cfg.exists() else ''
    if text.strip():
        tomllib.loads(text)
        text = remove_toml_section(text, 'mcp_servers.promotion_knowledge_base.env')
        text = remove_toml_section(text, 'mcp_servers.promotion_knowledge_base')
    updated = text.rstrip()
    if updated:
        updated += '\n\n'
    updated += promotion_kb_section(python, dest).rstrip() + '\n'
    tomllib.loads(updated)
    cfg.parent.mkdir(parents=True, exist_ok=True)
    if cfg.exists():
        shutil.copy2(cfg, cfg.with_name('config.toml.bak-starsky-promotionkb-' + stamp))
    temp = cfg.with_name('config.toml.' + uuid.uuid4().hex + '.tmp')
    temp.write_text(updated, encoding='utf8')
    os.replace(temp, cfg)
    return dest


def find_codex():
    explicit=os.environ.get('STARSKY_CODEX_CLI')
    candidates=[Path(explicit)] if explicit else []
    found=shutil.which('codex')
    if found:candidates.append(Path(found))
    if os.name=='nt':
        local=Path(os.environ.get('LOCALAPPDATA',str(Path.home()/'AppData/Local')))
        candidates.extend(sorted((local/'OpenAI/Codex/bin').glob('*/codex.exe'),key=lambda p:p.stat().st_mtime,reverse=True))
        candidates.extend([codex_home()/'plugins/.plugin-appserver/codex.exe',codex_home()/'.sandbox-bin/codex.exe'])
    else:
        apps=[Path('/Applications'),Path.home()/'Applications']
        # Newer ChatGPT.app builds (2026-09) ship the CLI at Resources/codex-cli/bin/codex; older ones at Resources/codex.
        candidates.extend(app/name/'Contents/Resources/codex-cli/bin/codex' for app in apps for name in ('ChatGPT.app','Codex.app'))
        candidates.extend([
            Path('/Applications/Codex.app/Contents/Resources/codex'),
            Path.home()/'Applications/Codex.app/Contents/Resources/codex',
            # The Mac field test uses Codex bundled inside ChatGPT.app.
            Path('/Applications/ChatGPT.app/Contents/Resources/codex'),
            Path.home()/'Applications/ChatGPT.app/Contents/Resources/codex',
            Path('/opt/homebrew/bin/codex'),
            Path('/usr/local/bin/codex'),
        ])
    for p in candidates:
        if p.is_file():
            try:
                run_checked([p,'plugin','add','--help'])
                return p
            except InstallError:continue
    raise InstallError('未找到支持插件命令的 Codex CLI。请安装并打开官方 Codex；也可用 STARSKY_CODEX_CLI 指定其路径。')


def read_json(path, default=None):
    if not Path(path).exists():return default
    try:return json.loads(Path(path).read_text(encoding='utf-8-sig'))
    except Exception as exc:raise InstallError(f'配置格式错误：{Path(path).name}；请备份后联系作者。') from exc


def mac_filesystem_metadata(path, bundle, expected):
    """Ignore only recognized Finder records; never ignore arbitrary hidden code."""
    relative = path.relative_to(bundle).as_posix()
    if relative in expected:
        return False
    with path.open('rb') as stream:
        header = stream.read(8)
    if path.name == '.DS_Store':
        return header == b'\x00\x00\x00\x01Bud1'
    if path.name.startswith('._') and header == b'\x00\x05\x16\x07\x00\x02\x00\x00':
        paired = path.with_name(path.name[2:])
        paired_relative = paired.relative_to(bundle).as_posix()
        return paired_relative in expected or paired.name in {'bundle.json', 'bundle.sig'} or paired.is_dir()
    return False


def verify_bundle(bundle):
    bundle=Path(bundle)
    raw=(bundle/'bundle.json').read_bytes()
    verify_signature(raw,base64.b64decode((bundle/'bundle.sig').read_text()),(bundle/'license_public.pem').read_bytes())
    metadata=json.loads(raw)
    if metadata.get('product')!=PRODUCT:raise InstallError('安装包产品不匹配。')
    safe_member(metadata['version'])
    expected=metadata['files']
    actual={p.relative_to(bundle).as_posix() for p in bundle.rglob('*') if p.is_file() and p.name not in {'bundle.json','bundle.sig'} and '__pycache__' not in p.parts and not mac_filesystem_metadata(p,bundle,expected)}
    if actual!=set(expected):
        missing = sorted(set(expected) - actual)
        extra = sorted(actual - set(expected))
        details = (' 缺少：' + '、'.join(missing[:5]) if missing else '') + (' 多出：' + '、'.join(extra[:5]) if extra else '')
        raise InstallError('安装包文件清单不完整或多出未知文件，请重新解压官方 ZIP。' + details)
    for name,digest in expected.items():safe_member(name);verify_file(bundle/name,digest)
    return metadata


def decrypt_payload(bundle, meta, authorization):
    """The decryption secret comes only from the privately issued license."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        encryption = meta['encryption']
        if encryption['algorithm'] != 'AES-256-GCM':
            raise ValueError('algorithm')
        secret = b64decode(authorization['content_keys'][encryption['key_id']])
        if len(secret) != 32:
            raise ValueError('key length')
        aad = json.dumps({'product': PRODUCT, 'version': meta['version'],
                          'key_id': encryption['key_id']}, sort_keys=True, separators=(',', ':')).encode()
        encrypted = (Path(bundle) / 'payload.enc').read_bytes()
        plain = AESGCM(secret).decrypt(encrypted[:12], encrypted[12:], aad)
        return io.BytesIO(plain)
    except Exception as exc:
        raise InstallError('本授权不能解密此发行包，或加密文件已损坏。请联系坚哥取得本版本授权码。') from exc


def preflight_license(bundle):
    """Validate authorization before runtime provisioning or dependency downloads."""
    bundle = Path(bundle)
    meta = verify_bundle(bundle)
    public = (bundle / 'license_public.pem').read_bytes()
    device = fingerprint()
    path = app_home() / 'license.json'
    activation_path = app_home() / 'activation.json'
    stored = read_json(path, {})
    activation = read_json(activation_path, {})
    key_id = meta.get('encryption', {}).get('key_id')
    def validate(code):
        obj = verify_license(code, public, device)
        if meta.get('tier') and obj.get('tier', 'basic') != meta['tier']:
            raise InstallError('授权版本档与本安装包不一致，请下载对应版本档的安装包。')
        keys = obj.get('content_keys', {})
        if not isinstance(keys, dict) or not keys:
            raise InstallError('授权缺少发行包权限，请联系作者。')
        if key_id and key_id not in keys and obj.get('update_policy') != 'membership':
            raise InstallError('固定版本授权不包含本发行包，请联系作者取得对应版本 Key。')
        return obj
    print('先核验本机授权；通过后才下载依赖并执行安装。', flush=True)
    # A ready runtime can also verify signed, encrypted renewals before provisioning
    # a new requirements environment. The normal installer rechecks all permissions.
    for candidate in dict.fromkeys((stored.get('code', ''), activation.get('code', ''))):
        if not candidate:
            continue
        try:
            obj = validate(candidate)
            print('已保存的授权校验通过，无需重新输入 KEY。', flush=True)
            return obj
        except InstallError as exc:
            print(str(exc), flush=True)
            try:
                anchor = verify_license(candidate, public, device, allow_expired=True)
                if anchor.get('update_policy') != 'membership' or (meta.get('tier') and anchor.get('tier', 'basic') != meta['tier']):
                    raise exc
                import cryptography
                obj = ensure_license(bundle)
                print('会员授权校验通过，可以准备运行环境。', flush=True)
                return obj
            except (ImportError, InstallError):
                pass
    print(f'\n产品：{LABEL}\n本机申请码：{device}\n申请授权：{CONTACT}', flush=True)
    print('请发送产品名、Windows/Mac 和本机申请码，不要发送账号密码或 API Key。', flush=True)
    if not sys.stdin.isatty():
        raise InstallError('尚无有效授权。请在终端交互运行，输入 KEY 后再安装。')
    print(f'请输入授权 KEY：粘贴完整的 {LICENSE_PREFIX}. 授权码，然后按回车确认。', flush=True)
    code = input().strip()
    obj = validate(code)
    atomic_json(activation_path, {'code': code})
    atomic_json(path, {'code': code})
    print('授权校验通过，开始准备运行环境。', flush=True)
    return obj


def ensure_license(bundle):
    import member_updates
    path=app_home()/'license.json';stored=read_json(path,{})
    code=stored.get('code','');public=(Path(bundle)/'license_public.pem').read_bytes();device=fingerprint()
    meta=read_json(Path(bundle)/'bundle.json',{})
    key_id=meta.get('encryption',{}).get('key_id')
    activation_path=app_home()/'activation.json'
    activation=read_json(activation_path,{})
    def remember(candidate, replace=False):
        verify_license(candidate,public,device,allow_expired=True)
        if replace or not activation_path.exists():atomic_json(activation_path,{'code':candidate})
    def validate(candidate):
        obj=verify_license(candidate,public,device)
        if key_id and key_id not in obj.get('content_keys',{}):
            raise InstallError('原授权尚未包含本发行包权限，正在尝试核验会员更新凭证。')
        return obj
    if code:
        try:
            remember(code)
            return validate(code)
        except InstallError as exc:print(str(exc))
    anchor=activation.get('code') or code
    if anchor:
        try:
            refreshed=member_updates.fetch_grant(anchor,bundle,meta,device,download)
            obj=validate(refreshed)
            remember(anchor)
            atomic_json(path,{'code':refreshed})
            print('会员更新权限已自动核验，无需重新输入授权码。')
            return obj
        except member_updates.GrantError as exc:
            print(str(exc))
    print(f'\n产品：{LABEL}\n本机申请码：{device}\n申请授权：{CONTACT}')
    print('请发送产品名、Windows/Mac、上面的申请码。不要发送 Codex 密码或 API Key。')
    if not sys.stdin.isatty():raise InstallError('尚无有效授权，请在终端交互运行安装器并粘贴授权码。')
    # PowerShell forwards native stdout by line: input(prompt) has no newline,
    # so it hides the prompt until after the user has already pressed Enter.
    print(f'请输入授权 KEY：粘贴完整的 {LICENSE_PREFIX}. 授权码，然后按回车确认。', flush=True)
    code=input().strip()
    original_code=code
    try:
        obj=validate(code)
    except InstallError:
        try:
            code=member_updates.fetch_grant(original_code,bundle,meta,device,download)
            obj=validate(code)
        except member_updates.GrantError as exc:
            raise InstallError(str(exc)) from exc
    remember(original_code,replace=True)
    atomic_json(path,{'code':code})
    print('授权通过，有效期至 '+obj['expires']+'（北京时间 UTC+08:00，当日结束）')
    return obj


def installed_conflicts():
    cfg=codex_home()/'config.toml'
    if not cfg.exists():return []
    config=tomllib.loads(cfg.read_text(encoding='utf-8-sig'))
    return [k for k,v in config.get('plugins',{}).items() if k.startswith(PLUGIN+'@') and k!=PLUGIN+'@'+MARKET and v.get('enabled',False)]


def print_user_guide(launcher):
    if not launcher:
        return
    guide = Path(launcher)/'00-使用说明.html'
    if guide.is_file():
        print('使用说明（用浏览器打开）：'+str(guide))
        print('同目录另有“01-口令速查.html”“02-MCP配置必读.html”和“03-MCP优惠购买入口.html”，均可离线阅读。')


def host_entry_text(state=None, harness=None):
    """A discoverable entry only; business files and version stay in one install."""
    return f'''---
name: starsky-amazon-agent
description: 星空亚马逊 Agent 的 CodexHost 兼容入口。用户说启动星空、启动星空 S1/S2/S3/S4/S5、继续星空、今日巡检，或引用星空亚马逊 Agent 插件时使用。在当前会话运行，不委托其他 Agent。
---

# 星空亚马逊 Agent · 当前会话入口 · {(state or {}).get('plugin_version') or (state or {}).get('version') or '跟随安装记录'}

这是已安装 Codex 插件的兼容定位入口，不是一份独立业务插件。
实际工具：{harness or '当前宿主'}。先完成正式入口检查，不要按其他旧 SOP 拼造启动卡；启动卡只显示星空版本与 S1–S5 选择，不转述兼容入口日志。

1. 读取安装记录 `{(app_home() / 'current.json').as_posix()}`，取 `source` 为插件根、`python` 为专用运行环境。
2. 读取 `<source>/skills/starsky-amazon-agent/SKILL.md`，在当前会话执行其入口规则。只说“启动星空”就返回 S1–S5 选择卡，等用户选阶段；入口读取不扩展为业务执行。未点选不调 MCP，不做市场调研。
3. 专业 Skill 按需读取 `<source>/skills/<技能名>/SKILL.md`。所有业务相对路径按这些真实文件的位置解析；不要从本兼容入口目录推算插件根。模板和脚本位于 `<source>/templates`、`<source>/scripts`。
4. 沿用用户当前模型，不要求切换模型。GPT-6 的分阶段建议仅供主动选择，不适用于强制约束第三方模型；启动时说明“沿用当前模型”，步骤卡中的官方推荐可忽略。不自动切换，不因模型名、品牌或推理档位暂停，不委托 Codex/GPT 来替做。
5. “启动星空”及 `plugin://starsky-amazon-agent@starskycodex` 指的是本地插件，**不要委托**、不要调用 `codexhost delegate`、不要新建后台任务。
6. 选定业务后先使用会话已有 MCP 工具。没有原生工具时，在用户授权与宿主权限范围内用记录中的 Python 调用 `<source>/scripts/starsky_mcp.py --config "{(codex_home() / 'config.toml').as_posix()}" --server <名称> list|schema|call`。
   - Sorftime：`--server sorftime call get_time '{{}}'`；SIF：`--server sif_mcp call ping '{{}}'`。
   - 知识库、1688 等本地 stdio 也使用同一脚本，先 `list`、再 `schema <工具>`，最后 `call <工具> @<参数.json>`；不要猜入参，不打印配置或凭证。
   - 桥接会读取既有 Codex 配置及凭证绑定，不让用户重复安装 MCP。成功记 `direct_bridge`；不能声称工具已原生注入。禁用、缺密钥、权限拒绝或服务错误如实报告，不绕过限制。
7. 安装记录或入口文件缺失时说明具体缺项，建议运行星空“安装与更新”；不要改用外部委托，不伪称已接通。证据、预算、真实数据和人工审核要求在任何模型下保持一致。
8. 执行每条星空控制器命令时，给该子进程设置 `STARSKY_HOST_ID={harness or '实际宿主ID'}`。原生日志必须绑定宿主确认的当前会话 ID（可用 `STARSKY_SESSION_ID` 传入；禁止从最近修改文件猜测）；身份未知时只尝试 Host 当前线程的真实后续用户回合，仍无证据则阻断。不要从 Codex 会话记录冒认 Pi 回合。每张步骤卡单独作为最终回复，不用进度消息或多张卡合并交付；下一次工具调用再 ack，再用独立调用 begin。
'''


HOST_ENTRY_SPECS = entry_specs()


def host_entry_targets(user, honor_environment=True):
    """Native discovery roots; never install a duplicate into Codex's .agents root.

    Evidence and unverified hosts are recorded in user-guide/host_compatibility.md.
    A discovery root is independent of the provider/model selected by that host.
    """
    targets = []
    for harness, relative, variable in HOST_ENTRY_SPECS:
        root = Path(user) / relative
        if honor_environment:
            if variable and os.environ.get(variable):
                root = Path(os.environ[variable]).expanduser()
            elif harness == 'opencode' and os.environ.get('XDG_CONFIG_HOME'):
                root = Path(os.environ['XDG_CONFIG_HOME']).expanduser() / 'opencode'
        targets.append((harness, root / 'skills' / PLUGIN))
    return targets


def deploy_host_entries(state, user_home=None):
    """Install owned native entry files without touching official Codex discovery."""
    source = Path(state['source'])
    if not (source / 'skills' / PLUGIN / 'SKILL.md').is_file():
        raise InstallError('兼容入口未安装：星空源文件缺失。')
    user = Path(user_home) if user_home is not None else Path.home()
    targets = host_entry_targets(user, honor_environment=user_home is None)
    records = []
    for harness, directory in targets:
        content = host_entry_text(state, harness).encode('utf8')
        digest = hashlib.sha256(content).hexdigest()
        entry = directory / 'SKILL.md'
        marker = directory / '.starsky-entry.json'
        row = {'harness': harness, 'path': str(entry), 'status': 'error'}
        try:
            # Never traverse or replace a pre-existing junction/symlink entry.
            linked = any(p.is_symlink() or bool(getattr(p.lstat(), 'st_file_attributes', 0) & 0x400)
                         for p in (directory, entry, marker) if p.exists() or p.is_symlink())
            saved = read_json(marker, {}) if not linked else {}
            owned = (not linked and saved.get('managed_by') == PRODUCT and entry.is_file()
                     and saved.get('sha256') == hashlib.sha256(entry.read_bytes()).hexdigest())
            if linked or (directory.exists() and not owned):
                row.update(status='conflict', reason='已有同名目录、链接或用户改动，未覆盖')
            else:
                directory.mkdir(parents=True, exist_ok=True)
                if not entry.exists() or entry.read_bytes() != content:
                    if entry.exists():
                        backup = app_home() / 'backups/host-entries' / (harness + '-' + uuid.uuid4().hex + '.md')
                        backup.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(entry, backup)
                    temp = entry.with_name('.SKILL.' + uuid.uuid4().hex + '.tmp')
                    temp.write_bytes(content)
                    os.replace(temp, entry)
                atomic_json(marker, {'managed_by': PRODUCT, 'schema_version': 1, 'sha256': digest})
                if hashlib.sha256(entry.read_bytes()).hexdigest() != digest:
                    raise InstallError('兼容入口回读不一致')
                row.update(status='ready', evidence='file_readback', sha256=digest)
        except (OSError, ValueError, InstallError) as exc:
            row.update(status='error', reason=type(exc).__name__)
        records.append(row)
    return records



def refresh_registered_host_entries(state, user_home=None, *, planned=None):
    """Refresh registered supported entries; preserve every other host and edit."""
    user=Path(user_home or Path.home()).resolve()
    targets = dict(host_entry_targets(user, honor_environment=user_home is None))
    rows=[]
    for saved in state.get('host_entries',[]):
        row=dict(saved)
        try:
            path=Path(saved.get('path',''))
            if saved.get('registration_conflict'):
                raise ValueError('登记记录中的哈希冲突，未覆盖')
            harness = saved.get('harness')
            if harness not in targets:
                row.update(status='preserved', reason='宿主发现目录尚未实测，保留原入口，仅记录安装日志')
                rows.append(row)
                continue
            if (not path.is_absolute() or path.resolve() != (targets[harness] / 'SKILL.md').resolve()
                    or path.name!='SKILL.md' or path.parent.name!=PLUGIN or path.parent.parent.name!='skills'
                    or not path.resolve().is_relative_to(user)):
                raise ValueError('未登记的兼容入口位置')
            chain=[path,*path.parents]
            if any(p.is_symlink() or bool(getattr(p.lstat(),'st_file_attributes',0)&0x400)
                   for p in chain if p.exists() or p.is_symlink()):
                raise ValueError('兼容入口为链接，未覆盖')
            old = path.read_bytes() if path.is_file() else None
            if old is not None and hashlib.sha256(old).hexdigest()!=saved.get('sha256'):
                raise ValueError('用户已修改，未覆盖')
            content = host_entry_text(state, harness).encode('utf8')
            digest=hashlib.sha256(content).hexdigest()
            marker = path.parent / '.starsky-entry.json'
            _no_reparse(marker)
            marker_before = marker.read_bytes() if marker.exists() else None
            owned = read_json(marker, {})
            if owned and owned.get('managed_by') != PRODUCT:
                raise ValueError('入口标记不属于本安装器，未覆盖')
            marker_raw = (json.dumps({'managed_by': PRODUCT, 'schema_version': 1, 'sha256': digest},
                                     ensure_ascii=False, indent=2)+'\n').encode('utf8')
            for target, before, raw in [(path, old, content), (marker, marker_before, marker_raw)]:
                if before == raw: continue
                if planned is not None:
                    planned.append((target, before, raw))
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    temporary = target.with_name('.entry.'+uuid.uuid4().hex+'.tmp')
                    try:
                        temporary.write_bytes(raw); os.replace(temporary, target)
                    finally: temporary.unlink(missing_ok=True)
            if planned is None and hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
                raise OSError('兼容入口回读不一致')
            row.pop('reason', None)
            row.update(status='ready',sha256=digest,evidence='file_readback',plugin_version=state.get('plugin_version'))
        except (OSError,ValueError,TypeError) as exc:
            row.update(status='conflict',reason=str(exc) if isinstance(exc,ValueError) else type(exc).__name__)
        rows.append(row)
    return rows


def host_entry_notices(state, *, diagnostic=False):
    conflicts=[{k:row[k] for k in ('harness','path','reason') if k in row}
               for row in state.get('host_entries',[]) if row.get('status') in {'conflict', 'preserved', 'error'}]
    # The log is deterministic: repeated startup neither rewrites it nor repeats notices.
    path=app_home()/'logs/host-entries.json'
    previous=read_json(path,{})
    fingerprint=hashlib.sha256(json.dumps(conflicts,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
    notified=previous.get('notified') if previous.get('fingerprint')==fingerprint else False
    message='有兼容入口需要检查，原文件已保留，详情见安装日志。' if diagnostic and conflicts and not notified else ''
    log={'fingerprint':fingerprint,'entries':conflicts,'notified':bool(notified or message)}
    if previous!=log:atomic_json(path,log)
    return {'preserved_host_entries':[], 'host_entry_notice':message}


def extract_version(meta, plaintext):
    """Unpack one decrypted release into app_home/marketplace/versions/<plugin_version>; same plugin_version must be the same payload.
    按插件版本（含档位后缀）分目录：基础档和旗舰档、同一档的不同发布互不覆盖。"""
    root=app_home();destination=root/'marketplace/versions'/meta['plugin_version']
    if destination.exists():
        saved=read_json(destination/'source.json',{})
        if saved.get('payload_sha256')!=meta['files']['payload.enc']:
            raise InstallError('同版本已存在不同内容，拒绝覆盖。请使用独立版本号。')
        verify_install_identity(meta,destination/'plugins'/PLUGIN)
        return destination
    staging=root/'staging'/uuid.uuid4().hex
    safe_extract(plaintext,staging)
    plugin=staging/'plugins'/PLUGIN
    pj=read_json(plugin/'.codex-plugin/plugin.json',{})
    if pj.get('version')!=meta['plugin_version']:raise InstallError('插件版本与发行清单不一致。')
    atomic_json(staging/'source.json',{'payload_sha256':meta['files']['payload.enc'],
                                     'runtime_manifest_required':(plugin/'runtime-files.json').is_file()})
    destination.parent.mkdir(parents=True,exist_ok=True)
    staging.rename(destination)
    return destination


def verify_locked(locked):
    """The locked folder of a Git-marketplace release: signed bundle.json plus the files it lists that we ship there."""
    locked=Path(locked)
    raw=(locked/'bundle.json').read_bytes()
    verify_signature(raw,base64.b64decode((locked/'bundle.sig').read_text()),(locked/'license_public.pem').read_bytes())
    meta=json.loads(raw)
    if meta.get('product')!=PRODUCT:raise InstallError('更新包产品不匹配。')
    safe_member(meta['version'])
    for name in ('payload.enc','starsky_installer.py','member_updates.py','git_unlock.py','sandbox_support.py','host_support.py','host.json'):
        if name not in meta['files']:raise InstallError('更新包清单缺少 '+name+'，请联系作者。')
        verify_file(locked/name,meta['files'][name])
    # Upgrade-time runtime provisioning (R06.1): only a signed dependency list may ever be installed from.
    for name in ('requirements.txt','runtime_provision.py'):
        if (locked/name).is_file():
            if name not in meta['files']:raise InstallError('更新包清单缺少 '+name+'，请联系作者。')
            verify_file(locked/name,meta['files'][name])
    return meta


def local_grants(locked, version):
    """Member grants travel inside the Git release (grants/v1/<version>/), so unlocking needs no extra download."""
    folder=Path(locked)/'grants'/'v1'/version
    def read(url,limit,timeout=0):
        path=folder/url.rsplit('/',1)[-1].split('?',1)[0]
        if not path.is_file():raise InstallError('更新包里没有会员凭证文件。')
        data=path.read_bytes()
        if len(data)>limit:raise InstallError('会员凭证文件超出限制。')
        return data
    return read


def unlock_git_release(locked, python=None, quiet=False):
    """Open the release Codex pulled through the Git marketplace (after Upgrade) with this machine's activation.
    Fast when nothing changed; otherwise decrypts, refreshes knowledge bases and points current.json at it."""
    import member_updates
    locked=Path(locked).resolve();root=app_home();current=read_json(root/'current.json',{})
    # A freshly provisioned runtime (git_unlock hands over to it) must become the recorded interpreter.
    if python and current:current=dict(current,python=str(python))
    try:
        meta=verify_locked(locked)
    except InstallError as exc:
        return {'status':'blocked','message':str(exc)}
    version=meta['version']
    # The thin installed entry and the decrypted source must identify the same
    # signed release before a fast path may repair its registration record.
    manifest=read_json(locked.parent/('.claude-plugin' if HOST=='claude' else '.codex-plugin')/'plugin.json',{})
    if manifest.get('version')!=meta['plugin_version']:
        raise InstallError('正在解锁的安装目录与发行清单不一致。')
    # Emergency repair is narrowly scoped to our exact invalid 3.0.19 profile.
    # Normal unlock still never rewrites MCP/model/approval configuration.
    if HOST=='codex':
        from sandbox_support import repair_invalid_profile
        repair_invalid_profile(codex_home()/'config.toml',root)
    if current.get('version')==version and current.get('plugin_version')==meta['plugin_version'] and current.get('source') and Path(current['source']).is_dir():
        expected=root/'marketplace/versions'/meta['plugin_version']/'plugins'/PLUGIN
        if Path(current['source']).resolve()!=expected.resolve() or Path(current.get('home','')).resolve()!=locked.parent:
            raise InstallError('安装记录的实际目录身份不一致，请运行安装与更新。')
        verify_install_identity(meta,current['source'],locked.parent,host=HOST)
        repaired=persist_install_state(current,host=HOST,runtime=True)
        return {'status':'ready','updated':False,'record_repaired':repaired,'version':version,'source':current['source'],'python':current.get('python'),**host_entry_notices(current)}
    public=(locked/'license_public.pem').read_bytes();device=fingerprint();key_id=meta['encryption']['key_id']
    code=read_json(root/'license.json',{}).get('code','')
    anchor=read_json(root/'activation.json',{}).get('code') or code
    authorization=None
    if code:
        try:
            obj=verify_license(code,public,device)
            if key_id in obj.get('content_keys',{}):authorization=obj
        except InstallError:
            pass
    if authorization is None:
        if not anchor:
            return {'status':'blocked','message':'本机还没有星空授权：请运行安装包里的「安装与更新」完成授权。'}
        try:
            code=member_updates.fetch_grant(anchor,locked,meta,device,local_grants(locked,version))
            authorization=verify_license(code,public,device)
        except member_updates.NoGrant:
            return {'status':'blocked','message':'新版 '+version+' 需要有效会员才能使用：会员可能已到期或未登记，请联系坚哥续费；当前版本继续可用。',
                    'installed':current.get('version')}
        except (member_updates.GrantError,InstallError) as exc:
            return {'status':'blocked','message':str(exc),'installed':current.get('version')}
    destination=extract_version(meta,decrypt_payload(locked,meta,authorization))
    plugin=destination/'plugins'/PLUGIN
    verify_install_identity(meta,plugin,locked.parent,host=HOST)
    authorization_records={root/'license.json':{'code':code}}
    if not (root/'activation.json').exists():authorization_records[root/'activation.json']={'code':anchor or code}
    config=root/'config/lingxing_config.yaml'
    migrate_config(config,[plugin/'skills/lingxing-erp-connector/references/lingxing_config模板.yaml'])
    python=Path(python or current.get('python') or sys.executable)
    kb={}
    for name,validate in (('ads-kb',validate_ads_kb),('selection-kb',validate_selection_kb),('promotion-kb',validate_promotion_kb)):
        try:
            if (plugin/'mcp'/name/'server.py').is_file():
                validate(plugin/'mcp'/name,python)
                kb[name]='validated'
            else:kb[name]='skipped'
        except Exception as exc:  # one knowledge base must not block the business plugin
            kb[name]='failed: '+str(exc)[:120]
    state=dict(current,version=version,plugin_version=meta['plugin_version'],home=str(locked.parent),source=str(plugin),
               python=str(python),config=str(config),previous=current.get('version'),delivery='git_marketplace',
               previous_plugin_version=current.get('plugin_version'),previous_state=previous_install_identity(current),
               installed_at=datetime.now(timezone.utc).isoformat())
    persist_install_state(state,host=HOST,extra_records=authorization_records,runtime=True)
    # Stable KB/desktop launchers follow current.json. Host setup is installer-only.
    return {'status':'ready','updated':True,'version':version,'previous':current.get('version'),'source':str(plugin),
            'python':str(python),'knowledge_bases':kb,'expires':authorization.get('expires'),**host_entry_notices(state)}


def install_ads_launcher(state):
    """Windows flagship: create/repair the host's own entries without installing the engine."""
    if HOST not in ('codex', 'claude') or os.name != 'nt' or not state.get('source'):
        return
    terminal = Path(state['source']) / 'skills/starsky-ads-terminal/scripts/terminal.py'
    if not terminal.is_file():
        return
    if HOST == 'claude' and not (terminal.parents[1] / 'assets/desktop/desktop_entries.py').is_file():
        return  # Existing Claude releases with batch launchers do not have this interface.
    try:
        result = subprocess.run([str(state.get('python') or sys.executable), '-B', str(terminal),
                                 'shortcuts', '--state-file', str(app_home() / 'current.json')],
                                capture_output=True, encoding='utf-8', errors='replace', timeout=60,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        info = json.loads(result.stdout or '{}')
        if result.returncode == 0 and info.get('ok'):
            suffix = '（Claude）' if HOST == 'claude' else ''
            print('广告桌面入口已装好：启动星空广告终端' + suffix + ' / 停止星空广告终端' + suffix + '。')
        else:
            print('广告桌面入口未建成：请在 ' + ('Claude' if HOST == 'claude' else 'Codex') + ' 中说“修复广告桌面入口”。')
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print('广告桌面入口未建成：请在 ' + ('Claude' if HOST == 'claude' else 'Codex') + ' 中说“修复广告桌面入口”。')


def install_nav_launcher(state):
    """装完就把悬浮窗放进系统：Mac 生成「星空导航」App（Spotlight 搜得到），Windows 生成桌面快捷方式。
    启动器每次读安装记录，所以以后更新（含 Upgrade）不用重装。失败只提示，不影响安装。"""
    install_ads_launcher(state)
    script=Path(state.get('source',''))/'scripts'/'make_nav_app.py'
    if not script.is_file():return
    try:
        run=subprocess.run([str(state.get('python') or sys.executable),'-B',str(script)],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=90)
        info=json.loads((run.stdout or '{}').strip().splitlines()[-1]) if run.stdout.strip() else {}
        if info.get('ok'):print('悬浮窗已装好：'+str(info.get('use') or info.get('app')))
        else:print('悬浮窗入口没建成（不影响使用）：以后对助手说「打开悬浮窗」即可。')
    except (OSError,ValueError,subprocess.TimeoutExpired):
        print('悬浮窗入口没建成（不影响使用）：以后对助手说「打开悬浮窗」即可。')


def require_git():
    """Codex invokes Git as a child; refresh this process PATH after a fresh install."""
    candidates = []
    located = shutil.which('git')
    if located:
        candidates.append(Path(located))
    if os.name == 'nt':
        for variable, relative in [('ProgramFiles', 'Git/cmd/git.exe'),
                                   ('ProgramFiles(x86)', 'Git/cmd/git.exe'),
                                   ('LOCALAPPDATA', 'Programs/Git/cmd/git.exe')]:
            base = os.environ.get(variable)
            if base:
                candidates.append(Path(base) / relative)
    for candidate in candidates:
        if candidate.is_file():
            run_checked([candidate, '--version'], operation='检查 Git 环境')
            os.environ['PATH'] = str(candidate.parent) + os.pathsep + os.environ.get('PATH', '')
            return candidate
    raise InstallError('正式版 Git 市场需要 Git，但本安装进程未找到 Git。请先安装 Git（Windows：https://git-scm.com/install/windows），再关闭此窗口并重新运行“安装与更新”。原有插件登记未改动。')


def install_git(bundle, meta, authorization, cli):
    """Paid channel: register the Git marketplace (so Codex's Upgrade button delivers new releases), install the
    thin plugin from it, then unlock the release it carries with this machine's license."""
    require_git()
    url=os.environ.get('STARSKY_GIT_MARKETPLACE_URL') or GIT_MARKETPLACE['url']
    tier=authorization.get('tier') or meta.get('tier') or 'basic'
    ref=(GIT_MARKETPLACE.get('refs') or {}).get(tier) or GIT_MARKETPLACE.get('ref')  # 买哪一档就登记哪一档的分支
    if tier!=(meta.get('tier') or 'basic'):
        raise InstallError('本安装包是「'+str(meta.get('tier') or 'basic')+'」档，你的授权是「'+tier+'」档：请下载对应档位的安装包。')
    root=app_home();root.mkdir(parents=True,exist_ok=True)
    # The name is shared with the old local marketplace; replace it (the local versions folder stays for rollback).
    subprocess.run([str(cli),'plugin','marketplace','remove',MARKET],capture_output=True,timeout=60)
    print('正在登记正式版 Git 市场（首次需要从 GitHub 下载）……', flush=True)
    run_checked([cli,'plugin','marketplace','add',url]+(['--ref',ref] if ref else []),timeout=600,operation='登记正式版 Git 市场')
    print('正在安装正式版插件……', flush=True)
    result=json.loads(run_checked([cli,'plugin','add',PLUGIN+'@'+MARKET,'--json'],operation='安装正式版插件'))
    loaded=Path(result.get('installedPath',''))
    if result.get('version')!=meta['plugin_version'] or not (loaded/'locked').is_dir():
        raise InstallError('GitHub 上的正式版（'+str(result.get('version'))+'）与本安装包（'+meta['plugin_version']+'）不一致：请下载最新安装包，或稍后再试。')
    outcome=unlock_git_release(loaded/'locked',python=sys.executable)
    if outcome['status']!='ready':raise InstallError(outcome['message'])
    from sandbox_support import setup as setup_sandbox
    permission=setup_sandbox(sys.modules[__name__],sys.executable)
    if permission.get('read_only'):
        print('当前 Codex 为只读模式：可写目录设置不能放行写入；后续需宿主允许的单次权限申请。')
    if permission.get('selection_required'):
        print('请在 Codex 权限菜单选择「'+permission['profile']+'」一次，再重开 Codex；默认档未自动切换，审批和网络限制保留。')
    if permission.get('permission_request_required'):
        print('当前使用内置权限档：未写入新权限档，也未切换全局默认。后续更新解锁需按宿主提示允许单次权限请求。')
    persist_install_state(read_json(root/'current.json',{}))
    apply_sif_http()
    install_nav_launcher(read_json(root/'current.json',{}))
    print('\n插件安装完成：'+meta['plugin_version']+'（正式版：以后在 Codex 设置 → 插件 → Marketplace 点「Upgrade」即可更新）')
    for name,state in outcome.get('knowledge_bases',{}).items():
        print('知识库 '+name+'：'+state)
    print('请完全退出再打开官方 Codex，新开会话输入：启动星空。')
    return outcome


def install(bundle):
    bundle=Path(bundle).resolve();meta=verify_bundle(bundle);authorization=ensure_license(bundle)
    plaintext=decrypt_payload(bundle,meta,authorization);cli=find_codex()
    conflicts=installed_conflicts()
    if conflicts:
        raise InstallError('检测到旧市场启用的同名插件：'+', '.join(conflicts)+'。为保留旧安装，请先联系作者完成迁移；本程序未卸载它。')
    if GIT_MARKETPLACE:
        return install_git(bundle,meta,authorization,cli)
    root=app_home();version=meta['version']
    destination=extract_version(meta,plaintext)
    plugin=destination/'plugins'/PLUGIN
    oldpointer=read_json(codex_home()/'starsky.json',{})
    legacy=Path(oldpointer['home']) if oldpointer.get('home') else Path.home()/'plugins'/PLUGIN
    config=root/'config/lingxing_config.yaml'
    migrate_config(config,[legacy/'skills/lingxing-erp-connector/lingxing_config.yaml',plugin/'skills/lingxing-erp-connector/references/lingxing_config模板.yaml'])
    # One stable, dedicated local marketplace; never rewrite the user's TOML directly.
    registry=root/'marketplace';registry.mkdir(parents=True,exist_ok=True)
    marketfile=registry/'.agents/plugins/marketplace.json'
    before=marketfile.read_bytes() if marketfile.exists() else None
    atomic_json(marketfile,{'name':MARKET,'interface':{'displayName':'星空 Codex · 公开发行'},'plugins':[{'name':PLUGIN,'source':{'source':'local','path':'./'+plugin.relative_to(registry).as_posix()},'policy':{'installation':'AVAILABLE','authentication':'ON_INSTALL'},'category':'Productivity'}]})
    previous=read_json(root/'current.json',{})
    try:
        run_checked([cli,'plugin','marketplace','add',registry])
        response=run_checked([cli,'plugin','add',PLUGIN+'@'+MARKET,'--json'])
        result=json.loads(response)
        if result.get('version')!=meta['plugin_version'] or not result.get('installedPath'):
            raise InstallError('Codex 未返回期望的安装版本与路径。')
        loaded=Path(result['installedPath']);installed=read_json(loaded/'.codex-plugin/plugin.json',{})
        if installed.get('version')!=meta['plugin_version']:raise InstallError('Codex 缓存版本复核失败。')
        verify_install_identity(meta,plugin,loaded)
        launcher=root/'launcher'/meta['plugin_version']
        if not launcher.exists():shutil.copytree(bundle,launcher,ignore=shutil.ignore_patterns('__pycache__'))
        state=dict(previous,version=version,plugin_version=meta['plugin_version'],home=str(loaded),source=str(plugin),launcher=str(launcher),python=sys.executable,config=str(config),previous=previous.get('version'),previous_plugin_version=previous.get('plugin_version'),previous_state=previous_install_identity(previous),installed_at=datetime.now(timezone.utc).isoformat())
        if (launcher/'00-使用说明.html').is_file():
            state['user_guide']=str(launcher/'00-使用说明.html')
        try:
            state['host_entries'] = deploy_host_entries(state)
        except InstallError as exc:
            state['host_entries'] = [{'status': 'error', 'reason': str(exc)}]
        persist_install_state(state)
    except Exception as exc:
        if before is not None:
            marketfile.write_bytes(before)
            if previous:
                try:run_checked([cli,'plugin','add',PLUGIN+'@'+MARKET,'--json'])
                except InstallError:print('旧版自动恢复未完成；旧文件保留，请联系作者。')
        elif marketfile.exists():marketfile.unlink()
        if isinstance(exc,InstallError):raise
        raise InstallError('安装返回格式异常，有效版本指针未更新。') from exc
    install_nav_launcher(state)
    for item in state['host_entries']:
        if item['status'] == 'ready':
            print(f"{item['harness']} 兼容入口已写入；需在 CodexHost 新会话验证唤醒与工具调用。")
        else:
            print('兼容入口未就绪：'+item.get('harness', '')+' '+item.get('reason', '')+'；已有文件保留。')
    print('\n插件文件安装完成：'+meta['plugin_version']+'；MCP 分项结果如下。')
    print('配置保存在 '+str(config))
    try:
        _n = clean_managed_mcp_types()
        if _n:
            print(f'已顺手清理 { _n } 处旧版残留的 type 字段（1688/知识库），黄色警告会少 { _n } 条。')
    except Exception as exc:
        print('旧 type 字段清理跳过：'+str(exc)+'。不影响本次安装。')
    try:
        apply_sif_http()
    except Exception as exc:
        print('SIF 配置处理未完成：'+str(exc)+'。请按 MCP 说明检查。')
    try:
        if apply_ads_kb(Path(state['source'])/'mcp/ads-kb', sys.executable, required=False) is not None:
            print('广告知识库已写入，安装前后独立进程 kb_status 核验通过。新会话仍需验证工具加载。')
    except Exception as exc:
        print('广告知识库未自动写入：'+str(exc)+'。可稍后运行“安装广告知识库”。')
    try:
        if apply_selection_kb(Path(state['source'])/'mcp/selection-kb', sys.executable, required=False) is not None:
            print('选品知识库已写入，安装前后独立进程 kb_status 核验通过。新会话仍需验证工具加载。')
    except Exception as exc:
        print('选品知识库未自动写入：'+str(exc)+'。可稍后运行“安装选品知识库”。')
    try:
        if apply_promotion_kb(Path(state['source'])/'mcp/promotion-kb', sys.executable, required=False) is not None:
            print('产品推广知识库已写入，安装前后独立进程 kb_status 核验通过。新会话仍需验证工具加载。')
    except Exception as exc:
        print('产品推广知识库未自动写入：'+str(exc)+'。可稍后运行“安装产品推广知识库”。')
    print('三个附加入口无需逐个重复运行：SIF 保留已有配置；广告知识库安装时自动处理；需要 1688 抓取时再运行“安装1688”。')
    print('请完全退出再打开官方 Codex，新开会话输入：启动星空。Mac 实机验证状态见发布说明。')
    print_user_guide(launcher)


def probe_1688(mode, server=None):
    command = [sys.executable, '-u', '-B', str(Path(__file__).with_name('mcp_1688_probe.py')), '--mode', mode]
    if server is not None:
        command += ['--server', str(server)]
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf8', timeout=60)
        data = json.loads(result.stdout or '{}')
        if not isinstance(data, dict):
            return {'ok': False, 'code': 'probe_failed'}
        if result.returncode or data.get('ok') is not True:
            return {'ok': False, 'code': data.get('code', 'probe_failed')}
        return data
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {'ok': False, 'code': 'probe_failed'}


def install_chromium():
    print('正在检查本机 Chromium 组件（使用独立临时浏览器，不读取登录资料）……', flush=True)
    local = probe_1688('browser')
    if local['ok']:
        print('本机 Chromium 启动检查通过，无需重复下载。', flush=True)
        return
    if local['code'] != 'browser_missing':
        raise InstallError('Chromium 启动检查失败；请先检查组件或系统环境，原 MCP 配置保持不变。')
    print('本机缺少 Chromium，开始下载；最长等待 15 分钟，每 10 秒显示等待状态。', flush=True)
    stopped = threading.Event()
    def progress():
        elapsed = 0
        while not stopped.wait(10):
            elapsed += 10
            print(f'Chromium 下载仍在进行（已等待 {elapsed} 秒）；完成前不会写入配置。', flush=True)
    reporter = threading.Thread(target=progress, daemon=True)
    reporter.start()
    # Download progress is public component output, never user configuration.
    try:
        result = subprocess.run([sys.executable, '-m', 'playwright', 'install', 'chromium'], timeout=900,
                                env={**os.environ, 'PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT': '60000'})
    except subprocess.TimeoutExpired as exc:
        raise InstallError('Chromium 下载超过 15 分钟，1688 配置尚未写入；检查网络后重试。') from exc
    except OSError as exc:
        raise InstallError('Chromium 安装未启动，1688 配置尚未写入；检查 Python 环境后重试。') from exc
    finally:
        stopped.set()
        reporter.join(timeout=1)
    if result.returncode:
        raise InstallError(f'Chromium 下载失败，退出码 {result.returncode}；1688 配置尚未写入。请按上方下载错误检查网络后重试。')
    if not probe_1688('browser')['ok']:
        raise InstallError('Chromium 下载结束但启动检查未通过，原 MCP 配置保持不变。')


def install_mcp(bundle):
    report = {'status': 'failed', 'stage': 'package_and_license', 'account_login': 'not_checked', 'offer_fetch': 'not_checked'}
    try:
        _install_mcp(bundle, report)
        report['status'] = 'installed_and_probed'
    finally:
        # Only whitelisted status data; no tokens, arbitrary child output, cookies or license content.
        try:
            evidence = app_home()/'evidence'/('1688-install-'+datetime.now().strftime('%Y%m%d_%H%M%S')+'-'+uuid.uuid4().hex[:6]+'.json')
            evidence.parent.mkdir(parents=True, exist_ok=True)
            evidence.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf8')
            print('1688 安装检查记录：'+str(evidence), flush=True)
        except OSError:
            print('安装检查记录无法保存，请保留窗口中最后一步提示。', flush=True)


def prepare_1688_installation(bundle, meta, install_action, report=None):
    """Synchronize an absent/older plugin, but never install an older bundle over it."""
    state = read_json(app_home()/'current.json', {})
    expected = meta.get('version') if isinstance(meta, dict) else None
    installed = state.get('version')
    if report is not None:
        report.update(bundle_version=expected, installed_version=installed)
    if expected:
        if installed and version_order(installed) > version_order(expected):
            raise InstallError('安装包版本 '+expected+' 与已安装插件 '+installed+' 不一致：这个安装包较旧，不会降级。请完整解压最新包后运行“安装1688”：https://github.com/'+REPO+'/releases/latest')
        if not installed or version_order(installed) < version_order(expected):
            print('本机插件 '+str(installed or '尚未安装')+'，安装包 '+expected+'；先完成对应插件安装/更新，再继续安装 1688。', flush=True)
            if report is not None:
                report['stage'] = 'synchronize_plugin'
            install_action(bundle)
            state = read_json(app_home()/'current.json', {})
            if state.get('version') != expected:
                raise InstallError('插件同步后版本未达到安装包 '+expected+'（当前 '+str(state.get('version') or '未安装')+'），1688 尚未登记，请保留窗口提示联系作者。')
            if report is not None:
                report['installed_version'] = expected
                report['plugin_synchronized'] = True
    if not state:
        raise InstallError('请先运行“安装与更新”安装星空插件。')
    return state


def replace_1688_config(text, section):
    """Replace only our parent/env tables, including normal quoted TOML keys."""
    def component(name):
        return '(?:'+re.escape(name)+'|'+re.escape(json.dumps(name))+"|"+re.escape("'"+name+"'")+')'
    parent = component('mcp_servers')+r'[ \t]*\.[ \t]*'+component('1688_scraper')
    for name in (parent+r'[ \t]*\.[ \t]*'+component('env'), parent):
        rx = re.compile(r'(?m)^[ \t]*\[[ \t]*'+name+r'[ \t]*\][^\r\n]*(?:\r?\n|$)(?:(?![ \t]*\[)[^\r\n]*(?:\r?\n|$))*')
        # Preserve standalone notes when moving the managed values into one table.
        text = rx.sub(lambda m: ''.join(line+'\n' for line in m.group().splitlines() if line.lstrip().startswith('#')), text, count=1)
    updated = text.rstrip()+'\n\n'+section.rstrip()+'\n'
    tomllib.loads(updated)
    return updated


def _install_mcp(bundle, report):
    print('[1688 1/4] 正在检查安装包和本机授权……', flush=True)
    meta = verify_bundle(bundle);ensure_license(bundle)
    state=prepare_1688_installation(bundle, meta, install, report)
    source=Path(state['source'])/'mcp/1688';dest=codex_home()/'mcp/starsky-1688'
    if dest.exists() and not (dest/'.starsky-managed').exists():
        raise InstallError('已有非星空受管的 1688 目录，拒绝覆盖。')
    if any(not (source / name).is_file() for name in ['server.py', 'smoke_test.py', 'requirements.txt']):
        raise InstallError('插件包缺少 1688 服务文件，请重新安装完整星空版本。')
    cfg=codex_home()/'config.toml';text=cfg.read_text(encoding='utf-8-sig') if cfg.exists() else ''
    existing = tomllib.loads(text).get('mcp_servers', {}).get('1688_scraper', {})
    service_env = dict(existing.get('env', {}))
    if any(not isinstance(value, str) for value in service_env.values()):
        raise InstallError('1688 环境变量必须是文本，原配置未修改。')
    cache = os.environ.get('PLAYWRIGHT_BROWSERS_PATH') or service_env.get('PLAYWRIGHT_BROWSERS_PATH')
    if cache:
        base = Path.cwd() if os.environ.get('PLAYWRIGHT_BROWSERS_PATH') else Path(existing.get('cwd') or dest)
        cache = cache if cache == '0' else str((base / Path(cache).expanduser()).resolve())
        service_env['PLAYWRIGHT_BROWSERS_PATH'] = cache
        os.environ['PLAYWRIGHT_BROWSERS_PATH'] = cache
    print('[1688 2/4] 检查 Chromium 浏览器组件，缺少时才下载。', flush=True)
    report['stage'] = 'chromium'
    install_chromium()
    report['chromium'] = 'launch_passed'
    print('[1688 3/4] 验证 MCP 初始化、五项工具和 ping（不访问商品网页）……', flush=True)
    report['stage'] = 'mcp_protocol'
    # Probe before replacing an existing server or its configuration.
    probe = probe_1688('protocol', source / 'server.py')
    if not probe['ok']:
        report['protocol'] = 'failed'
        raise InstallError('1688 服务启动验证未通过（'+probe['code']+'），原服务和 MCP 配置保持不变。请运行完整包的“安装与更新”后重试。')
    report['protocol'] = 'initialize_tools_ping_passed'
    print('[1688 4/4] 浏览器与 MCP 验证通过，正在写入本机 MCP 配置……', flush=True)
    report['stage'] = 'write_config'
    section='[mcp_servers.1688_scraper]\ncommand = '+json.dumps(sys.executable)+'\nargs = '+json.dumps([str(dest/'server.py')])+'\ncwd = '+json.dumps(str(dest))+'\nstartup_timeout_sec = 120\ntool_timeout_sec = 300\n'
    if service_env:
        section += 'env = { '+', '.join(json.dumps(key)+' = '+json.dumps(value) for key,value in service_env.items())+' }\n'
    updated=replace_1688_config(text,section)
    dest.mkdir(parents=True,exist_ok=True)
    stamp=datetime.now().strftime('%Y%m%d_%H%M%S')+'_'+uuid.uuid4().hex[:6]
    for name in ['server.py','smoke_test.py','requirements.txt']:
        if (dest/name).exists():
            backup=dest/'_backup'/stamp;backup.mkdir(parents=True,exist_ok=True);shutil.copy2(dest/name,backup/name)
        shutil.copy2(source/name,dest/name)
    (dest/'.starsky-managed').write_text('managed-by=starsky-codex\n',encoding='utf8')
    cfg.parent.mkdir(parents=True,exist_ok=True)
    if cfg.exists():shutil.copy2(cfg,cfg.with_name('config.toml.bak-starsky-'+stamp))
    temp=cfg.with_name('config.toml.'+uuid.uuid4().hex+'.tmp');temp.write_text(updated,encoding='utf8');os.replace(temp,cfg)
    print('1688 配置已写入；独立进程 initialize、tools/list、ping 和 Chromium 启动检查通过。原配置已备份，已有登录态保留。')
    print('请重开 Codex 并新建会话验证 1688 ping。账号登录和实际商品抓取需要在工具浏览器中另行验证。')
    report['stage'] = 'complete'
    print_user_guide(state.get('launcher'))


def install_ads_kb(bundle):
    verify_bundle(bundle);ensure_license(bundle)
    state=read_json(app_home()/'current.json',{})
    if not state:raise InstallError('请先安装星空 Codex 插件。')
    dest=apply_ads_kb(Path(state['source'])/'mcp/ads-kb', sys.executable, required=True)
    print('广告知识库已写入 '+str(dest)+'。请重开 Codex 并新建会话，说「调 kb_status」。它不会改广告后台。')
    print_user_guide(state.get('launcher'))


def install_selection_kb(bundle):
    verify_bundle(bundle);ensure_license(bundle)
    state=read_json(app_home()/'current.json',{})
    if not state:raise InstallError('请先安装星空 Codex 插件。')
    dest=apply_selection_kb(Path(state['source'])/'mcp/selection-kb', sys.executable, required=True)
    print('选品知识库已写入 '+str(dest)+'。请重开 Codex 并新建会话，S1 开步先调 kb_status。它不登录、不拉数、不立项。')
    print_user_guide(state.get('launcher'))


def install_promotion_kb(bundle):
    verify_bundle(bundle);ensure_license(bundle)
    state=read_json(app_home()/'current.json',{})
    if not state:raise InstallError('请先安装星空 Codex 插件。')
    dest=apply_promotion_kb(Path(state['source'])/'mcp/promotion-kb', sys.executable, required=True)
    print('产品推广知识库已写入 '+str(dest)+'。请重开 Codex 并新建会话，S4/S5先调 kb_status，断货掉位调 kb_diagnose。它不改后台。')
    print_user_guide(state.get('launcher'))


def health():
    state=read_json(app_home()/'current.json',{})
    if not state:raise InstallError('未找到星空 Codex 公开版安装记录。')
    loaded=Path(state['home'])
    if not (loaded/'.codex-plugin/plugin.json').exists():raise InstallError('安装缓存已丢失，请重新运行安装器。')
    print('已安装 '+state['plugin_version'])
    print('Skill 数量：'+str(len(list((loaded/'skills').glob('*/SKILL.md')))))
    for item in state.get('host_entries', []):
        entry = Path(item.get('path', ''))
        ok = (item.get('status') == 'ready' and entry.is_file()
              and hashlib.sha256(entry.read_bytes()).hexdigest() == item.get('sha256'))
        print('CodexHost '+item.get('harness', '兼容入口')+'：'+('入口文件核对通过；会话与工具仍需实测' if ok else '入口未就绪或已变动，请检查安装记录'))
    for module in ['openpyxl','yaml','PIL','requests','Crypto','mcp','playwright','numpy','pandas','fitz','jsonschema','urllib3','cv2','rapidocr','onnxruntime']:
        __import__(module);print('[OK] '+module)
    smoke=loaded/'scripts/mcp_runtime_smoke.py'
    if smoke.is_file():
        out=app_home()/'health'/('mcp_runtime_smoke_'+datetime.now().strftime('%Y%m%d_%H%M%S')+'.json')
        print('开始 MCP 运行时冒烟（只读，不落密钥）…')
        result=subprocess.run([sys.executable,'-B',str(smoke),'--out',str(out)],timeout=600)
        print('MCP 冒烟'+('通过' if result.returncode==0 else '未全部通过，按上面提示处理后重跑“一键体检”')+'；报告：'+str(out))
        print('本机进程能直连不等于 Codex 新任务里工具已注入；新会话加载与模型仍需在官方 Codex 中验证。')
    else:
        print('本次仅检查本机文件与依赖。新会话加载、模型与外部 MCP 连通需在官方 Codex 中验证。')
    print_user_guide(state.get('launcher'))


def download(url, limit=50_000_000, timeout=90):
    if not url.startswith('https://'):raise InstallError('下载地址必须使用 HTTPS。')
    req=urllib.request.Request(url,headers={'User-Agent':'Starsky-Codex-Installer','Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(req,timeout=timeout) as r:
        data=r.read(limit+1)
    if len(data)>limit:raise InstallError('下载文件超过大小限制。')
    return data


def version_order(version):
    match=re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?',version)
    if not match:raise InstallError('无法识别发行版本号。')
    major,minor,patch,rc=match.groups()
    return (int(major),int(minor),int(patch),1 if rc is None else 0,int(rc or 0))


class ChannelNotFound(InstallError):
    pass


class FlagshipUpdateUnavailable(InstallError):
    pass


# Published flagship tag namespaces, distinct from the operating edition.
FLAGSHIP_RELEASES = {
    'starsky-claude-v2': ('wenjiany312-hub/starsky-amazon-claude-desktop-v2', 'v{version}-claude-flagship'),
    'starsky-codex-v2': ('wenjiany312-hub/starsky-amazon-codex-v2', 'v{version}-codex-flagship'),
}


def _fetch_channel_api(bundle, timeout):
    releases=json.loads(download('https://api.github.com/repos/'+REPO+'/releases?per_page=10',2_000_000,timeout=timeout))
    tier=read_json(Path(bundle)/'bundle.json',{}).get('tier','basic')
    channel_name='flagship-channel.json' if tier=='flagship' else 'channel.json'
    signature_name='flagship-channel.sig' if tier=='flagship' else 'channel.sig'
    for release in releases:
        if release.get('draft'):continue
        urls={a['name']:a['browser_download_url'] for a in release.get('assets',[])}
        if not {channel_name,signature_name} <= urls.keys():continue
        raw=download(urls[channel_name],1_000_000,timeout=timeout);signature=base64.b64decode(download(urls[signature_name],20_000,timeout=timeout))
        verify_signature(raw,signature,(Path(bundle)/'license_public.pem').read_bytes());channel=json.loads(raw)
        if channel.get('product')!=PRODUCT or channel.get('tier','basic')!=tier:continue
        version_order(channel['version'])
        return channel,urls
    raise ChannelNotFound('未找到当前产品与版本档的有效更新清单。')


def _fetch_flagship_catalog(bundle, timeout):
    binding = FLAGSHIP_RELEASES.get(PRODUCT)
    if not binding or binding[0] != REPO:
        raise InstallError('旗舰更新源与当前产品不符。')
    catalog_url = 'https://raw.githubusercontent.com/' + REPO + '/refs/heads/main/release-catalog-flagship.json'
    catalog = json.loads(download(catalog_url, 1_000_000, timeout=timeout))
    version = catalog['version']
    version_order(version)
    # Ignore all URLs/platform data from the unsigned catalog. It is only a locator.
    root = 'https://github.com/' + REPO + '/releases/download/' + binding[1].format(version=version) + '/'
    urls = {name: root + name for name in ('flagship-channel.json', 'flagship-channel.sig')}
    raw = download(urls['flagship-channel.json'], 1_000_000, timeout=timeout)
    signature = base64.b64decode(download(urls['flagship-channel.sig'], 20_000, timeout=timeout).strip(), validate=True)
    verify_signature(raw, signature, (Path(bundle) / 'license_public.pem').read_bytes())
    channel = json.loads(raw)
    if channel.get('product') != PRODUCT or channel.get('tier') != 'flagship' or channel.get('version') != version:
        raise InstallError('旗舰更新清单的产品、档位或版本不匹配。')
    current = read_json(Path(bundle) / 'bundle.json', {}).get('version')
    if current and version_order(version) < version_order(current):
        raise InstallError('旗舰更新清单版本较旧，已拒绝降级。')
    for asset in channel['platforms'].values():
        name = asset['file']
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*\.zip', name):
            raise InstallError('旗舰更新包文件名不正确。')
        urls[name] = root + name
    return channel, urls


def fetch_channel(bundle, timeout=90):
    if read_json(Path(bundle) / 'bundle.json', {}).get('tier', 'basic') != 'flagship':
        return _fetch_channel_api(bundle, timeout)
    try:
        return _fetch_channel_api(bundle, timeout)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ChannelNotFound) as exc:
        limited = getattr(exc, 'code', None) in (403, 429)
    # Signature errors are InstallError and fail closed, without trying another source.
    try:
        return _fetch_flagship_catalog(bundle, timeout)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, InstallError) as exc:
        limited = limited or getattr(exc, 'code', None) in (403, 429)
        message = ('GitHub 暂时限流，这是网络出口的限制，不是授权问题。请约 1 小时后重试，或换一个网络（如手机热点）。当前版本继续可用。'
                   if limited and not isinstance(exc, InstallError) else
                   '本次未能确认更新状态，不代表已经是最新版。当前版本继续使用。')
        raise FlagshipUpdateUnavailable(message) from None


def notice(bundle):
    """Called by the Starsky entry skill; no install, credential prompt or file writes."""
    current=read_json(app_home()/'current.json',{})
    try:
        if not current:raise InstallError('未找到公开版安装记录。')
        stored=read_json(app_home()/'license.json',{})
        code=stored.get('code','')
        if code:
            authorized=verify_license(code,(Path(bundle)/'license_public.pem').read_bytes(),fingerprint(),allow_expired=True)
            if authorized.get('update_policy')=='version_locked':
                print(json.dumps({'status':'version_locked','installed':current['version']},ensure_ascii=False));return
        channel,_=fetch_channel(bundle,timeout=5)
        newer=version_order(channel['version'])>version_order(current['version'])
        if newer and channel.get('member_feed',{}).get('protocol')==1:
            import member_updates
            anchor=read_json(app_home()/'activation.json',{}).get('code') or code
            if not anchor:
                print(json.dumps({'status':'update_eligibility_unknown','installed':current['version']}));return
            bind=channel['authorization_binding']
            meta={'version':channel['version'],'encryption':{'key_id':bind['key_id']},'files':{'payload.enc':bind['payload_sha256']}}
            try:
                member_updates.fetch_grant(anchor,bundle,meta,fingerprint(),download)
            except member_updates.NoGrant:
                print(json.dumps({'status':'no_update_entitlement','installed':current['version']}));return
        result={'status':'update_available' if newer else 'no_newer_release','installed':current['version'],'latest':channel['version']}
        if newer:
            result.update(url='https://github.com/'+REPO+'/releases/tag/v'+channel['version'],message='星空有新版。会员更新权限已核验时可直接更新；旧版客户端可能需要一次兼容安装器升级。当前版本继续使用。')
            if GIT_MARKETPLACE:
                result['message']='星空正式版有新版 '+channel['version']+'：在 Codex 设置 → 插件 → Marketplace 找到「星空 Codex」点 Upgrade，然后新开会话说“启动星空”即可（也可运行安装包里的“检查新版”）。当前版本继续使用。'
            elif HOST=='claude' and current.get('delivery')=='claude_native_command':
                suffix='-claude-flagship' if channel.get('tier')=='flagship' else ''
                result['url']='https://github.com/'+REPO+'/releases/tag/v'+channel['version']+suffix
                result['message']='星空正式版有新版 '+channel['version']+'：在 Claude 插件页找到星空，点击原生 Update，按提示完成后重开 Claude 并新建会话。当前版本继续使用。'
        print(json.dumps(result,ensure_ascii=False))
    except FlagshipUpdateUnavailable as exc:
        print(json.dumps({'status':'check_unavailable','message':str(exc)},ensure_ascii=False))
    except Exception:
        print(json.dumps({'status':'check_unavailable','message':'本次未能确认更新状态，继续当前业务，不代表已经是最新版。'},ensure_ascii=False))


def update_git():
    """Paid channel: same as Codex's Upgrade button, then unlock the new release on this machine."""
    require_git()
    cli=find_codex()
    run_checked([cli,'plugin','marketplace','upgrade',MARKET],timeout=600)
    result=json.loads(run_checked([cli,'plugin','add',PLUGIN+'@'+MARKET,'--json']))
    outcome=unlock_git_release(Path(result['installedPath'])/'locked')
    if outcome['status']!='ready':raise InstallError(outcome['message'])
    print(('已更新到 '+outcome['version'] if outcome.get('updated') else '已是最新版 '+outcome['version'])+'。请重开官方 Codex，并新开会话。')


def update(bundle):
    if GIT_MARKETPLACE:
        return update_git()
    verify_bundle(bundle)
    channel,urls=fetch_channel(bundle)
    current=read_json(app_home()/'current.json',{})
    if current.get('version') and version_order(channel['version'])<=version_order(current['version']):
        print('未发现比已安装版本更新的发行。当前 '+current['version']);return
    target='windows' if os.name=='nt' else 'macos';asset=channel['platforms'][target]
    filename=asset['file'];safe_member(filename)
    content=download(urls[filename]);root=app_home()/'downloads'/uuid.uuid4().hex;root.mkdir(parents=True)
    archive=root/'installer.zip';archive.write_bytes(content);verify_file(archive,asset['sha256'])
    safe_extract(archive,root/'unpacked')
    packages=list((root/'unpacked').glob('*/bundle.json'))
    if len(packages)!=1:raise InstallError('更新包布局不正确。')
    package=packages[0].parent
    if (package/'license_public.pem').read_bytes()!=(Path(bundle)/'license_public.pem').read_bytes():raise InstallError('更新包验签公钥发生变化，请联系作者。')
    newmeta=verify_bundle(package)
    if newmeta['version']!=channel['version'] or newmeta['platform']!=target:
        raise InstallError('更新包版本或平台与签名清单不符。')
    ensure_license(package)
    run_checked([sys.executable,'-B',package/'bootstrap.py','--action','install'],timeout=1200)
    print('更新完成：'+channel['version']+'。请重开'+('Claude Code' if HOST=='claude' else '官方 Codex')+'，并新开会话。')


def main():
    parser=argparse.ArgumentParser(description='星空 Codex 安装/更新器；使用需联系坚哥授权。')
    parser.add_argument('--action',choices=['install','update','health','mcp','ads-kb','selection-kb','promotion-kb','request','notice','authorize','check-host-entries'],default='install')
    parser.add_argument('--bundle',type=Path,default=Path(__file__).resolve().parent)
    args=parser.parse_args()
    try:
        if args.action == 'check-host-entries':
            result=host_entry_notices(read_json(app_home()/'current.json',{}), diagnostic=True)
            print(result['host_entry_notice'] or '入口检查记录未变化，详情见安装日志。')
            return 0
        if args.action == 'authorize':
            preflight_license(args.bundle)
            return 0
        if HOST=='claude' and args.action in {'install','mcp','health','ads-kb','selection-kb','promotion-kb'}:
            import claude_host
            return claude_host.run(args.action,args.bundle)
        if args.action=='request':print('产品：'+LABEL+'\n本机申请码：'+fingerprint()+'\n联系：'+CONTACT)
        elif args.action=='install':install(args.bundle)
        elif args.action=='update':update(args.bundle)
        elif args.action=='mcp':install_mcp(args.bundle)
        elif args.action=='ads-kb':install_ads_kb(args.bundle)
        elif args.action=='selection-kb':install_selection_kb(args.bundle)
        elif args.action=='promotion-kb':install_promotion_kb(args.bundle)
        elif args.action=='notice':notice(args.bundle)
        else:health()
    except (InstallError,OSError,ValueError,KeyError,ImportError,zipfile.BadZipFile) as exc:
        print('[未完成] '+str(exc),file=sys.stderr);return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
