"""升级时自己准备专用 Python 运行环境（R06.1）。

背景：Codex 市场的 Upgrade 只会拿到“薄插件”。新版本一旦新增依赖（3.0.22 新增 cv2、rapidocr、onnxruntime），
旧运行环境就缺包，解锁脚本只会检查并阻断，要用户手动去运行安装包里的「安装与更新」。
这里让解锁脚本自己补上：先找本版本对应、已就绪的运行环境并交接过去；找不到就在后台建一个，用户过几分钟再说「启动星空」。

约定与 bootstrap.py 完全一致：运行环境放在 <app_home>/runtimes/<依赖清单 SHA-256 前 16 位>/，
就绪标记 .ready 的内容是完整 SHA-256，所以“安装与更新”建好的环境这里可以直接复用，反之亦然。

安全：只信任被签名的 bundle.json 列出了哈希的 requirements.txt；哈希对不上就不装。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REQUIREMENTS = 'requirements.txt'
STALE_AFTER_SECONDS = 45 * 60  # 超过这个时间没有结束的“正在准备”视为已中断，可以重新开始
ESTIMATE = '首次需要联网，约 3 到 10 分钟'


class ProvisionError(ValueError):
    """面向用户的可读失败原因。"""


def runtime_python(runtime):
    return Path(runtime) / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')


def digest_of(requirements):
    return hashlib.sha256(Path(requirements).read_bytes()).hexdigest()


def runtime_dir(app_home, digest):
    return Path(app_home) / 'runtimes' / digest[:16]


def status_path(app_home, digest):
    return Path(app_home) / 'runtimes' / (digest[:16] + '.provision.json')


def log_path(app_home, digest):
    return Path(app_home) / 'runtimes' / (digest[:16] + '.provision.log')


def is_ready(runtime, digest):
    marker = Path(runtime) / '.ready'
    return runtime_python(runtime).is_file() and marker.is_file() and marker.read_text(encoding='utf-8').strip() == digest


def _now():
    return datetime.now(timezone.utc)


def read_status(app_home, digest):
    try:
        data = json.loads(status_path(app_home, digest).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_status(app_home, digest, **fields):
    path = status_path(app_home, digest)
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {**read_status(app_home, digest), **fields}
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding='utf-8')
    os.replace(temporary, path)
    return document


def _age_seconds(status):
    try:
        started = datetime.fromisoformat(str(status.get('started_at')))
    except ValueError:
        return None
    return (_now() - started).total_seconds()


def _alive(pid):
    if not isinstance(pid, int) or pid <= 0:
        return False
    if os.name == 'nt':
        return True  # Windows 下没有轻量的存活探测，靠超时判断
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def build_in_progress(app_home, digest):
    status = read_status(app_home, digest)
    age = _age_seconds(status)
    return status.get('state') == 'building' and age is not None and age < STALE_AFTER_SECONDS and _alive(status.get('pid'))


# ───────────────────────── 后台工人：真正建环境 ─────────────────────────
def build(app_home, requirements, digest, *, python=None, run=subprocess.run):
    """建 venv、装依赖、写 .ready。失败只写状态，不留“就绪”标记。成功返回 True。"""
    app_home, requirements = Path(app_home), Path(requirements)
    runtime = runtime_dir(app_home, digest)
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUTF8': '1', 'PIP_DISABLE_PIP_VERSION_CHECK': '1'}
    _write_status(app_home, digest, state='building', pid=os.getpid(), started_at=_now().isoformat(), finished_at=None, error=None)
    try:
        if digest_of(requirements) != digest:
            raise ProvisionError('依赖清单与签名记录的哈希不一致，已停止安装。')
        if not runtime_python(runtime).is_file():
            print('正在创建星空专用 Python 环境……', flush=True)
            run([str(python or sys.executable), '-m', 'venv', str(runtime)], env=env, check=True)
        print('正在安装本版本的脚本依赖……', flush=True)
        run([str(runtime_python(runtime)), '-m', 'pip', 'install', '--no-cache-dir', '-r', str(requirements)], env=env, check=True)
        (runtime / '.ready').write_text(digest, encoding='utf-8')
    except (OSError, subprocess.CalledProcessError, ProvisionError) as error:
        reason = str(error) if isinstance(error, ProvisionError) else f'{type(error).__name__}：{error}'
        _write_status(app_home, digest, state='failed', finished_at=_now().isoformat(), error=reason[:300])
        print('运行环境准备失败：' + reason, flush=True)
        return False
    _write_status(app_home, digest, state='ready', finished_at=_now().isoformat(), error=None)
    print('运行环境已就绪。', flush=True)
    return True


# ───────────────────────── 解锁脚本侧：决定“继续 / 交接 / 后台准备” ─────────────────────────
def _spawn_worker(app_home, requirements_copy, digest, python, popen):
    log = log_path(app_home, digest)
    log.parent.mkdir(parents=True, exist_ok=True)
    command = [str(python), '-B', str(Path(__file__).resolve()), '--app-home', str(app_home),
               '--requirements', str(requirements_copy), '--digest', digest]
    options = {'stdin': subprocess.DEVNULL, 'close_fds': True}
    if os.name == 'nt':
        options['creationflags'] = 0x00000008 | 0x00000200 | 0x08000000  # DETACHED_PROCESS | NEW_PROCESS_GROUP | NO_WINDOW
    else:
        options['start_new_session'] = True  # 不随宿主的命令结束而被一起杀掉
    with open(log, 'ab') as stream:
        stream.write(f'\n[{_now().isoformat()}] 开始准备专用运行环境\n'.encode('utf-8'))
        stream.flush()
        process = popen(command, stdout=stream, stderr=subprocess.STDOUT, **options)
    return process, log


def ensure(app_home, locked, meta, *, error, python, check, verify_file, popen=subprocess.Popen):
    """在解锁脚本的依赖自检已经失败（error）之后调用，返回 {'action': 'handover'|'building'|'unavailable', ...}。

    handover    本版本对应的运行环境已就绪，请换用 result['python'] 重新运行解锁
    building    已在后台准备（或仍在准备），result['message'] 是给用户的原话
    unavailable 无法自愈（没有签名的依赖清单等），请按原来的方式报错（result['error']）
    """
    app_home, locked = Path(app_home), Path(locked)
    original = error
    missing = list(getattr(original, 'missing', []) or [])
    requirements = locked / REQUIREMENTS
    listed = (meta.get('files') or {}).get(REQUIREMENTS)
    if not requirements.is_file() or not listed:
        return {'action': 'unavailable', 'error': original}
    try:
        verify_file(requirements, listed)
    except Exception:
        return {'action': 'unavailable', 'error': ValueError('依赖清单未通过签名校验，未自动安装依赖。请运行安装包里的「安装与更新」。')}
    digest = digest_of(requirements)
    runtime = runtime_dir(app_home, digest)
    target = runtime_python(runtime)
    if is_ready(runtime, digest):
        try:
            check(target)
            return {'action': 'handover', 'python': str(target), 'digest': digest}
        except Exception:
            pass  # 标记说就绪但包不全（被删过或装坏了）：当作没有，重新准备
    version = meta.get('plugin_version') or meta.get('version') or '新版本'
    log = log_path(app_home, digest)
    if build_in_progress(app_home, digest):
        minutes = int((_age_seconds(read_status(app_home, digest)) or 0) // 60)
        return {'action': 'building', 'started': False, 'log': str(log), 'digest': digest,
                'message': f'星空已更新到 {version}，专用运行环境仍在后台准备中（已进行约 {minutes} 分钟）。请稍后再说「启动星空」。进度见 {log}'}
    previous = read_status(app_home, digest)
    retry = f'上次准备失败（{previous.get("error")}），已重新开始。' if previous.get('state') == 'failed' else ''
    copy = app_home / 'runtimes' / (digest[:16] + '.requirements.txt')
    copy.parent.mkdir(parents=True, exist_ok=True)
    copy.write_bytes(requirements.read_bytes())
    process, log = _spawn_worker(app_home, copy, digest, python, popen)
    _write_status(app_home, digest, state='building', pid=getattr(process, 'pid', None), started_at=_now().isoformat(),
                  finished_at=None, error=None, log=str(log), version=version)
    what = ('缺 ' + '、'.join(missing)) if missing else '依赖有变化'
    return {'action': 'building', 'started': True, 'log': str(log), 'digest': digest,
            'message': f'星空已更新到 {version}，但新版本需要新的依赖（{what}）。已在后台为它准备专用运行环境，{ESTIMATE}；'
                       f'无需手动操作。请等几分钟后再说「启动星空」。{retry}进度见 {log}'}


def main(argv=None):
    parser = argparse.ArgumentParser(description='后台准备星空专用运行环境（由解锁脚本启动，不需要手动运行）。')
    parser.add_argument('--app-home', type=Path, required=True)
    parser.add_argument('--requirements', type=Path, required=True)
    parser.add_argument('--digest', required=True)
    args = parser.parse_args(argv)
    return 0 if build(args.app_home, args.requirements, args.digest) else 1


if __name__ == '__main__':
    sys.exit(main())
