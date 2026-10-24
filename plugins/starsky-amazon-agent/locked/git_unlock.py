"""Unlock exactly the loaded signed entry; every failure blocks business dispatch."""
import json
import os
import subprocess
import sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import starsky_installer


def upgrade_message(expected, current):
    return (f'星空已更新到 {expected}，但本机还没完成解锁，当前仍是 {current}。'
            '请用支持权限申请的模型重新说『启动星空』并允许，或运行安装包里的『安装与更新』。')


def provision(core, meta, error, check):
    """The interpreter that started us lacks packages this release needs (R06.1): find or build the right runtime.

    Returns None when this build cannot heal (old locked folder without the provisioning module)."""
    try:
        import runtime_provision
    except ImportError:
        return None
    if not core.read_json(core.app_home() / 'current.json', {}):
        return None  # never set up through the authorized installer: nothing is downloaded before authorization
    return runtime_provision.ensure(core.app_home(), HERE, meta, error=error, python=sys.executable,
                                    check=check, verify_file=core.verify_file)


def relay(python, argv):
    """Continue the very same unlock under the freshly provisioned interpreter; its JSON goes straight to our stdout."""
    return subprocess.run([str(python), '-B', str(Path(__file__).resolve()), *argv, '--provisioned'],
                          env={**os.environ, 'PYTHONUTF8': '1', 'PYTHONDONTWRITEBYTECODE': '1'}).returncode


def main():
    core = starsky_installer
    argv = [a for a in sys.argv[1:] if a != '--provisioned']
    provisioned = '--provisioned' in sys.argv[1:]
    host_manifest = '.claude-plugin' if core.HOST == 'claude' else '.codex-plugin'
    manifest = core.read_json(HERE.parent / host_manifest / 'plugin.json', {})
    expected = manifest.get('version') or '未知版本'
    current = core.read_json(core.app_home() / 'current.json', {})
    previous = current.get('plugin_version') or current.get('version') or '未安装'
    try:
        receipt = core.read_json(core.app_home() / 'runtime/sandbox-ready.json', {})
        schema = receipt.get('schema')
        prepare = ('--prepare-sandbox' in argv or expected != previous
                   or not isinstance(schema, int) or isinstance(schema, bool) or schema < 2)
        permission = None
        if prepare:
            meta = core.verify_locked(HERE)
            if meta['plugin_version'] != expected:
                raise ValueError('当前入口与签名发行版本不一致。')
            from sandbox_support import setup, check_dependencies, RuntimeCheckError
            try:
                permission = setup(core, sys.executable)
            except RuntimeCheckError as error:
                outcome = None if provisioned else provision(core, meta, error, check_dependencies)
                if outcome is None:
                    raise
                if outcome['action'] == 'handover':
                    return relay(outcome['python'], argv)
                if outcome['action'] == 'building':
                    print(json.dumps({'status': 'blocked', 'reason': 'runtime_provisioning', 'message': outcome['message'],
                                      'log': outcome.get('log')}, ensure_ascii=False))
                    return 2
                raise outcome['error']
            receipt = core.read_json(core.app_home() / 'runtime/sandbox-ready.json', {})
            if core.HOST == 'claude':
                receipt = {'schema': 2, 'applicable': False, 'host': 'claude'}
            receipt['plugin_version'] = expected
            core.atomic_json(core.app_home() / 'runtime/sandbox-ready.json', receipt)
        # When we were handed over to a newly provisioned runtime, that interpreter becomes the recorded one.
        result = core.unlock_git_release(HERE, python=sys.executable) if provisioned else core.unlock_git_release(HERE)
        if result.get('status') == 'ready':
            source = Path(result['source'])
            saved = core.read_json(core.app_home() / 'current.json', {})
            actual = core.read_json(source / host_manifest / 'plugin.json', {})
            if (saved.get('plugin_version') != expected or actual.get('version') != expected
                    or Path(saved.get('source', '')).resolve() != source.resolve()
                    or Path(saved.get('home', '')).resolve() != HERE.parent.resolve()):
                raise ValueError('解锁记录与当前入口版本不一致。')
            if permission is not None:
                result['sandbox_setup'] = permission
                if permission.get('selection_required'):
                    result['next_action'] = '请在 Codex 权限菜单选择「' + permission['profile'] + '」一次，再完全退出重开 Codex、新建会话；原默认权限未自动切换。'
        else:
            result['message'] = upgrade_message(expected, previous)
    except Exception as exc:
        from sandbox_support import RuntimeCheckError
        result = {'status': 'blocked', 'message': str(exc) if isinstance(exc,RuntimeCheckError) else upgrade_message(expected, previous),
                  'reason': 'permission_required' if isinstance(exc, PermissionError) else type(exc).__name__}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get('status') == 'ready' else 2


if __name__ == '__main__':
    sys.exit(main())
