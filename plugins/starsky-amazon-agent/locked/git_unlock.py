"""星空正式版解锁：Codex 通过 Git Marketplace（设置里的 Upgrade）拉到新版本后，用本机激活离线解开它。

由插件入口在「启动星空」时调用：<专用python> <插件>/locked/git_unlock.py
输出一行 JSON：status=ready（source=插件根）或 status=blocked（message 原话转告用户）。不打印授权码或密钥。
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))  # 用同一个签名包里的安装器，产品标识来自旁边的 host.json

import starsky_installer  # noqa: E402


def main():
    try:
        prepare='--prepare-sandbox' in sys.argv[1:]
        permission=None
        if prepare:
            starsky_installer.verify_locked(HERE)
            from sandbox_support import setup
            permission=setup(starsky_installer,sys.executable)
        result = starsky_installer.unlock_git_release(HERE)
        if permission is not None:
            result['sandbox_setup']=permission
            if permission.get('selection_required'):
                result['next_action']='请在 Codex 权限菜单选择「'+permission['profile']+'」一次，再完全退出重开 Codex、新建会话；原默认权限未自动切换。'
    except PermissionError:
        result={'status':'blocked','reason':'permission_required','message':'这次更新需要允许星空写入用户目录。请在 Codex 权限请求中点「允许」；未弹出时回复「帮我解决这个权限问题，继续启动星空」。当前环境若禁止申请权限，请在系统终端运行官方权限迁移入口；旧版和数据保留，不要关闭沙盒。'}
    except Exception as exc:  # noqa: BLE001 — 给用户看得懂的原因，不带路径和密钥
        message = str(exc) if isinstance(exc, (starsky_installer.InstallError, ValueError)) else type(exc).__name__
        cause=exc
        while cause is not None and not isinstance(cause,PermissionError):cause=cause.__cause__
        if cause is not None:
            result={'status':'blocked','reason':'permission_required','message':'星空尚未获准写入用户目录，请允许宿主的单次权限请求；未弹出时回复「帮我解决这个权限问题，继续启动星空」。拒绝或无法申请时，旧版和数据保留，请在系统终端运行官方权限迁移入口，不要关闭沙盒。'}
        else:
            result = {'status': 'blocked', 'message': '解锁未完成：' + message + '。当前已装版本继续可用，请按具体原因核对授权或联系作者。'}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get('status') == 'ready' else 2


if __name__ == '__main__':
    sys.exit(main())
