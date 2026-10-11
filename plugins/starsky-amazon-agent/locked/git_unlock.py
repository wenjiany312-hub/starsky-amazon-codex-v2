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
        result = starsky_installer.unlock_git_release(HERE)
    except Exception as exc:  # noqa: BLE001 — 给用户看得懂的原因，不带路径和密钥
        message = str(exc) if isinstance(exc, (starsky_installer.InstallError, ValueError)) else type(exc).__name__
        result = {'status': 'blocked', 'message': '解锁未完成：' + message + '。当前已装版本继续可用，可运行安装包里的“安装与更新”。'}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get('status') == 'ready' else 2


if __name__ == '__main__':
    sys.exit(main())
