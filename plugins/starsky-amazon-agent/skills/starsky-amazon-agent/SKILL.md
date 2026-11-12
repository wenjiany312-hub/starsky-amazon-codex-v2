---
name: starsky-amazon-agent
description: 星空亚马逊业务入口：启动星空/实战、S1–S5/全链与续跑；选品、Listing、视觉、广告、巡检及独立任务。仅在用户请求亚马逊业务时使用。
---

# 星空亚马逊 Agent · 正式版入口

这个入口只负责打开自身对应的正式版；版本核对优先于启动卡和一切业务。

1. 插件根是本 Skill 文件所在目录的上两级。先读取自身 `<插件根>/.codex-plugin/plugin.json` 的版本 X，再读取 `~/.starsky-codex/current.json` 的 `plugin_version` 为 Y（缺失写“未安装”），仅取专用 `python`，不得输出授权或完整记录。
2. 若 X ≠ Y，或 `~/.starsky-codex/runtime/sandbox-ready.json` 不存在、schema < 2，必须先运行 `<python> "<插件根>/locked/git_unlock.py" --prepare-sandbox`；否则仍运行 `<python> "<插件根>/locked/git_unlock.py"` 验证当前身份。权限请求时请用户允许；宿主禁止申请权限、权限被拒、脚本错误或没有 Python 时均停止。
3. 仅 `status: ready` 且返回 source 的 `.codex-plugin/plugin.json` 版本等于 X，current.json 的 plugin_version 等于 X，source/home 目录都存在时，读取 `<source>/skills/starsky-amazon-agent/SKILL.md` 并在当前会话执行。`updated: true` 时告诉用户「星空已更新到 <version>」。启动和业务步骤不转述兼容入口信息；详情仅留安装日志，用户主动要求检查安装时才提示一次。契约、模板和脚本只按这个验证过的 source 解析。
4. 解锁失败原话输出（将 X/Y 换成实际值）：「星空已更新到 X，但本机还没完成解锁，当前仍是 Y。请用支持权限申请的模型重新说『启动星空』并允许，或运行安装包里的『安装与更新』。」然后停止，不继续业务。
5. 不得使用 current.json 里与 X 不一致的 source 或 home；不得自行到 marketplace/versions 目录里挑版本；不得回退到旧源目录、旧 home 或旧缓存。当前会话完成检查，不委托其他 Agent、不新建后台任务。成功后按真实业务入口规则执行。
6. 脚本若返回 `status: blocked` 且 `reason: runtime_provisioning`，说明新版本需要新的依赖、解锁脚本已在后台自行准备专用运行环境：原样转述返回的 `message`，然后停止，不要重试、不要自己安装任何依赖，也不要套用第 4 条的话术。用户过几分钟再说「启动星空」即可。
