---
name: starsky-amazon-agent
description: 星空亚马逊业务入口：启动星空/实战、S1–S5/全链与续跑；选品、Listing、视觉、广告、巡检及独立任务。仅在用户请求亚马逊业务时使用。
---

# 星空亚马逊 Agent · 正式版入口

这个入口只负责在本机打开正式版，业务规则全在解锁后的插件里。每个新会话第一次进来先做下面两步（版本没变时一两秒就好；刚点过 Upgrade 的新版本第一次要解开，约 1 分钟）：

1. 读安装记录 `~/.starsky-codex/current.json`（Windows：`%USERPROFILE%\.starsky-codex\current.json`），取 `python`。没有这个文件 → 告诉用户先运行安装包里的「安装与更新」完成授权，然后停止。
2. 检查 `~/.starsky-codex/runtime/sandbox-ready.json`：不存在或 schema 小于 2 时需旧用户一次性修复，使用宿主权限申请运行 `<python> "<本 Skill 文件所在目录>/../../locked/git_unlock.py" --prepare-sandbox`，理由「星空需一次性登记自身目录和知识库入口，请允许；不会关闭沙盒或改变审批方式」。宿主禁止申请或用户拒绝时停止，提示在系统终端运行该命令，不绕过。配置需重开 Codex/新会话生效。记录 schema 为 2 时正常运行 `<python> "<本 Skill 文件所在目录>/../../locked/git_unlock.py"`；如记录含 permission_request_required，必须主动通过宿主申请本次解锁权限。不能因为迁移已完成就省略必要的单次申请。只读模式或仍被拒绝时同样遵守宿主权限边界，不修改沙盒或审批模式。它输出一行 JSON：
   - `status: ready` → `updated: true` 时先告诉用户「星空已更新到 <version>」。不得创建未选择的命名权限档或自动设置全局 default_permissions。否则取 `source` 为插件根，读 `<source>/skills/starsky-amazon-agent/SKILL.md`，在当前会话执行它的入口规则；所有业务相对路径以 `<source>` 为准，专业 Skill 按需读 `<source>/skills/<技能名>/SKILL.md`，模板和脚本在 `<source>/templates`、`<source>/scripts`。
   - `status: blocked` → 把 `message` 原话告诉用户（例如会员到期要续费、授权缺失），不继续业务，不绕过。
3. 授权检查和解锁由当前会话完成，不委托其他 Agent、不新建后台任务。解锁成功后的业务执行、受限辅助任务和 MCP 调用，按 `<source>` 入口及当前步骤规则执行。
