---
name: starsky-amazon-agent
description: 星空亚马逊业务入口；用于启动星空、S1–S5、继续产品流程，以及选品、Listing、视觉、广告和巡检单点请求。普通文章学习、编程或客户端问题不触发业务流程。
---

# 星空亚马逊 Agent · 正式版入口

这个入口只负责在本机打开正式版，业务规则全在解锁后的插件里。每个新会话第一次进来先做下面两步（版本没变时一两秒就好；刚点过 Upgrade 的新版本第一次要解开，约 1 分钟）：

1. 读安装记录 `~/.starsky-codex/current.json`（Windows：`%USERPROFILE%\.starsky-codex\current.json`），取 `python`。没有这个文件 → 告诉用户先运行安装包里的「安装与更新」完成授权，然后停止。
2. 运行 `<python> "<本 Skill 文件所在目录>/../../locked/git_unlock.py"`。它要写用户目录 `~/.starsky-codex` 和 Codex 的知识库配置，宿主请求权限时请用户允许。它输出一行 JSON：
   - `status: ready` → 取 `source` 为插件根，读 `<source>/skills/starsky-amazon-agent/SKILL.md`，在当前会话执行它的入口规则；所有业务相对路径以 `<source>` 为准，专业 Skill 按需读 `<source>/skills/<技能名>/SKILL.md`，模板和脚本在 `<source>/templates`、`<source>/scripts`。`updated: true` 时先告诉用户「星空已更新到 <version>」。
   - `status: blocked` → 把 `message` 原话告诉用户（例如会员到期要续费、授权缺失），不继续业务，不绕过。
3. 不委托其他 Agent、不新建后台任务；MCP 调用规则以 `<source>` 入口里的为准。
