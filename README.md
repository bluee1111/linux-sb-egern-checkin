# linux.sb Egern 自动签到

Egern module for linux.sb daily check-in.

## 使用

1. 导入 `linux-sb-checkin.yaml`。
2. 正常打开 linux.sb 并登录，模块会自动抓取 Cookie（不需要手动填）。
3. 默认每天 09:37 执行，可按需修改 `CronExp`。

脚本会获取 CSRF Token、提交签到并再次确认状态，然后通过 Egern 通知结果。Cookie 不写入仓库。

## v5 变更

- 遇到站点临时不可用（Cloudflare 502/521/522、挑战页、空响应）自动重试 3 次，间隔 8 秒。
- 失败通知区分真实原因：Cookie 过期 / 站点不可用 / 人机验证 / 页面结构变化。
- 默认执行时间改为 09:37，避开站点深夜不稳定的时段（00:10 经常撞上 5xx）。
