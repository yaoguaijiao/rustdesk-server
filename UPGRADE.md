# 自有 RustDesk 分支更新记录

本次先把 lejianwen 的部署基线补到 `v0.1.2`，再合并官方开源服务端
[`1.1.16`](https://github.com/rustdesk/rustdesk-server/releases/tag/1.1.16)。
本地升级分支为 `upgrade/official-1.1.16`，原 `forapi` 分支保留。

| 来源 | 固定提交 |
| --- | --- |
| 原本地 lejianwen 分支 | `fb8b5b9cf494d045f0feb370d83913b1a7506388` |
| lejianwen 线上镜像对应的 v0.1.2 | `cdffe9b45cdddd59f4f99917d393a9797162e4f7` |
| 原官方合并基线 | `c650217919ce6b67bf62a3d0c092e41f0d37b18b` |
| 官方开源服务端 1.1.16 | `73523b31cfd25d77dee862e6fc9f5e1fb5e485ef` |
| 保留的 hbb_common 子模块 | `d6b14975ffd35ed63528617a53795c479a6eaf13` |

## 合并处理

- 保留 lejianwen 的加密 TCP、WebSocket 注册/在线查询、强制登录、JWT 校验及
  `must-login/ml` 控制命令。保留 fork 的说明文档和镜像发布工作流。
- 注册超时保持部署版本的 100 秒，同时采用官方的 `i64` 类型修复。
  fork 共用的 TCP/WS 在线状态查询也修复了同一处长时间离线溢出。
- 合入官方 UDP `PunchHoleRequest` 反射/放大修复；UDP 注册与其他响应仍保留，
  连接请求走 TCP/WS。特别旧的客户端需要在测试环境检查连接兼容性。
- 合入官方 `punch-requests/pr` 查询、UI 的 mio 更新、rootless 镜像环境修复等。
- 去除完整 TCP 消息、JWT 密钥和协商对称密钥的明文调试输出。
- 不把官方 release 的子模块指针覆盖到 fork 已使用的指针，避免丢失其协议适配。

## 构建来源

`docker/Dockerfile` 的 `API_IMAGE` 现在必须显式传入。
三份发布工作流支持 `api_image` 手动输入；标签构建使用仓库变量
`RUSTDESK_API_IMAGE`。填写自己已发布的普通 API 镜像固定标签或 digest，
例如 `ghcr.io/yaoguaijiao/rustdesk-api:<自己的固定版本>`。
不能使用 `latest` 或 `full-s6` 镜像，后者会造成打包依赖循环。

API 工作流默认使用 `yaoguaijiao/rustdesk-api-web` 固定提交
`3998c2a9213fcd047252776d0f0db33e6717026c`。前端改动发布后，需要同步修改
API 两份工作流的 `WEBCLIENT_SOURCE_REF`；手动运行也可覆盖仓库和 ref。

发布顺序：普通 API 镜像 → 自有 server-s6 镜像 → 可选 API Full S6 镜像。
server 镜像的 API 基座需覆盖所发布的 CPU 架构。
现有正式发布工作流会更新镜像标签（包括 `latest`）；源码验证应先使用
`Validate server source`，它不会发布镜像或 Release。

## 本轮验证与后续验证

本轮只做必要 Git refs 获取、源码合并及内存中的语法/脚本检查。
没有安装依赖、初始化子模块、编译、拉取镜像或修改生产服务。
Rust 语法解析、YAML 解析和 `git diff --check` 不能代替完整编译与连接验证。

原 fork 的 `Cargo.lock` 已存在与子模块依赖要求不一致的情况，例如锁定 tokio
`1.43.0`，但固定子模块要求 `1.44`。本轮仅合并官方的 lockfile 变更，没有在
本机拉取整套依赖重新解析。新增 `Validate server source` 工作流在 GitHub runner
上执行单架构 `cargo check --bins`，上传解析后的 `Cargo.lock` 供审查；若有变化，
需审查并纳入仓库后再启用 `--locked` 构建。本轮尚未运行该工作流。

正式替换部署前，在独立测试环境验证：桌面客户端注册、直连和中继；浏览器远控；
登录与过期/无效 JWT 拒绝；强制登录开关；API 管理操作；设备在线/离线变化；
容器启动、健康检查和数据目录兼容。备份现有数据库、密钥及配置，回滚时恢复
原镜像及匹配的数据备份，不只替换镜像标签。

已知上游行为变化：默认中继速度阈值从 4 提高到 32 Mbit/s，单连接带宽上限
从 16 提高到 128 Mbit/s，可通过原有环境变量覆盖。
新增连接请求记录保存在内存中，无自动淘汰，`pr -` 可清空；后续应考虑容量上限。

## 低写入检查命令

```powershell
# 只读检查差异及空白错误，不安装依赖、不生成编译缓存。
git diff --check

# 只读查看当前分支及文件状态，不会提交或发布。
git status --short --branch

# 获取指定官方版本的源码对象，写入少量 Git 元数据；不拉全部标签或子模块。
# 将 <下一个版本> 换为确认过的官方开源服务端稳定标签再执行。
git fetch --no-tags --no-recurse-submodules official refs/tags/<下一个版本>:refs/remotes/official/release-<下一个版本>
```

本地 `cargo check` 会解析/下载依赖并写入 `target`；Docker 构建会拉取镜像并写入
层缓存。需要完整验证时优先使用上述 CI 或独立测试机，避免在本机重复构建。
