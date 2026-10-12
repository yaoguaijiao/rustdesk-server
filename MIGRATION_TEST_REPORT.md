# 镜像构建与数据副本测试

2026-10-12 完成本轮隔离验证，未切换生产服务。测试使用 2026-10-10 14:55（UTC+8）取得的一致数据快照。

## 固定产物

- [成功的完整构建](https://github.com/yaoguaijiao/rustdesk-api/actions/runs/38032499529)：前端、静态 Go API、三个静态 Rust 服务端二进制、合并 S6 镜像。
- 服务端源码：`0784a2014e9a6ad4138198f681cccd51eecf0183`，包含官方开源服务端 `1.1.16`。
- API 工作流提交：`e97f5e420bb7033ee26c234d913d2068e2fa964a`；本次构建的 PR merge revision 为 `0e2ee48a25664cbe1c87d52dfcbed37fe34b94ad`。
- 管理前端：`3998c2a9213fcd047252776d0f0db33e6717026c`。
- 服务器已导入镜像：`localhost/rustdesk-server-s6:migration-0e2ee48a2566`。
- Podman 镜像 ID：`da9cc91f77f4310ea3a518d27f06b7ecc7c0b343edb29c80a97fcb0a9b1f6ab7`。
- 镜像归档约 38.9 MB，SHA256：`3df2674dc2797b90e4d3ef16d40744c537be5bd5bfdca7b4c18f459bf351ce07`。

GitHub 测试产物设置保留三天；服务器已有的固定镜像可继续复用。镜像在 CI 构建，归档直接下载到服务器内存后导入 Podman，没有在用户电脑保存大文件，也没有在服务器保留重复归档。没有发布正式 Release、Docker Hub 镜像或更新 `latest`。

## 隔离与数据保护

服务器使用 Podman 5.6.0、podman-compose 1.5.0。原部署的两处持久化挂载为 `/opt/rustdesk/server_data → /data` 和 `/opt/rustdesk/api_data → /app/data`。

测试目录是 `/opt/rustdesk/migration-test-20261010`，目录权限为 `0700`。原始快照、公私钥及数据副本仅保存在服务器，不进入 Git 仓库、CI 或公开日志。

备份在独立、private 的 mount namespace 中将原数据目录临时只读挂载，再使用 SQLite Online Backup API 取得包括 WAL 已提交数据的一致快照。没有使用忽略 WAL 的 `immutable` 方式备份；备份前后的表内容指纹一致，两库 `integrity_check` 为 `ok`。退出 namespace 后，生产挂载保持原状。

所有测试容器均使用 `network_mode: none`，不发布端口、没有外网连接，数据卷只指向副本。测试请求通过 `nsenter` 进入对应容器网络命名空间，只访问 loopback；脚本拒绝其他网络、副本路径越界，以及数据库/旁文件/公钥的符号链接或硬链接。

## 实测结果

| 检查 | 旧镜像基线 | 新镜像副本 |
| --- | --- | --- |
| hbbs/hbbr/API 三服务确实运行、API 返回版本 | 通过 | 通过 |
| 原公私钥内容及 API 返回公钥保持一致 | 通过 | 通过 |
| UDP 模拟节点注册与心跳、WS 注册与在线查询 | 通过 | 通过 |
| 两个模拟节点写入副本 SQLite | 通过 | 通过 |
| 中继拒绝错误公钥，正确公钥双向转发逐字节一致 | 通过 | 通过 |
| 管理前端入口及十个入口资源、登录选项 | 通过 | 通过 |
| 原有未过期令牌的后台及客户端鉴权 | 通过 | 通过 |
| 后台全局/本人列表、客户端用户/设备/地址簿范围 | 通过 | 通过 |
| 六个受保护接口拒绝缺少令牌的请求 | 通过 | 通过 |
| API 数据库版本保持 265 | 通过 | 通过 |
| 全部原有行的全部字段、表结构和索引保持一致 | 通过 | 通过 |

对账覆盖两个数据库的所有表和 `sqlite_master`。唯一新增记录是每份运行副本中明确登记的两个模拟注册节点；原始快照没有模拟节点。API 请求可能续期副本中的令牌，本次复检中原有行内容仍全部一致。

新镜像的测试容器曾重建，原密钥、数据库内容和模拟注册记录继续保留。

随后停止新版测试容器，使用旧镜像挂载同一份已运行过新版的数据副本进行回滚演练：三个服务、旧令牌鉴权和全部十三项 API 检查通过，原有行、结构、索引及密钥仍一致。回滚仅发生在副本上。

## 健康检查处理

现有镜像脚本只查询 hbbs/hbbr 的 S6 状态，没有检查 API；S6 状态查询成功也不等于进程处于 up。本次导出的新镜像导入 Podman 后没有保留镜像级健康检查配置，因此测试 Compose 显式检查三个服务的 `s6-svstat -u` 输出为 `true`，并请求 `/api/version`。显式健康检查在 Podman 上通过。

API 测试工作流已补充同样的三服务和版本检查，属于后续构建的检查增强；本次固定镜像的实测证据以以上构建链接和服务器报告为准。

## 留存状态与下一步边界

- `rustdesk-migration-baseline`、`rustdesk-migration-candidate`、`rustdesk-migration-rollback` 已全部停止，重启策略为 `no`。
- 固定测试镜像、原始快照、运行副本及隔离 Compose 保留在服务器。
- 服务器汇总：`/opt/rustdesk/migration-test-20261010/test-summary.json`；详细报告分别在 `baseline`、`candidate`、`rollback` 子目录。
- 生产容器继续运行且 healthy，容器 ID、镜像、启动时间及原密钥指纹与测试前一致。没有执行生产数据迁移或清空。

本轮没有验证 NaCl TCP 加密握手、真实客户端远控画面/直连会话、浏览器完整交互以及外部 OAuth/LDAP。正式迁移前还应验证真实客户端，并重新取得当时的数据库、密钥及配置一致备份；10 月 10 日的测试快照不能替代未来切换前的新备份。

```bash
# 只读查看已测试的镜像 ID；不拉取镜像、不构建、不修改数据库。
podman image inspect localhost/rustdesk-server-s6:migration-0e2ee48a2566 --format '{{.Id}}'

# 只读查看测试容器状态；不启动或重启任何容器，无业务数据写入。
podman inspect rustdesk-migration-candidate --format '{{.State.Status}}'
```
