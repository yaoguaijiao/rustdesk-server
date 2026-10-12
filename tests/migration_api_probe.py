#!/usr/bin/env python3
"""API 副本探测，兼容 Python 3.9，仅使用标准库。

只允许进入 --network none 测试容器的网络命名空间，且接口必须只有 lo。
data-path 和公开密钥必须位于指定测试目录同一个 baseline/candidate 副本。
连接固定为 127.0.0.1:21114，不使用代理、不跟随重定向、不调用登录或写入接口。
SQLite 以 mode=ro 打开；现存 token 只在内存使用，不输出用户资料或完整响应。
API 自身可能续期现存 token，因而请求仍可能对副本产生少量数据库/日志写入。
没有可用旧 token 时明确跳过鉴权覆盖，不插入临时 token、不重置密码。

示例（nsenter 仅切换网络，因此 data-path 是宿主机副本路径）：
    # 不安装依赖；只请求隔离副本，续期和日志写入只发生于副本。
    nsenter -t TEST_CONTAINER_PID -n python3 -B migration_api_probe.py \
      --isolated-copy \
      --data-path /opt/rustdesk/migration-test-20261010/candidate/api_data \
      --public-key-file /opt/rustdesk/migration-test-20261010/candidate/server_data/id_ed25519.pub

操作者另须核对容器挂载确实指向该副本。此脚本不证明镜像的生产部署、
浏览器完整交互、外部 OAuth/LDAP 登录或真实客户端远程桌面会话。
"""

import argparse
import base64
import hmac
import http.client
import json
from html.parser import HTMLParser
from pathlib import Path
import socket
import sqlite3
import stat
import sys
import time
from urllib.parse import urljoin, urlsplit


COPY_ROOT = Path("/opt/rustdesk/migration-test-20261010")
HOST = "127.0.0.1"
PORT = 21114
MAX_BODY = 8 * 1024 * 1024
PAGE_SIZE = 1000
TABLES = ("users", "user_tokens", "peers", "address_books")


class ProbeError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ProbeError(message)


def report(check, status="PASS", **details):
    print(json.dumps(dict(check=check, status=status, **details), sort_keys=True))


def require_plain_path(path, regular_file=False):
    require(path.is_absolute() and ".." not in path.parts,
            "copy paths must be absolute without parent traversal")
    for component in tuple(reversed(path.parents)) + (path,):
        info = component.lstat()
        require(not stat.S_ISLNK(info.st_mode),
                "copy path ancestry must not contain symbolic links")
    require(path.resolve(strict=True) == path,
            "copy path must not redirect to another location")
    if regular_file:
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                "copied files must be regular files without hard links")
    else:
        require(stat.S_ISDIR(info.st_mode), "copy path must be a directory")


def require_copy_paths(data_path, public_key_path):
    require(sys.platform.startswith("linux"), "Linux network namespace required")
    require({name for _, name in socket.if_nameindex()} == {"lo"},
            "network namespace must contain only lo")
    root = COPY_ROOT
    data = Path(data_path)
    public_key = Path(public_key_path)
    try:
        data_parts = data.relative_to(root).parts
        key_parts = public_key.relative_to(root).parts
    except ValueError:
        raise ProbeError("paths must remain inside the fixed test-copy root")
    require(len(data_parts) >= 2 and data_parts[0] in ("baseline", "candidate"),
            "data-path must be inside a baseline or candidate copy")
    require(len(key_parts) >= 2 and key_parts[0] == data_parts[0],
            "public key must belong to the same test copy")
    require_plain_path(root)
    require_plain_path(data)
    require(public_key.name == "id_ed25519.pub",
            "only a copied id_ed25519.pub public key is accepted")
    require_plain_path(public_key, regular_file=True)
    database = data / "rustdeskapi.db"
    require_plain_path(database, regular_file=True)
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = database.with_name(database.name + suffix)
        try:
            sidecar.lstat()
        except FileNotFoundError:
            continue
        require_plain_path(sidecar, regular_file=True)
    return database, public_key


def request(path, token=None, client=False):
    require(path.startswith("/") and not path.startswith("//"),
            "request must use a local absolute path")
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization" if client else "api-token"] = (
            "Bearer " + token if client else token)
    connection = http.client.HTTPConnection(HOST, PORT, timeout=5)
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read(MAX_BODY + 1)
        require(len(body) <= MAX_BODY, "response exceeded the memory-only limit")
        return response.status, body
    finally:
        connection.close()


def json_request(path, token=None, client=False):
    status, body = request(path, token, client)
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise ProbeError("API response was not valid JSON")
    return status, payload


def admin_data(path, token):
    status, payload = json_request(path, token)
    require(status == 200 and isinstance(payload, dict)
            and payload.get("code") == 0, "authenticated admin request failed")
    require(isinstance(payload.get("data"), dict), "admin data shape changed")
    return payload["data"]


class EntryAssets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.references = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script" and attrs.get("src"):
            self.references.append(attrs["src"])
        if tag == "link" and attrs.get("rel") in ("stylesheet", "modulepreload"):
            if attrs.get("href"):
                self.references.append(attrs["href"])


def probe_public():
    status, body = request("/_admin/")
    require(status == 200, "admin frontend index failed")
    parser = EntryAssets()
    parser.feed(body.decode("utf-8"))
    require(parser.references, "admin frontend has no entry assets")
    assets = set()
    for reference in parser.references:
        target = urlsplit(urljoin("http://127.0.0.1:21114/_admin/", reference))
        require(target.scheme == "http" and target.hostname == HOST
                and target.port == PORT and target.path.startswith("/_admin/"),
                "frontend entry asset points outside the isolated API")
        assets.add(target.path + ("?" + target.query if target.query else ""))
    for path in sorted(assets):
        asset_status, asset_body = request(path)
        require(asset_status == 200 and bool(asset_body), "frontend entry asset failed")
    report("admin_frontend_entry_assets", count=len(assets))

    status, options = json_request("/api/login-options")
    require(status == 200 and isinstance(options, list), "client login-options failed")
    admin_options = admin_data("/api/admin/login-options", None)
    require(isinstance(admin_options.get("ops"), (list, type(None))),
            "admin login-options shape changed")
    report("login_options_without_login")

    protected = (
        "/api/admin/user/current", "/api/admin/config/server",
        "/api/admin/user/list", "/api/admin/peer/list",
        "/api/admin/address_book/list", "/api/user/info",
    )
    for path in protected:
        status, payload = json_request(path)
        denied = status in (401, 403) or (
            status == 200 and isinstance(payload, dict) and payload.get("code") == 403)
        require(denied, "protected endpoint did not reject a missing token")
    # Admin APIs historically return HTTP 200 with business code 403.
    report("missing_token_rejected", count=len(protected))


def counts(database):
    return {table: database.execute("SELECT count(*) FROM " + table).fetchone()[0]
            for table in TABLES}


def probe_page(path, token, expected):
    data = admin_data(path + "?page=1&page_size=" + str(PAGE_SIZE), token)
    items = data.get("list") or []
    require(isinstance(items, list) and data.get("total") == expected,
            "list total did not match the copied database")
    require(len(items) == min(expected, PAGE_SIZE), "list page length changed")


def probe_existing_token(database, before, public_key):
    old = database.execute(
        "SELECT t.token, t.user_id, u.username, u.is_admin, u.group_id "
        "FROM user_tokens t JOIN users u ON u.id = t.user_id "
        "WHERE t.expired_at > ? AND t.token <> '' AND u.status = 1 "
        "ORDER BY coalesce(u.is_admin, 0) DESC, t.expired_at DESC LIMIT 1",
        (int(time.time()),)).fetchone()
    if old is None:
        report("old_token_authentication_and_lists", "SKIP",
               reason="no_unexpired_enabled_user_token_in_copy")
        report("copied_public_key_config", "SKIP", reason="authentication_required")
        return False

    token, user_id, username, is_admin, group_id = old
    current = admin_data("/api/admin/user/current", token)
    require(current.get("username") == username
            and isinstance(current.get("token"), str)
            and hmac.compare_digest(current["token"], token),
            "old admin token did not resolve to its copied owner")
    status, current_client = json_request("/api/user/info", token, client=True)
    require(status == 200 and isinstance(current_client, dict)
            and current_client.get("name") == username and current_client.get("status") == 1,
            "old client token did not resolve to its copied owner")
    report("old_token_admin_and_client_authentication")

    expected_key = public_key.read_text(encoding="ascii").strip()
    require(len(base64.b64decode(expected_key, validate=True)) == 32,
            "copied public key format changed")
    server_config = admin_data("/api/admin/config/server", token)
    actual_key = server_config.get("key")
    require(isinstance(actual_key, str)
            and hmac.compare_digest(actual_key.strip(), expected_key),
            "API public server key did not match the copied public key")
    report("copied_public_key_config")

    own_peers = database.execute(
        "SELECT count(*) FROM peers WHERE user_id = ?", (user_id,)).fetchone()[0]
    own_addresses = database.execute(
        "SELECT count(*) FROM address_books WHERE user_id = ?", (user_id,)).fetchone()[0]
    probe_page("/api/admin/my/peer/list", token, own_peers)
    probe_page("/api/admin/my/address_book/list", token, own_addresses)
    report("old_token_own_device_and_addressbook_lists",
           devices=own_peers, address_books=own_addresses)

    if is_admin:
        for endpoint, table in (("user", "users"), ("peer", "peers"),
                                ("address_book", "address_books")):
            probe_page("/api/admin/" + endpoint + "/list", token, before[table])
        report("old_admin_token_global_lists",
               users=before["users"], devices=before["peers"],
               address_books=before["address_books"])
    else:
        report("old_admin_token_global_lists", "SKIP", reason="old_token_is_not_admin")

    group = database.execute("SELECT type FROM groups WHERE id = ?", (group_id,)).fetchone()
    if not is_admin and (group is None or group[0] != 2):
        visible_users = 1
        visible_peers = own_peers
    else:
        visible_users = database.execute(
            "SELECT count(*) FROM users WHERE group_id = ?", (group_id,)).fetchone()[0]
        visible_peers = database.execute(
            "SELECT count(*) FROM peers WHERE user_id IN "
            "(SELECT id FROM users WHERE group_id = ?)", (group_id,)).fetchone()[0]
    for endpoint, expected in (("users", visible_users), ("peers", visible_peers)):
        status, payload = json_request(
            "/api/" + endpoint + "?page=1&pageSize=" + str(PAGE_SIZE), token, client=True)
        require(status == 200 and isinstance(payload, dict)
                and payload.get("total") == expected
                and isinstance(payload.get("data"), list)
                and len(payload["data"]) == min(expected, PAGE_SIZE),
                "client user or device list did not match its copied group scope")
    report("old_token_client_user_and_device_lists",
           users=visible_users, devices=visible_peers)

    # Legacy client address-book GET is read-only; its data field is a JSON string.
    status, legacy_ab = json_request("/api/ab", token, client=True)
    require(status == 200 and isinstance(legacy_ab, dict)
            and isinstance(legacy_ab.get("data"), str), "client address-book response changed")
    legacy_data = json.loads(legacy_ab["data"])
    require(isinstance(legacy_data, dict)
            and isinstance(legacy_data.get("peers") or [], list),
            "client address-book data shape changed")
    expected_legacy = database.execute(
        "SELECT count(*) FROM address_books WHERE user_id = ? AND collection_id = 0",
        (user_id,)).fetchone()[0]
    require(len(legacy_data.get("peers") or []) == min(expected_legacy, PAGE_SIZE),
            "client address-book count did not match the copied database")
    report("old_token_client_addressbook", count=expected_legacy)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-copy", action="store_true")
    parser.add_argument("--data-path", required=True)
    parser.add_argument("--public-key-file", required=True)
    args = parser.parse_args()
    require(args.isolated_copy, "explicit isolated-copy acknowledgement required")
    database_path, public_key = require_copy_paths(args.data_path, args.public_key_file)
    report("network_and_copy_path_guard")
    connection = sqlite3.connect(database_path.as_uri() + "?mode=ro", uri=True,
                                 timeout=3, isolation_level=None)
    try:
        before = counts(connection)
        version = connection.execute(
            "SELECT version FROM versions ORDER BY id DESC LIMIT 1").fetchone()
        require(version and version[0] == 265, "copied API schema must remain at version 265")
        report("copied_database_baseline", **before, schema_version=265)
        probe_public()
        old_token_covered = probe_existing_token(connection, before, public_key)
        require(counts(connection) == before, "API requests changed copied table record counts")
        report("copied_table_counts_unchanged")
        report("api_probe_complete", old_token_covered=old_token_covered,
               token_expiry_may_refresh_in_copy=True)
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        main()
    except ProbeError as error:
        report("api_probe", "FAIL", reason=str(error))
        sys.exit(1)
    except Exception as error:
        # Deliberately suppress exception details, which could contain private response data.
        report("api_probe", "FAIL", reason=type(error).__name__)
        sys.exit(1)
