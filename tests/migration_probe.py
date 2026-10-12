#!/usr/bin/env python3
"""隔离副本协议探测；仅使用 Python 标准库，不下载依赖、不读取密钥文件。

运行前由操作者验证测试容器使用 --network none、无发布端口且只挂载副本。
本脚本再次要求网络命名空间仅有 lo，固定连接 127.0.0.1，禁止任意目标地址。
它向 hbbs 副本添加两个 migration-probe-* 模拟节点，不修改生产节点。

Linux 示例（只进入测试容器的网络命名空间，不进入其文件系统）：
    # 公开的服务器 licence key 仅经环境变量传入；不要传私钥或生产 JWT。
    # nsenter/probe 不安装、不构建；注册只对测试数据库产生少量写入。
    nsenter -t TEST_CONTAINER_PID -n python3 -B migration_probe.py --isolated-copy

ENCRYPTED_ONLY=1 的 hbbr 要求 RUSTDESK_PROBE_RELAY_LICENCE_KEY；由操作者在
内存中传入公开 licence key。--require-relay-key-auth 额外确认错误 key 被拒绝。
不改变 ENCRYPTED_ONLY、MUST_LOGIN 或容器配置，不测试 NaCl TCP 密钥交换、
端到端加密或真实桌面会话。UDP 没有 OnlineRequest，在线位图走 WS 21118。
只检查注册应答和内存在线状态；数据库持久化还需由操作者核对副本。

固定协议依据：hbb_common d6b14975ffd35ed63528617a53795c479a6eaf13
https://github.com/rustdesk/hbb_common/blob/d6b14975ffd35ed63528617a53795c479a6eaf13/protos/rendezvous.proto
"""

import argparse
import base64
import hashlib
import os
import secrets
import socket
import struct
import sys
import time


HOST = "127.0.0.1"
HBBS_UDP_PORT = 21116
HBBS_WS_PORT = 21118
HBBR_WS_PORT = 21119
MAX_PACKET = 1024 * 1024
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class ProbeError(Exception):
    pass


class WebSocketClosed(ProbeError):
    pass


def require(condition, message):
    if not condition:
        raise ProbeError(message)


def varint(value):
    require(0 <= value < 1 << 64, "protobuf integer out of range")
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def blob(field, value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return varint((field << 3) | 2) + varint(len(value)) + value


def rendezvous(field, body):
    return blob(field, body)


def read_varint(data, offset):
    value = 0
    for index in range(10):
        require(offset < len(data), "truncated protobuf integer")
        byte = data[offset]
        offset += 1
        require(index < 9 or byte <= 1, "protobuf integer overflow")
        value |= (byte & 127) << (7 * index)
        if not byte & 128:
            return value, offset
    raise ProbeError("protobuf integer overflow")


def fields(data):
    require(len(data) <= MAX_PACKET, "protobuf packet too large")
    parsed = {}
    offset = 0
    while offset < len(data):
        tag, offset = read_varint(data, offset)
        field, wire = tag >> 3, tag & 7
        require(field > 0, "protobuf field zero")
        if wire == 0:
            value, offset = read_varint(data, offset)
        elif wire == 2:
            length, offset = read_varint(data, offset)
            require(length <= len(data) - offset, "truncated protobuf bytes")
            value = data[offset:offset + length]
            offset += length
        elif wire in (1, 5):
            length = 8 if wire == 1 else 4
            require(length <= len(data) - offset, "truncated protobuf fixed field")
            value = data[offset:offset + length]
            offset += length
        else:
            raise ProbeError("unsupported protobuf wire type")
        parsed.setdefault(field, []).append((wire, value))
    return parsed


def one(parsed, field, wire, default=None):
    values = parsed.get(field, [])
    if not values:
        return default
    require(len(values) == 1 and values[0][0] == wire,
            "unexpected protobuf field shape")
    return values[0][1]


def response_body(packet, expected_union):
    body = one(fields(packet), expected_union, 2)
    require(body is not None, "unexpected rendezvous response type")
    return fields(body)


def register_pk(peer_id):
    # 合成标识和随机 pk 只用于协议注册；不声称完成任何密码学握手。
    body = blob(1, peer_id) + blob(2, secrets.token_bytes(16))
    body += blob(3, secrets.token_bytes(32))
    return rendezvous(15, body)


def check_registered(packet):
    result = one(response_body(packet, 16), 1, 0, 0)
    require(result == 0, "hbbs rejected synthetic registration (code %d)" % result)


def ws_frame(opcode, payload, mask=None):
    require(len(payload) <= MAX_PACKET, "WebSocket payload too large")
    mask = secrets.token_bytes(4) if mask is None else mask
    require(len(mask) == 4, "invalid WebSocket mask")
    first = 0x80 | opcode
    length = len(payload)
    if length < 126:
        header = bytes((first, 0x80 | length))
    elif length <= 65535:
        header = bytes((first, 0x80 | 126)) + struct.pack(">H", length)
    else:
        header = bytes((first, 0x80 | 127)) + struct.pack(">Q", length)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return header + mask + masked


class WebSocket:
    def __init__(self, port, timeout):
        self.timeout = timeout
        self.buffer = bytearray()
        self.sock = socket.create_connection((HOST, port), timeout)
        try:
            key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
            request = (
                "GET / HTTP/1.1\r\nHost: %s:%d\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ) % (HOST, port, key)
            self.sock.sendall(request.encode("ascii"))
            deadline = time.monotonic() + timeout
            while b"\r\n\r\n" not in self.buffer:
                require(len(self.buffer) < 16384, "WebSocket handshake header too large")
                self._receive(deadline)
            header, remainder = bytes(self.buffer).split(b"\r\n\r\n", 1)
            self.buffer = bytearray(remainder)
            lines = header.decode("ascii").split("\r\n")
            status = lines[0].split()
            require(len(status) >= 2 and status[1] == "101",
                    "WebSocket HTTP upgrade was rejected")
            headers = {}
            for line in lines[1:]:
                require(":" in line, "malformed WebSocket handshake header")
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()
            expected = base64.b64encode(hashlib.sha1(
                (key + WS_GUID).encode("ascii")).digest()).decode("ascii")
            require(headers.get("sec-websocket-accept") == expected,
                    "WebSocket handshake accept mismatch")
            require(headers.get("upgrade", "").lower() == "websocket",
                    "WebSocket upgrade header missing")
            connections = headers.get("connection", "").lower().split(",")
            require("upgrade" in [value.strip() for value in connections],
                    "WebSocket connection upgrade header missing")
        except Exception:
            self.sock.close()
            raise

    def _receive(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("WebSocket response deadline exceeded")
        self.sock.settimeout(remaining)
        part = self.sock.recv(4096)
        if not part:
            raise WebSocketClosed("WebSocket peer closed connection")
        self.buffer.extend(part)

    def _exact(self, length, deadline):
        while len(self.buffer) < length:
            self._receive(deadline)
        value = bytes(self.buffer[:length])
        del self.buffer[:length]
        return value

    def send(self, payload):
        self.sock.settimeout(self.timeout)
        self.sock.sendall(ws_frame(2, payload))

    def receive(self):
        deadline = time.monotonic() + self.timeout
        while True:
            first, second = self._exact(2, deadline)
            require(first & 0x80 and not first & 0x70,
                    "unsupported fragmented or reserved WebSocket frame")
            require(not second & 0x80, "server sent a masked WebSocket frame")
            opcode = first & 15
            length = second & 127
            if length == 126:
                length = struct.unpack(">H", self._exact(2, deadline))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._exact(8, deadline))[0]
            require(length <= MAX_PACKET, "WebSocket response too large")
            require(opcode < 8 or length <= 125, "invalid WebSocket control frame")
            payload = self._exact(length, deadline)
            if opcode == 8:
                raise WebSocketClosed("WebSocket peer sent close frame")
            if opcode == 9:
                self.sock.sendall(ws_frame(10, payload))
            elif opcode == 10:
                continue
            elif opcode == 2:
                return payload
            else:
                raise ProbeError("unexpected WebSocket opcode")

    def close(self):
        try:
            self.sock.settimeout(0.2)
            self.sock.sendall(ws_frame(8, struct.pack(">H", 1000)))
        except OSError:
            pass
        self.sock.close()


def udp_response(sock, request, expected_union, timeout):
    sock.send(request)
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("hbbs UDP response deadline exceeded")
        sock.settimeout(remaining)
        packet = sock.recv(MAX_PACKET)
        parsed = fields(packet)
        if expected_union in parsed:
            return packet
        # heartbeat 可能附带 ConfigUpdate；只接受已知额外消息。
        require(set(parsed) == {14}, "unexpected hbbs UDP response")


def online_state(peer_ids, expected, timeout):
    query = rendezvous(23, b"".join(blob(2, peer) for peer in peer_ids))
    ws = WebSocket(HBBS_WS_PORT, timeout)
    try:
        ws.send(query)
        state = one(response_body(ws.receive(), 24), 1, 2, b"")
        require(state == expected, "hbbs online bitmap mismatch")
    finally:
        ws.close()


def probe_hbbs(timeout):
    suffix = secrets.token_hex(8)
    udp_id = "migration-probe-udp-" + suffix
    ws_id = "migration-probe-ws-" + suffix
    missing_id = "migration-probe-missing-" + suffix
    heartbeat = rendezvous(6, blob(1, udp_id))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind((HOST, 0))
        udp.connect((HOST, HBBS_UDP_PORT))
        packet = udp_response(udp, heartbeat, 7, timeout)
        require(one(response_body(packet, 7), 2, 0, 0) == 1,
                "hbbs did not request a key for fresh synthetic peer")
        check_registered(udp_response(udp, register_pk(udp_id), 16, timeout))
        packet = udp_response(udp, heartbeat, 7, timeout)
        require(one(response_body(packet, 7), 2, 0, 0) == 0,
                "hbbs requested the key again after successful registration")
        print("PASS hbbs_udp_register_and_heartbeat", flush=True)
        online_state([udp_id, missing_id], b"\x80", timeout)
        print("PASS hbbs_online_query_udp_peer_online_missing_peer_offline", flush=True)
        ws = WebSocket(HBBS_WS_PORT, timeout)
        try:
            ws.send(register_pk(ws_id))
            check_registered(ws.receive())
            online_state([udp_id, ws_id, missing_id], b"\xc0", timeout)
            print("PASS hbbs_ws_register_and_online_query", flush=True)
        finally:
            ws.close()
    return udp_id, ws_id


def relay_request(pair_id, licence):
    return rendezvous(18, blob(2, pair_id) + blob(6, licence))


def probe_relay(timeout, licence, require_key_auth):
    require(bool(licence),
            "missing RUSTDESK_PROBE_RELAY_LICENCE_KEY (public licence key required)")
    try:
        decoded = base64.b64decode(licence, validate=True)
    except (ValueError, TypeError):
        raise ProbeError("relay licence input must be the base64 public key")
    require(len(decoded) == 32, "relay licence input must be a 32-byte public key")
    if require_key_auth:
        wrong = WebSocket(HBBR_WS_PORT, timeout)
        try:
            wrong.send(relay_request(secrets.token_hex(16), "migration-probe-invalid-key"))
            try:
                wrong.receive()
            except WebSocketClosed:
                print("PASS hbbr_wrong_licence_key_rejected", flush=True)
            else:
                raise ProbeError("hbbr unexpectedly answered wrong licence key")
        except socket.timeout:
            raise ProbeError("hbbr did not reject wrong licence key; check expected ENCRYPTED_ONLY")
        finally:
            wrong.close()
    pair_id = secrets.token_hex(16)
    first = WebSocket(HBBR_WS_PORT, timeout)
    second = None
    try:
        first.send(relay_request(pair_id, licence))
        # 中继没有入队应答；让首端先进入等待表，避免两端同时 remove/insert。
        time.sleep(0.1)
        second = WebSocket(HBBR_WS_PORT, timeout)
        second.send(relay_request(pair_id, licence))
        forward = b"\x00migration-probe-forward\xff" + secrets.token_bytes(32)
        reverse = b"\xffmigration-probe-reverse\x00" + secrets.token_bytes(32)
        first.send(forward)
        require(second.receive() == forward, "hbbr forward payload mismatch")
        second.send(reverse)
        require(first.receive() == reverse, "hbbr reverse payload mismatch")
        print("PASS hbbr_ws_pair_and_bidirectional_relay bytes=%d" %
              (len(forward) + len(reverse)), flush=True)
    finally:
        first.close()
        if second is not None:
            second.close()


def isolated_namespace(args):
    require(args.isolated_copy, "explicit --isolated-copy is required")
    require(sys.platform.startswith("linux"), "probe must run inside Linux test network namespace")
    require({name for _, name in socket.if_nameindex()} == {"lo"},
            "network namespace has interfaces beyond lo; require Podman --network none")
    # 只检查隔离网络本身，不读取生产配置、数据库、密钥或令牌。
    with open("/proc/net/route", "r", encoding="ascii") as routes:
        for line in list(routes)[1:]:
            parts = line.split()
            require(not parts or parts[0] == "lo", "non-loopback network route detected")
    print("PASS isolation_loopback_only", flush=True)


def self_test():
    # 固定 protobuf 字节，避免只有编码/解码相互印证而漏掉字段号错误。
    golden = bytes.fromhex("32080a06313233343536")
    require(rendezvous(6, blob(1, "123456")) == golden, "RegisterPeer wire fixture mismatch")
    require(one(response_body(bytes.fromhex("820100"), 16), 1, 0, 0) == 0,
            "proto3 empty successful response fixture mismatch")
    online = rendezvous(23, blob(2, "123456") + blob(2, "654321"))
    require(online.hex() == "ba011012063132333435361206363534333231",
            "OnlineRequest wire fixture mismatch")
    expected = bytes.fromhex("818537fa213d7f9f4d5158")
    require(ws_frame(1, b"Hello", bytes.fromhex("37fa213d")) == expected,
            "WebSocket masked frame fixture mismatch")
    accept = base64.b64encode(hashlib.sha1(
        ("dGhlIHNhbXBsZSBub25jZQ==" + WS_GUID).encode("ascii")).digest())
    require(accept == b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "WebSocket handshake fixture mismatch")
    for invalid in (b"\x00", b"\x12\x05ab", b"\x08" + b"\xff" * 10):
        try:
            fields(invalid)
        except ProbeError:
            pass
        else:
            raise ProbeError("malformed protobuf fixture unexpectedly accepted")
    print("PASS stdlib_wire_fixtures cases=8 no_network=1 no_file_writes=1", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--isolated-copy", action="store_true",
                        help="确认这是 Podman network none 数据副本，模拟注册会写入副本")
    parser.add_argument("--require-relay-key-auth", action="store_true",
                        help="ENCRYPTED_ONLY=1 时额外验证错误 licence key 被拒绝")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="每次应答的超时秒数，范围 0.2 到 15，默认 5")
    parser.add_argument("--self-test", action="store_true",
                        help="只验证固定协议字节，不打开网络连接或写入文件")
    args = parser.parse_args()
    stage = "configuration"
    try:
        require(0.2 <= args.timeout <= 15.0, "timeout must be between 0.2 and 15 seconds")
        if args.self_test:
            self_test()
            return 0
        stage = "isolation"
        isolated_namespace(args)
        stage = "hbbs_udp_ws"
        peer_ids = probe_hbbs(args.timeout)
        print("STATS synthetic_ids=%s,%s" % peer_ids, flush=True)
        # 外部提供的公开 licence key 不出现在参数列表、日志或异常文本中。
        licence = os.environ.get("RUSTDESK_PROBE_RELAY_LICENCE_KEY", "").strip()
        stage = "hbbr_ws"
        probe_relay(args.timeout, licence, args.require_relay_key_auth)
        print("STATS nacl_tcp_handshake=not_tested desktop_session=not_tested "
              "database_persistence=requires_separate_check", flush=True)
        return 0
    except (ProbeError, OSError, UnicodeError) as error:
        # 异常只包含固定诊断或网络错误；不回显服务器报文、密钥和令牌。
        print("FAIL %s: %s" % (stage, error), file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
