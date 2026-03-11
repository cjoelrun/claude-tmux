"""Minimal HTTP CONNECT proxy that forwards through a SOCKS5 proxy.

Uses raw sockets to avoid buffered I/O issues with TLS relay."""
import socket, select, struct, sys, threading

SOCKS_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 1080
LISTEN_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8118


def socks5_connect(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", SOCKS_PORT))
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        s.close()
        raise Exception("SOCKS5 auth failed")
    host_bytes = host.encode()
    port_bytes = struct.pack("!H", port)
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + port_bytes)
    resp = s.recv(10)
    if resp[1] != 0:
        s.close()
        raise Exception(f"SOCKS5 connect failed: {resp[1]}")
    return s


def relay(a, b):
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 120)
            if not r:
                break
            for sock in r:
                data = sock.recv(65536)
                if not data:
                    return
                (b if sock is a else a).sendall(data)
    except Exception:
        pass
    finally:
        a.close()
        b.close()


def handle_client(client):
    try:
        # Read CONNECT request using raw recv (no buffered IO)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = client.recv(4096)
            if not chunk:
                client.close()
                return
            data += chunk

        header_end = data.index(b"\r\n\r\n") + 4
        first_line = data[: data.index(b"\r\n")].decode()
        extra = data[header_end:]  # TLS data sent immediately after headers

        parts = first_line.split()
        if len(parts) < 2 or parts[0] != "CONNECT":
            client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            client.close()
            return

        host, _, port_str = parts[1].rpartition(":")
        port = int(port_str) if port_str else 443

        sys.stderr.write(f"CONNECT {host}:{port}\n")
        sys.stderr.flush()

        try:
            remote = socks5_connect(host, port)
        except Exception as e:
            sys.stderr.write(f"FAILED {host}:{port}: {e}\n")
            sys.stderr.flush()
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            client.close()
            return

        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Forward any data that arrived with the CONNECT request
        if extra:
            remote.sendall(extra)

        relay(client, remote)
    except Exception as e:
        sys.stderr.write(f"ERROR: {e}\n")
        sys.stderr.flush()
        try:
            client.close()
        except Exception:
            pass


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", LISTEN_PORT))
    server.listen(128)
    sys.stderr.write(
        f"HTTP CONNECT proxy on 127.0.0.1:{LISTEN_PORT} -> SOCKS5 127.0.0.1:{SOCKS_PORT}\n"
    )
    sys.stderr.flush()

    while True:
        client, _ = server.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
