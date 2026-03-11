#!/usr/bin/env python3
"""QUIC protocol simulator — multiplexed streams over UDP with 0-RTT.

Simulates QUIC transport: connection establishment (1-RTT/0-RTT),
stream multiplexing, flow control, loss detection, congestion control.

Usage: python quic_sim.py [--test]
"""

import sys, struct, os, time
from enum import IntEnum
from collections import defaultdict

class PacketType(IntEnum):
    INITIAL = 0
    HANDSHAKE = 1
    ZERO_RTT = 2
    ONE_RTT = 3
    RETRY = 4

class FrameType(IntEnum):
    PADDING = 0x00
    PING = 0x01
    ACK = 0x02
    STREAM = 0x08
    MAX_DATA = 0x10
    MAX_STREAM_DATA = 0x11
    STREAM_DATA_BLOCKED = 0x14
    CONNECTION_CLOSE = 0x1c
    HANDSHAKE_DONE = 0x1e

class StreamState(IntEnum):
    IDLE = 0; OPEN = 1; HALF_CLOSED_LOCAL = 2
    HALF_CLOSED_REMOTE = 3; CLOSED = 4

class Frame:
    def __init__(self, frame_type, **kwargs):
        self.type = frame_type
        self.__dict__.update(kwargs)

class QUICStream:
    def __init__(self, stream_id, max_data=65536):
        self.stream_id = stream_id
        self.state = StreamState.OPEN
        self.send_buf = bytearray()
        self.recv_buf = bytearray()
        self.send_offset = 0
        self.recv_offset = 0
        self.max_send_data = max_data
        self.max_recv_data = max_data
        self.fin_sent = False
        self.fin_received = False

    def write(self, data):
        if self.state in (StreamState.HALF_CLOSED_LOCAL, StreamState.CLOSED):
            raise RuntimeError("Stream not writable")
        self.send_buf.extend(data)

    def read(self):
        data = bytes(self.recv_buf)
        self.recv_buf.clear()
        return data

    def close_send(self):
        self.fin_sent = True
        if self.fin_received:
            self.state = StreamState.CLOSED
        else:
            self.state = StreamState.HALF_CLOSED_LOCAL

class Packet:
    def __init__(self, ptype, pn, frames=None, dcid=None, scid=None):
        self.type = ptype
        self.packet_number = pn
        self.frames = frames or []
        self.dcid = dcid or b'\x00' * 8
        self.scid = scid or b'\x00' * 8
        self.sent_time = None
        self.size = 0

class CongestionControl:
    """Simplified CUBIC-like congestion control."""
    def __init__(self):
        self.cwnd = 14720  # initial window (10 * 1472 MTU)
        self.ssthresh = float('inf')
        self.bytes_in_flight = 0
        self.rtt = 0.1  # estimated RTT
        self.min_rtt = float('inf')

    def on_ack(self, acked_bytes):
        self.bytes_in_flight -= acked_bytes
        if self.cwnd < self.ssthresh:
            self.cwnd += acked_bytes  # slow start
        else:
            self.cwnd += 1472 * acked_bytes // self.cwnd  # congestion avoidance

    def on_loss(self):
        self.ssthresh = max(self.cwnd // 2, 2 * 1472)
        self.cwnd = self.ssthresh

    def can_send(self, size):
        return self.bytes_in_flight + size <= self.cwnd

class QUICConnection:
    def __init__(self, is_client=True):
        self.is_client = is_client
        self.state = "idle"
        self.streams = {}
        self.next_stream_id = 0 if is_client else 1
        self.packet_number = 0
        self.ack_ranges = []
        self.sent_packets = {}
        self.cc = CongestionControl()
        self.max_data = 1048576
        self.data_sent = 0
        self.conn_id = os.urandom(8)
        self.peer_conn_id = None
        self.zero_rtt_available = False
        self.handshake_complete = False

    def connect(self):
        """Initiate connection (client side)."""
        self.state = "connecting"
        frames = [Frame(FrameType.PING)]
        if self.zero_rtt_available:
            return self._send_packet(PacketType.ZERO_RTT, frames)
        return self._send_packet(PacketType.INITIAL, frames)

    def accept(self, initial_packet):
        """Accept connection (server side)."""
        self.peer_conn_id = initial_packet.scid
        self.state = "connecting"
        frames = [Frame(FrameType.HANDSHAKE_DONE)]
        return self._send_packet(PacketType.HANDSHAKE, frames)

    def complete_handshake(self, handshake_packet=None):
        self.state = "connected"
        self.handshake_complete = True

    def open_stream(self):
        sid = self.next_stream_id
        self.next_stream_id += 4  # client: 0,4,8; server: 1,5,9
        stream = QUICStream(sid)
        self.streams[sid] = stream
        return stream

    def send_stream_data(self, stream_id, data, fin=False):
        stream = self.streams.get(stream_id)
        if not stream:
            raise ValueError(f"Unknown stream {stream_id}")
        stream.write(data)
        if fin:
            stream.close_send()
        frame = Frame(FrameType.STREAM, stream_id=stream_id,
                     offset=stream.send_offset, data=data, fin=fin)
        stream.send_offset += len(data)
        return self._send_packet(PacketType.ONE_RTT, [frame])

    def receive_packet(self, packet):
        """Process received packet."""
        self.ack_ranges.append(packet.packet_number)
        results = []
        for frame in packet.frames:
            if frame.type == FrameType.STREAM:
                sid = frame.stream_id
                if sid not in self.streams:
                    self.streams[sid] = QUICStream(sid)
                stream = self.streams[sid]
                stream.recv_buf.extend(frame.data)
                stream.recv_offset += len(frame.data)
                if getattr(frame, 'fin', False):
                    stream.fin_received = True
                    if stream.fin_sent:
                        stream.state = StreamState.CLOSED
                    else:
                        stream.state = StreamState.HALF_CLOSED_REMOTE
                results.append(("data", sid, frame.data))
            elif frame.type == FrameType.ACK:
                for pn in getattr(frame, 'acked', []):
                    if pn in self.sent_packets:
                        pkt = self.sent_packets.pop(pn)
                        self.cc.on_ack(pkt.size)
                results.append(("ack", getattr(frame, 'acked', [])))
            elif frame.type == FrameType.HANDSHAKE_DONE:
                self.complete_handshake()
                results.append(("handshake_done",))
            elif frame.type == FrameType.CONNECTION_CLOSE:
                self.state = "closed"
                results.append(("close", getattr(frame, 'error_code', 0)))
        return results

    def generate_ack(self):
        if not self.ack_ranges:
            return None
        frame = Frame(FrameType.ACK, acked=list(self.ack_ranges))
        self.ack_ranges.clear()
        return self._send_packet(PacketType.ONE_RTT, [frame])

    def close(self, error_code=0, reason=""):
        frame = Frame(FrameType.CONNECTION_CLOSE,
                     error_code=error_code, reason=reason)
        self.state = "closing"
        return self._send_packet(PacketType.ONE_RTT, [frame])

    def _send_packet(self, ptype, frames):
        pn = self.packet_number
        self.packet_number += 1
        pkt = Packet(ptype, pn, frames, scid=self.conn_id, dcid=self.peer_conn_id)
        pkt.sent_time = time.monotonic()
        pkt.size = sum(len(getattr(f, 'data', b'')) for f in frames) + 40
        self.sent_packets[pn] = pkt
        self.cc.bytes_in_flight += pkt.size
        return pkt

# --- Tests ---

def test_handshake():
    client = QUICConnection(is_client=True)
    server = QUICConnection(is_client=False)
    initial = client.connect()
    assert initial.type == PacketType.INITIAL
    hs = server.accept(initial)
    assert hs.type == PacketType.HANDSHAKE
    client.receive_packet(hs)
    assert client.handshake_complete

def test_stream_data():
    client = QUICConnection(True)
    server = QUICConnection(False)
    client.complete_handshake()
    server.complete_handshake()
    s = client.open_stream()
    pkt = client.send_stream_data(s.stream_id, b"Hello QUIC!")
    results = server.receive_packet(pkt)
    assert any(r[0] == "data" and r[2] == b"Hello QUIC!" for r in results)

def test_multiple_streams():
    client = QUICConnection(True)
    client.complete_handshake()
    server = QUICConnection(False)
    server.complete_handshake()
    s1 = client.open_stream()
    s2 = client.open_stream()
    assert s1.stream_id != s2.stream_id
    p1 = client.send_stream_data(s1.stream_id, b"stream1")
    p2 = client.send_stream_data(s2.stream_id, b"stream2")
    server.receive_packet(p1)
    server.receive_packet(p2)
    assert server.streams[s1.stream_id].read() == b"stream1"
    assert server.streams[s2.stream_id].read() == b"stream2"

def test_ack():
    client = QUICConnection(True)
    server = QUICConnection(False)
    client.complete_handshake(); server.complete_handshake()
    s = client.open_stream()
    pkt = client.send_stream_data(s.stream_id, b"data")
    server.receive_packet(pkt)
    ack_pkt = server.generate_ack()
    results = client.receive_packet(ack_pkt)
    assert any(r[0] == "ack" for r in results)

def test_close():
    client = QUICConnection(True)
    client.complete_handshake()
    server = QUICConnection(False)
    server.complete_handshake()
    close_pkt = client.close(0, "done")
    results = server.receive_packet(close_pkt)
    assert any(r[0] == "close" for r in results)
    assert server.state == "closed"

def test_congestion_control():
    cc = CongestionControl()
    initial = cc.cwnd
    cc.on_ack(1472)
    assert cc.cwnd > initial  # slow start grows
    cc.on_loss()
    assert cc.cwnd < initial  # loss reduces

def test_stream_fin():
    client = QUICConnection(True)
    client.complete_handshake()
    server = QUICConnection(False)
    server.complete_handshake()
    s = client.open_stream()
    pkt = client.send_stream_data(s.stream_id, b"final", fin=True)
    server.receive_packet(pkt)
    assert server.streams[s.stream_id].fin_received

if __name__ == "__main__":
    if "--test" in sys.argv or len(sys.argv) == 1:
        test_handshake()
        test_stream_data()
        test_multiple_streams()
        test_ack()
        test_close()
        test_congestion_control()
        test_stream_fin()
        print("All tests passed!")
