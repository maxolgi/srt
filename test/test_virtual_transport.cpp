/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2026 maxolgi.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#include "gtest/gtest.h"
#include "test_env.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <sys/socket.h>

#include "srt.h"
#include "srttransport.h"

#include "core.h" // CHandShake, CPacket: the wire-level handshake pins

namespace
{

// Routes the datagrams sent by one endpoint's SRTTransportQueue into the
// peer endpoint's queue, reporting a fixed source address - a wire between
// two sockets. Built on the srttransport helper the way an application
// owning a datagram medium would use it: the queue wired into
// srt_bind_virtual gathers an outgoing datagram and hands it to the plain
// send callback below, which pushes it into the peer queue as if the
// datagram arrived from the wire's fixed source label.
struct Wire
{
    // The queue of the peer endpoint: everything sent through this wire is
    // pushed here. NULL leaves the wire unterminated - a datagram sent
    // through it is dropped, like on a wire to nowhere.
    srt::SRTTransportQueue* peer = NULL;
    sockaddr_storage         source_addr;
    socklen_t                source_len = 0;
    // The socket whose outgoing datagrams pass through this wire; held for
    // bookkeeping only, the send path never uses it.
    SRTSOCKET sock = SRT_INVALID_SOCK;
    // When not NULL, datagrams carrying this byte sequence in the payload
    // are swallowed to emulate a loss. Retransmissions carry the same
    // payload, so every copy of the packet disappears on the wire.
    const char* swallow_tag = NULL;
    // Counts the send callbacks fired through this wire (called from SRT
    // threads).
    std::atomic<long long> send_count{ 0 };
    // The first datagram ever sent through this wire, captured once for
    // the wire-level handshake pins (see ExpectFirstHandshake). Guarded by
    // its own mutex because the send callback can fire on SRT threads.
    std::vector<char> first_datagram;
    bool              first_datagram_captured = false;
    std::mutex        first_datagram_lock;
};

int WireSend(void* opaq, const char* data, int len, const struct sockaddr* /*dst*/, int /*dstlen*/)
{
    Wire* w = (Wire*)opaq;
    ++w->send_count;
    // One-shot capture of the opening flight, ahead of the swallow check
    // so that the first datagram is recorded even under loss emulation
    // (see ExpectFirstHandshake).
    {
        std::lock_guard<std::mutex> lock(w->first_datagram_lock);
        if (!w->first_datagram_captured)
        {
            w->first_datagram.assign(data, data + len);
            w->first_datagram_captured = true;
        }
    }
    if (w->swallow_tag &&
        std::search(data, data + len, w->swallow_tag, w->swallow_tag + strlen(w->swallow_tag)) != data + len)
        return len;

    if (!w->peer)
        return -1; // no peer attached: the datagram is lost on the wire

    if (w->peer->push(data, (size_t)len, (const struct sockaddr*)&w->source_addr, w->source_len) == -1)
        return -1;

    return len;
}

sockaddr_in FillV4(const char* ip, uint16_t port)
{
    sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(port);
    sa.sin_addr.s_addr = inet_addr(ip);
    return sa;
}

void FillWireSource(Wire& w, const sockaddr_in& sa)
{
    memset(&w.source_addr, 0, sizeof w.source_addr);
    memcpy(&w.source_addr, &sa, sizeof sa);
    w.source_len = sizeof sa;
}

// Pins the handshake request type of the very first datagram sent through
// the wire - the opening flight of the socket behind it. On the wire the
// datagram is the fixed 16-byte SRT packet header (CPacket::HDR_SIZE)
// followed by the serialized CHandShake - its fields in declaration order
// (handshake.h), in network byte order, because the send path runs
// CPacket::toNetworkByteOrder over the header and the whole control
// payload. The pin reverses that exactly the way the receive path does -
// CPacket::toHostByteOrder is NtoHLA over the payload words - and then
// decodes with CHandShake::load_from, the library's own reader of that
// layout. When decoded is not NULL, it receives the parsed handshake for
// the caller's further pins.
void ExpectFirstHandshake(Wire& w, srt::UDTRequestType expect_req, srt::CHandShake* decoded = NULL)
{
    std::vector<char> first;
    {
        std::lock_guard<std::mutex> lock(w.first_datagram_lock);
        first = w.first_datagram;
    }

    ASSERT_FALSE(first.empty()) << "no datagram was ever sent through the wire";
    ASSERT_GE(first.size(), srt::CPacket::HDR_SIZE + srt::CHandShake::m_iContentSize)
        << "the first datagram is too short to carry the SRT header plus a handshake";

    const size_t          payload_bytes = first.size() - srt::CPacket::HDR_SIZE;
    std::vector<uint32_t> payload(payload_bytes / 4); // whole 32-bit words of the handshake
    memcpy(payload.data(), first.data() + srt::CPacket::HDR_SIZE, payload.size() * sizeof(uint32_t));
    srt::NtoHLA(payload.data(), payload.data(), payload.size());

    srt::CHandShake hs;
    ASSERT_EQ(hs.load_from((const char*)payload.data(), payload.size() * sizeof(uint32_t)), 0)
        << "the first datagram payload does not decode as a handshake";
    ASSERT_EQ(hs.m_iReqType, expect_req);
    if (decoded)
        *decoded = hs;
}

// A bounded read-readiness check through epoll, so that a handshake or a
// delivery that never happens fails the test instead of hanging it in a
// blocking call.
bool WaitReadable(SRTSOCKET sock, int timeout_ms)
{
    const int pollid = srt_epoll_create();
    if (pollid == SRT_ERROR)
        return false;
    const int events = SRT_EPOLL_IN;
    if (srt_epoll_add_usock(pollid, sock, &events) == SRT_ERROR)
    {
        srt_epoll_release(pollid);
        return false;
    }

    SRT_EPOLL_EVENT ready[1];
    const int       nready = srt_epoll_uwait(pollid, ready, 1, timeout_ms);
    srt_epoll_release(pollid);
    return nready == 1 && (ready[0].events & SRT_EPOLL_IN) != 0;
}

// Pins the error code of the last failed SRT call, with its message in
// the failure log.
void ExpectLastErrno(int expected)
{
    EXPECT_EQ(srt_getlasterror(NULL), expected) << srt_getlasterror_str();
}

// The label contract of srt_bind_virtual: srt_getsockname() must report
// exactly the address the socket was bound with - family, port, address -
// because the label is the socket's identity on the virtual medium.
void ExpectSockName(SRTSOCKET sock, const sockaddr_in& expect)
{
    sockaddr_in self;
    memset(&self, 0, sizeof self);
    int self_len = (int)sizeof self;
    ASSERT_EQ(srt_getsockname(sock, (sockaddr*)&self, &self_len), SRT_STATUS_OK) << srt_getlasterror_str();
    EXPECT_EQ(self_len, (int)sizeof self);
    EXPECT_EQ(self.sin_family, expect.sin_family);
    EXPECT_EQ(self.sin_port, expect.sin_port);
    EXPECT_EQ(self.sin_addr.s_addr, expect.sin_addr.s_addr);
}

} // namespace

class TestVirtualTransport : public srt::Test
{
protected:
    void setup() override {}

    void teardown() override
    {
        if (m_caller_sock != SRT_INVALID_SOCK)
            srt_close(m_caller_sock);
        if (m_accepted_sock != SRT_INVALID_SOCK)
            srt_close(m_accepted_sock);
        if (m_listener_sock != SRT_INVALID_SOCK)
            srt_close(m_listener_sock);
    }

    // Pairs the wires for one caller/listener pair: what the caller sends
    // is pushed into the listener's queue as if received from the caller
    // label, and what the listener (or its accepted socket) sends is
    // pushed into the caller's queue as if received from the listener
    // label.
    void PairWires(const sockaddr_in& caller_label, const sockaddr_in& listener_label)
    {
        m_caller_wire.peer = &m_listener_queue;
        FillWireSource(m_caller_wire, caller_label);
        m_listener_wire.peer = &m_caller_queue;
        FillWireSource(m_listener_wire, listener_label);
    }

    TestVirtualTransport()
        : m_caller_queue(&WireSend, &m_caller_wire)
        , m_listener_queue(&WireSend, &m_listener_wire)
    {
    }

    SRTSOCKET m_caller_sock   = SRT_INVALID_SOCK;
    SRTSOCKET m_accepted_sock = SRT_INVALID_SOCK;
    SRTSOCKET m_listener_sock = SRT_INVALID_SOCK;

    // The wires and queues must live as long as the sockets: srt_close()
    // in teardown() (and in the test bodies) sends the shutdown through
    // the wire, which calls WireSend - after the test body and its locals
    // are gone.
    Wire m_caller_wire;
    Wire m_listener_wire;
    srt::SRTTransportQueue m_caller_queue;
    srt::SRTTransportQueue m_listener_queue;
};

// A stock caller-listener handshake (induction first) and payload round
// trips in both directions, carried end to end by the virtual transport
// seam: the listener is bound with srt_bind_virtual and listens, the
// caller is bound with srt_bind_virtual and connects, and everything both
// sides exchange passes through the wires between the two queues.
TEST_F(TestVirtualTransport, BindVirtualConnectListenSendReceive)
{
    // The addresses never reach the network; they only identify the
    // endpoints for the SRT dispatching machinery. They are unique to
    // this test - the RTT cache and the virtual demux key off them.
    const sockaddr_in listener_addr = FillV4("10.210.0.2", 5555);
    const sockaddr_in caller_addr   = FillV4("10.210.0.1", 5556);

    PairWires(caller_addr, listener_addr);

    // Listener side: the virtual bind creates a dedicated multiplexer
    // with a CChannelVirtual channel, then listen.
    m_listener_sock = srt_create_socket();
    ASSERT_NE(m_listener_sock, SRT_INVALID_SOCK);
    m_listener_wire.sock = m_listener_sock;
    {
        const SRT_VirtualTransportConfig cfg = m_listener_queue.getConfig();
        ASSERT_EQ(srt_bind_virtual(m_listener_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr, &cfg),
                  SRT_STATUS_OK)
            << srt_getlasterror_str();
    }
    ExpectSockName(m_listener_sock, listener_addr);
    ASSERT_NE(srt_listen(m_listener_sock, 4), SRT_ERROR) << srt_getlasterror_str();

    // Caller side: virtual bind, then connect to the listener's label.
    m_caller_sock = srt_create_socket();
    ASSERT_NE(m_caller_sock, SRT_INVALID_SOCK);
    m_caller_wire.sock = m_caller_sock;
    {
        const SRT_VirtualTransportConfig cfg = m_caller_queue.getConfig();
        ASSERT_EQ(srt_bind_virtual(m_caller_sock, (const sockaddr*)&caller_addr, (int)sizeof caller_addr, &cfg),
                  SRT_STATUS_OK)
            << srt_getlasterror_str();
    }
    ExpectSockName(m_caller_sock, caller_addr);

    ASSERT_NE(srt_connect(m_caller_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr), SRT_ERROR)
        << srt_getlasterror_str();

    // Bounded wait for the queued connection: a handshake that never
    // completes must fail the test, not hang it in srt_accept.
    ASSERT_TRUE(WaitReadable(m_listener_sock, 15000)) << "no connection was ever queued on the listener";

    sockaddr_in accept_addr;
    int         accept_len = (int)sizeof accept_addr;
    m_accepted_sock        = srt_accept(m_listener_sock, (sockaddr*)&accept_addr, &accept_len);
    ASSERT_NE(m_accepted_sock, SRT_INVALID_SOCK) << srt_getlasterror_str();

    // The peer of the accepted socket is the source address the caller's
    // wire reports for its datagrams.
    EXPECT_EQ(accept_addr.sin_family, AF_INET);
    EXPECT_EQ(accept_addr.sin_addr.s_addr, caller_addr.sin_addr.s_addr);
    EXPECT_EQ(accept_addr.sin_port, caller_addr.sin_port);

    // The accepted socket shares the listener's multiplexer, so it reports
    // the listener's label.
    ExpectSockName(m_accepted_sock, listener_addr);

    // The wire-level pin on the caller's opening flight: with the stock
    // handshake (no skip_induction in the config), the first datagram is
    // the Induction handshake.
    ExpectFirstHandshake(m_caller_wire, srt::URQ_INDUCTION);

    // One payload message from the caller to the accepted socket. Use
    // epoll to also check that read-readiness signaling works for virtual
    // sockets.
    const char* payload     = "virtual transport seam";
    const int   payload_len = (int)strlen(payload);
    ASSERT_EQ(srt_sendmsg(m_caller_sock, payload, payload_len, SRT_MSGTTL_INF, false), payload_len)
        << srt_getlasterror_str();

    const int pollid = srt_epoll_create();
    ASSERT_NE(pollid, SRT_ERROR);
    const int events = SRT_EPOLL_IN;
    ASSERT_NE(srt_epoll_add_usock(pollid, m_accepted_sock, &events), SRT_ERROR);

    SRT_EPOLL_EVENT ready[1];
    const int       nready = srt_epoll_uwait(pollid, ready, 1, 5000);
    EXPECT_EQ(nready, 1);
    if (nready == 1)
    {
        EXPECT_EQ(ready[0].fd, m_accepted_sock);
        EXPECT_NE(ready[0].events & SRT_EPOLL_IN, 0);
    }
    srt_epoll_release(pollid);

    char      buf[1456];
    const int recv_len = srt_recvmsg(m_accepted_sock, buf, (int)sizeof buf);
    ASSERT_GT(recv_len, 0) << srt_getlasterror_str();
    EXPECT_EQ(recv_len, payload_len);
    EXPECT_EQ(memcmp(buf, payload, payload_len), 0);

    // The reverse direction: the accepted socket back to the caller.
    ASSERT_EQ(srt_sendmsg(m_accepted_sock, payload, payload_len, SRT_MSGTTL_INF, false), payload_len)
        << srt_getlasterror_str();
    ASSERT_TRUE(WaitReadable(m_caller_sock, 5000)) << "the caller never became read-ready";
    ASSERT_GT(srt_recvmsg(m_caller_sock, buf, (int)sizeof buf), 0) << srt_getlasterror_str();
    EXPECT_EQ(memcmp(buf, payload, payload_len), 0);

    // Clean close - the shutdown flights go through the wires too.
    EXPECT_EQ(srt_close(m_accepted_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_accepted_sock = SRT_INVALID_SOCK;
    EXPECT_EQ(srt_close(m_caller_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_caller_sock = SRT_INVALID_SOCK;
    EXPECT_EQ(srt_close(m_listener_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_listener_sock = SRT_INVALID_SOCK;
}

// The config gate of srt_bind_virtual: the whole transport must be usable
// as given, because there are no virtual-transport socket options to fix
// anything up later. A NULL config, a missing callback, an out-of-range
// initial_rtt_ms and a skip_induction other than 0/1 are all rejected
// with SRT_EINVPARAM, as is a call on an invalid or closed socket or with
// a namelen too small for the address family. The boundary values of
// initial_rtt_ms (0 and 30000) are accepted, and every refusal leaves the
// socket untouched in the INIT state.
TEST_F(TestVirtualTransport, BindVirtualBadConfigRejected)
{
    // Unique to this test, like the labels of the other tests are to
    // theirs.
    const sockaddr_in self_addr = FillV4("10.211.0.2", 5555);

    m_listener_sock = srt_create_socket();
    ASSERT_NE(m_listener_sock, SRT_INVALID_SOCK);

    // The reference config, valid as given.
    const SRT_VirtualTransportConfig good = m_listener_queue.getConfig();

    // A NULL config.
    EXPECT_EQ(srt_bind_virtual(m_listener_sock, (const sockaddr*)&self_addr, (int)sizeof self_addr, NULL), SRT_ERROR);
    ExpectLastErrno(SRT_EINVPARAM);

    // One missing callback each: send, waitread, deliver.
    {
        SRT_VirtualTransportConfig cfg = good;
        cfg.send = NULL;
        EXPECT_EQ(srt_bind_virtual(m_listener_sock, (const sockaddr*)&self_addr, (int)sizeof self_addr, &cfg),
                  SRT_ERROR)
            << "a NULL send callback was not rejected";
        ExpectLastErrno(SRT_EINVPARAM);
    }
    {
        SRT_VirtualTransportConfig cfg = good;
        cfg.waitread = NULL;
        EXPECT_EQ(srt_bind_virtual(m_listener_sock, (const sockaddr*)&self_addr, (int)sizeof self_addr, &cfg),
                  SRT_ERROR)
            << "a NULL waitread callback was not rejected";
        ExpectLastErrno(SRT_EINVPARAM);
    }
    {
        SRT_VirtualTransportConfig cfg = good;
        cfg.deliver = NULL;
        EXPECT_EQ(srt_bind_virtual(m_listener_sock, (const sockaddr*)&self_addr, (int)sizeof self_addr, &cfg),
                  SRT_ERROR)
            << "a NULL deliver callback was not rejected";
        ExpectLastErrno(SRT_EINVPARAM);
    }

    // initial_rtt_ms outside the 0..30000 range.
    {
        SRT_VirtualTransportConfig cfg = good;
        cfg.initial_rtt_ms = -1;
        EXPECT_EQ(srt_bind_virtual(m_listener_sock, (const sockaddr*)&self_addr, (int)sizeof self_addr, &cfg),
                  SRT_ERROR)
            << "initial_rtt_ms = -1 was not rejected";
        ExpectLastErrno(SRT_EINVPARAM);
    }
    {
        SRT_VirtualTransportConfig cfg = good;
        cfg.initial_rtt_ms = 30001;
        EXPECT_EQ(srt_bind_virtual(m_listener_sock, (const sockaddr*)&self_addr, (int)sizeof self_addr, &cfg),
                  SRT_ERROR)
            << "initial_rtt_ms = 30001 was not rejected";
        ExpectLastErrno(SRT_EINVPARAM);
    }

    // skip_induction other than 0/1.
    {
        SRT_VirtualTransportConfig cfg = good;
        cfg.skip_induction = 2;
        EXPECT_EQ(srt_bind_virtual(m_listener_sock, (const sockaddr*)&self_addr, (int)sizeof self_addr, &cfg),
                  SRT_ERROR)
            << "skip_induction = 2 was not rejected";
        ExpectLastErrno(SRT_EINVPARAM);
    }

    // A namelen too small for the family, and a family no socket can be
    // bound with: in both cases there is no address to bind to.
    {
        SRT_VirtualTransportConfig cfg = good;
        EXPECT_EQ(
            srt_bind_virtual(m_listener_sock, (const sockaddr*)&self_addr, (int)sizeof self_addr - 1, &cfg), SRT_ERROR)
            << "a namelen too small for sockaddr_in was not rejected";
        ExpectLastErrno(SRT_EINVPARAM);

        sockaddr bad_family;
        memset(&bad_family, 0, sizeof bad_family);
        bad_family.sa_family = AF_UNIX;
        EXPECT_EQ(srt_bind_virtual(m_listener_sock, &bad_family, (int)sizeof bad_family, &cfg), SRT_ERROR)
            << "an unsupported address family was not rejected";
        ExpectLastErrno(SRT_EINVPARAM);
    }

    // No refusal above may have bound the socket.
    EXPECT_EQ(srt_getsockstate(m_listener_sock), SRTS_INIT);

    // The boundary values of initial_rtt_ms are accepted (each on its own
    // fresh socket - a socket can be bound only once).
    {
        const SRT_VirtualTransportConfig cfg0  = m_listener_queue.getConfig(0, 0);
        const sockaddr_in                addr0 = FillV4("10.211.0.3", 5555);
        m_caller_sock                      = srt_create_socket();
        ASSERT_NE(m_caller_sock, SRT_INVALID_SOCK);
        ASSERT_EQ(srt_bind_virtual(m_caller_sock, (const sockaddr*)&addr0, (int)sizeof addr0, &cfg0), SRT_STATUS_OK)
            << srt_getlasterror_str();
        EXPECT_EQ(srt_getsockstate(m_caller_sock), SRTS_OPENED);
        EXPECT_EQ(srt_close(m_caller_sock), SRT_STATUS_OK) << srt_getlasterror_str();
        m_caller_sock = SRT_INVALID_SOCK;
    }
    {
        const SRT_VirtualTransportConfig cfg_max = m_listener_queue.getConfig(30000, 1);
        const sockaddr_in                addr9   = FillV4("10.211.0.4", 5555);
        m_accepted_sock                    = srt_create_socket();
        ASSERT_NE(m_accepted_sock, SRT_INVALID_SOCK);
        ASSERT_EQ(
            srt_bind_virtual(m_accepted_sock, (const sockaddr*)&addr9, (int)sizeof addr9, &cfg_max), SRT_STATUS_OK)
            << srt_getlasterror_str();
        EXPECT_EQ(srt_getsockstate(m_accepted_sock), SRTS_OPENED);
        EXPECT_EQ(srt_close(m_accepted_sock), SRT_STATUS_OK) << srt_getlasterror_str();
        m_accepted_sock = SRT_INVALID_SOCK;
    }

    // An invalid socket, and a socket that was already closed.
    EXPECT_EQ(srt_bind_virtual(SRT_INVALID_SOCK, (const sockaddr*)&self_addr, (int)sizeof self_addr, &good),
              SRT_ERROR);
    ExpectLastErrno(SRT_EINVPARAM);
    {
        SRTSOCKET closed_sock = srt_create_socket();
        ASSERT_NE(closed_sock, SRT_INVALID_SOCK);
        ASSERT_EQ(srt_close(closed_sock), SRT_STATUS_OK) << srt_getlasterror_str();
        EXPECT_EQ(srt_bind_virtual(closed_sock, (const sockaddr*)&self_addr, (int)sizeof self_addr, &good), SRT_ERROR)
            << "a bind on a closed socket was not rejected";
        ExpectLastErrno(SRT_EINVPARAM);
    }

    // The refused socket remains untouched, usable and closable.
    EXPECT_EQ(srt_getsockstate(m_listener_sock), SRTS_INIT);
    EXPECT_EQ(srt_close(m_listener_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_listener_sock = SRT_INVALID_SOCK;
}

// The binding state machine around srt_bind_virtual: a socket can be
// bound only once, exactly as with srt_bind. A second srt_bind_virtual,
// an srt_bind after a virtual bind and a virtual bind after listen are
// all rejected with SRT_EINVOP, and a rendezvous-preset socket is refused
// up front with SRT_ERDVNOSERV (rendezvous has no listener that could
// complete the handshake over the virtual medium). Every rejection leaves
// the socket usable and closable - no leaked binding state.
TEST_F(TestVirtualTransport, BindVirtualDoubleBindRejected)
{
    const sockaddr_in listener_addr = FillV4("10.212.0.2", 5555);
    const sockaddr_in caller_addr   = FillV4("10.212.0.3", 5555);
    const sockaddr_in rdv_addr      = FillV4("10.212.0.4", 5555);

    // A virtually bound listener...
    m_listener_sock = srt_create_socket();
    ASSERT_NE(m_listener_sock, SRT_INVALID_SOCK);
    m_listener_wire.sock = m_listener_sock;
    const SRT_VirtualTransportConfig cfg = m_listener_queue.getConfig();
    ASSERT_EQ(srt_bind_virtual(m_listener_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr, &cfg),
              SRT_STATUS_OK)
        << srt_getlasterror_str();

    // ...takes no second virtual binding.
    EXPECT_EQ(srt_bind_virtual(m_listener_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr, &cfg),
              SRT_ERROR)
        << "a second srt_bind_virtual was not rejected";
    ExpectLastErrno(SRT_EINVOP);

    // ...and no binding over to an OS UDP socket either.
    EXPECT_EQ(srt_bind(m_listener_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr), SRT_ERROR)
        << "an srt_bind after srt_bind_virtual was not rejected";
    ExpectLastErrno(SRT_EINVOP);

    // The refusals leave the socket usable: it still enters the listening
    // state.
    ASSERT_NE(srt_listen(m_listener_sock, 4), SRT_ERROR) << srt_getlasterror_str();

    // A virtual bind after listen is rejected as well.
    m_caller_sock = srt_create_socket();
    ASSERT_NE(m_caller_sock, SRT_INVALID_SOCK);
    m_caller_wire.sock = m_caller_sock;
    const SRT_VirtualTransportConfig caller_cfg = m_caller_queue.getConfig();
    ASSERT_EQ(srt_bind_virtual(m_caller_sock, (const sockaddr*)&caller_addr, (int)sizeof caller_addr, &caller_cfg),
              SRT_STATUS_OK)
        << srt_getlasterror_str();
    ASSERT_NE(srt_listen(m_caller_sock, 4), SRT_ERROR) << srt_getlasterror_str();
    EXPECT_EQ(srt_bind_virtual(m_caller_sock, (const sockaddr*)&caller_addr, (int)sizeof caller_addr, &caller_cfg),
              SRT_ERROR)
        << "an srt_bind_virtual after listen was not rejected";
    ExpectLastErrno(SRT_EINVOP);

    // A rendezvous-preset socket is refused up front.
    m_accepted_sock = srt_create_socket(); // reused here as the rendezvous socket
    ASSERT_NE(m_accepted_sock, SRT_INVALID_SOCK);
    const int yes = 1;
    ASSERT_NE(srt_setsockopt(m_accepted_sock, 0, SRTO_RENDEZVOUS, &yes, sizeof yes), SRT_ERROR)
        << srt_getlasterror_str();
    EXPECT_EQ(srt_bind_virtual(m_accepted_sock, (const sockaddr*)&rdv_addr, (int)sizeof rdv_addr, &cfg), SRT_ERROR)
        << "a rendezvous-preset socket was not rejected";
    ExpectLastErrno(SRT_ERDVNOSERV);
    EXPECT_EQ(srt_getsockstate(m_accepted_sock), SRTS_INIT);

    // All sockets remain closable - the rejections leaked no state.
    EXPECT_EQ(srt_close(m_accepted_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_accepted_sock = SRT_INVALID_SOCK;
    EXPECT_EQ(srt_close(m_caller_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_caller_sock = SRT_INVALID_SOCK;
    EXPECT_EQ(srt_close(m_listener_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_listener_sock = SRT_INVALID_SOCK;
}

// The same wire as in BindVirtualConnectListenSendReceive, but with
// skip_induction=1 in the configs of BOTH endpoints: the caller's opening
// flight is the CONCLUSION handshake - HS_VERSION_SRT1, cookie 0, carrying
// the HSv5 extension blocks - and the listener's multiplexer accepts it
// without the Induction/cookie exchange. The wire-level pins make the
// option's defining behavior falsifiable: a virtual listener would complete
// a session against a stock caller too (it answers Inductions), so the
// conclusion-first shape is only observable in the caller's very first
// datagram. Proves the skip-induction path leaves the connected state and
// the bidirectional data flow intact.
TEST_F(TestVirtualTransport, BindVirtualSkipInductionRoundTrip)
{
    const sockaddr_in listener_addr = FillV4("10.215.0.2", 5555);
    const sockaddr_in caller_addr   = FillV4("10.215.0.1", 5556);

    PairWires(caller_addr, listener_addr);

    // Listener side: the multiplexer config carries skip_induction, so its
    // channel reports it and processConnectRequest bypasses the cookie
    // check for a conclusion-first request.
    m_listener_sock = srt_create_socket();
    ASSERT_NE(m_listener_sock, SRT_INVALID_SOCK);
    m_listener_wire.sock = m_listener_sock;
    {
        const SRT_VirtualTransportConfig cfg = m_listener_queue.getConfig(0, 1);
        ASSERT_EQ(srt_bind_virtual(m_listener_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr, &cfg),
                  SRT_STATUS_OK)
            << srt_getlasterror_str();
    }
    ASSERT_NE(srt_listen(m_listener_sock, 4), SRT_ERROR) << srt_getlasterror_str();

    // Caller side: skip_induction in its multiplexer config turns the first
    // handshake into the CONCLUSION.
    m_caller_sock = srt_create_socket();
    ASSERT_NE(m_caller_sock, SRT_INVALID_SOCK);
    m_caller_wire.sock = m_caller_sock;
    {
        const SRT_VirtualTransportConfig cfg = m_caller_queue.getConfig(0, 1);
        ASSERT_EQ(srt_bind_virtual(m_caller_sock, (const sockaddr*)&caller_addr, (int)sizeof caller_addr, &cfg),
                  SRT_STATUS_OK)
            << srt_getlasterror_str();
    }

    ASSERT_NE(srt_connect(m_caller_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr), SRT_ERROR)
        << srt_getlasterror_str();

    ASSERT_TRUE(WaitReadable(m_listener_sock, 15000)) << "no connection was ever queued on the listener";

    sockaddr_in accept_addr;
    int         accept_len = (int)sizeof accept_addr;
    m_accepted_sock        = srt_accept(m_listener_sock, (sockaddr*)&accept_addr, &accept_len);
    ASSERT_NE(m_accepted_sock, SRT_INVALID_SOCK) << srt_getlasterror_str();
    EXPECT_EQ(accept_addr.sin_addr.s_addr, caller_addr.sin_addr.s_addr);
    EXPECT_EQ(accept_addr.sin_port, caller_addr.sin_port);

    // The wire-level pins on the caller's opening flight: a CONCLUSION of
    // HS_VERSION_SRT1 with no cookie - there was no Induction response to
    // take a cookie from. (The version constant is taken by value:
    // CUDT::HS_VERSION_SRT1 has no out-of-class definition to ODR-use.)
    const int       hs_version_srt1 = srt::CUDT::HS_VERSION_SRT1;
    srt::CHandShake first_flight;
    ExpectFirstHandshake(m_caller_wire, srt::URQ_CONCLUSION, &first_flight);
    ASSERT_EQ(first_flight.m_iVersion, hs_version_srt1);
    ASSERT_EQ(first_flight.m_iCookie, 0);

    // The first flight must also carry the HSv5 extension blocks (HSREQ is
    // serialized after the bare handshake structure), which a stock
    // Induction never has.
    {
        std::vector<char> first;
        {
            std::lock_guard<std::mutex> lock(m_caller_wire.first_datagram_lock);
            first = m_caller_wire.first_datagram;
        }
        EXPECT_GT(first.size(), srt::CPacket::HDR_SIZE + srt::CHandShake::m_iContentSize)
            << "the conclusion-first flight carries no handshake extension blocks";
    }

    EXPECT_EQ(srt_getsockstate(m_caller_sock), SRTS_CONNECTED);
    EXPECT_EQ(srt_getsockstate(m_accepted_sock), SRTS_CONNECTED);

    // One payload message each way over the conclusion-first connection.
    const char* payload     = "skip-induction round trip";
    const int   payload_len = (int)strlen(payload);
    char        buf[1456];

    ASSERT_EQ(srt_sendmsg(m_caller_sock, payload, payload_len, SRT_MSGTTL_INF, false), payload_len)
        << srt_getlasterror_str();
    ASSERT_TRUE(WaitReadable(m_accepted_sock, 5000)) << "the accepted socket never became read-ready";
    ASSERT_EQ(srt_recvmsg(m_accepted_sock, buf, (int)sizeof buf), payload_len) << srt_getlasterror_str();
    EXPECT_EQ(memcmp(buf, payload, payload_len), 0);

    ASSERT_EQ(srt_sendmsg(m_accepted_sock, payload, payload_len, SRT_MSGTTL_INF, false), payload_len)
        << srt_getlasterror_str();
    ASSERT_TRUE(WaitReadable(m_caller_sock, 5000)) << "the caller never became read-ready";
    ASSERT_EQ(srt_recvmsg(m_caller_sock, buf, (int)sizeof buf), payload_len) << srt_getlasterror_str();
    EXPECT_EQ(memcmp(buf, payload, payload_len), 0);

    // Clean close - the shutdown flights go through the wires too.
    EXPECT_EQ(srt_close(m_accepted_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_accepted_sock = SRT_INVALID_SOCK;
    EXPECT_EQ(srt_close(m_caller_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_caller_sock = SRT_INVALID_SOCK;
    EXPECT_EQ(srt_close(m_listener_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_listener_sock = SRT_INVALID_SOCK;
}

// The per-multiplexer gate of skip_induction: the cookie bypass belongs to
// the listener's OWN bind configuration, not to the medium. A listener
// bound without skip_induction must keep the stock cookie validation even
// against a conclusion-first request that arrived over a virtual
// transport: a wrong cookie (0, as a skip caller sends) is silently
// ignored, no connection may ever be queued on it, and the listener stays
// in the listening state. The caller observes the refusal through its
// bounded connect timeout. This pins that skip_induction is a contract
// between the two endpoints' configs, not a global property of the
// virtual transport seam.
TEST_F(TestVirtualTransport, VirtualListenerWithoutSkipStillRequiresCookie)
{
    const sockaddr_in listener_addr = FillV4("10.216.0.2", 5555);
    const sockaddr_in caller_addr   = FillV4("10.216.0.1", 5556);

    PairWires(caller_addr, listener_addr);

    // Listener side: the stock config - no skip_induction.
    m_listener_sock = srt_create_socket();
    ASSERT_NE(m_listener_sock, SRT_INVALID_SOCK);
    m_listener_wire.sock = m_listener_sock;
    {
        const SRT_VirtualTransportConfig cfg = m_listener_queue.getConfig();
        ASSERT_EQ(srt_bind_virtual(m_listener_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr, &cfg),
                  SRT_STATUS_OK)
            << srt_getlasterror_str();
    }
    ASSERT_NE(srt_listen(m_listener_sock, 4), SRT_ERROR) << srt_getlasterror_str();

    // Caller side: skip_induction, so its opening flight is a cookie-0
    // CONCLUSION. The connect timeout bounds the refusal: the listener
    // ignores every retransmission of the wrong-cookie request, so the
    // caller can only run out of its connect timeout.
    m_caller_sock = srt_create_socket();
    ASSERT_NE(m_caller_sock, SRT_INVALID_SOCK);
    m_caller_wire.sock = m_caller_sock;
    const int conn_timeout_ms = 500;
    ASSERT_NE(srt_setsockopt(m_caller_sock, 0, SRTO_CONNTIMEO, &conn_timeout_ms, sizeof conn_timeout_ms), SRT_ERROR)
        << srt_getlasterror_str();
    {
        const SRT_VirtualTransportConfig cfg = m_caller_queue.getConfig(0, 1);
        ASSERT_EQ(srt_bind_virtual(m_caller_sock, (const sockaddr*)&caller_addr, (int)sizeof caller_addr, &cfg),
                  SRT_STATUS_OK)
            << srt_getlasterror_str();
    }

    EXPECT_EQ(srt_connect(m_caller_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr), SRT_ERROR);
    // The bounded refusal: the caller can only run out of its connect
    // timeout, the shape the wrong-cookie silence produces.
    ExpectLastErrno(SRT_ENOSERVER);

    // The refusal was about the listener's missing skip config, not about
    // the caller's opening flight: it was the conclusion-first shape.
    const int       hs_version_srt1 = srt::CUDT::HS_VERSION_SRT1;
    srt::CHandShake first_flight;
    ExpectFirstHandshake(m_caller_wire, srt::URQ_CONCLUSION, &first_flight);
    ASSERT_EQ(first_flight.m_iVersion, hs_version_srt1);
    ASSERT_EQ(first_flight.m_iCookie, 0);

    // Nothing was ever queued on the listener, and it stays listening.
    EXPECT_FALSE(WaitReadable(m_listener_sock, 500)) << "a connection was queued on the listener without skip_induction";
    EXPECT_EQ(srt_getsockstate(m_listener_sock), SRTS_LISTENING);

    // Both sockets close cleanly after the refused handshake.
    EXPECT_EQ(srt_close(m_caller_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_caller_sock = SRT_INVALID_SOCK;
    EXPECT_EQ(srt_close(m_listener_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_listener_sock = SRT_INVALID_SOCK;
}

// The seed must survive the connection completion on both sides: the
// caller's through postConnect, the accepted socket's through
// acceptAndRespond - both of which consult a per-peer-address RTT cache
// keyed by the peer label, and a virtual transport label is an
// owner-assigned identity that repeats across sessions. The trap is
// therefore sprung inside this test: a FIRST session on a pair of labels
// drives the live RTT far below the seed, and a SECOND session reusing
// the very same labels (through a fresh listener, so the duplicate-label
// rule of the multiplexer is not involved) must still come up seeded -
// a cache-consulting implementation would restore the first session's
// stale live values instead. The first live ACK/ACKACK samples must then
// replace the seed with the true in-memory RTT.
TEST_F(TestVirtualTransport, InitialRTTSeedViaConfigThenLiveReplace)
{
    // Reused by the second session below - that is the point of this test.
    const sockaddr_in listener_addr = FillV4("10.217.0.2", 5555);
    const sockaddr_in caller_addr   = FillV4("10.217.0.1", 5556);

    const int seed_rtt_ms    = 300;
    const int rcv_timeout_ms = 5000;

    // ---- First session: seed, verify the seed, then replace it live. ----

    PairWires(caller_addr, listener_addr);

    m_listener_sock = srt_create_socket();
    ASSERT_NE(m_listener_sock, SRT_INVALID_SOCK);
    m_listener_wire.sock = m_listener_sock;
    {
        // Both endpoints skip the Induction round trip (the phase that
        // normally delivers the first RTT sample) and seed the estimator
        // explicitly, as a WebTransport gateway does with the QUIC
        // smoothed RTT.
        const SRT_VirtualTransportConfig cfg = m_listener_queue.getConfig(seed_rtt_ms, 1);
        ASSERT_EQ(srt_bind_virtual(m_listener_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr, &cfg),
                  SRT_STATUS_OK)
            << srt_getlasterror_str();
    }
    ASSERT_NE(srt_listen(m_listener_sock, 4), SRT_ERROR) << srt_getlasterror_str();

    m_caller_sock = srt_create_socket();
    ASSERT_NE(m_caller_sock, SRT_INVALID_SOCK);
    m_caller_wire.sock = m_caller_sock;
    ASSERT_NE(srt_setsockopt(m_caller_sock, 0, SRTO_RCVTIMEO, &rcv_timeout_ms, sizeof rcv_timeout_ms), SRT_ERROR)
        << srt_getlasterror_str();
    {
        const SRT_VirtualTransportConfig cfg = m_caller_queue.getConfig(seed_rtt_ms, 1);
        ASSERT_EQ(srt_bind_virtual(m_caller_sock, (const sockaddr*)&caller_addr, (int)sizeof caller_addr, &cfg),
                  SRT_STATUS_OK)
            << srt_getlasterror_str();
    }

    ASSERT_NE(srt_connect(m_caller_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr), SRT_ERROR)
        << srt_getlasterror_str();

    ASSERT_TRUE(WaitReadable(m_listener_sock, 15000)) << "no connection was ever queued on the listener";

    sockaddr_in accept_addr;
    int         accept_len = (int)sizeof accept_addr;
    m_accepted_sock        = srt_accept(m_listener_sock, (sockaddr*)&accept_addr, &accept_len);
    ASSERT_NE(m_accepted_sock, SRT_INVALID_SOCK) << srt_getlasterror_str();
    ASSERT_NE(srt_setsockopt(m_accepted_sock, 0, SRTO_RCVTIMEO, &rcv_timeout_ms, sizeof rcv_timeout_ms), SRT_ERROR)
        << srt_getlasterror_str();

    // Pre-data: no ACK/ACKACK samples exist yet, so both estimators must
    // still hold the seed (300 ms), not the open()-time default.
    {
        SRT_TRACEBSTATS perf;
        ASSERT_EQ(srt_bstats(m_caller_sock, &perf, 0), 0);
        EXPECT_DOUBLE_EQ(perf.msRTT, (double)seed_rtt_ms) << "caller: the seed did not survive postConnect";
        ASSERT_EQ(srt_bstats(m_accepted_sock, &perf, 0), 0);
        EXPECT_DOUBLE_EQ(perf.msRTT, (double)seed_rtt_ms) << "accepted: the seed did not survive acceptAndRespond";
    }

    // Round trips of payload make both sides measure the true (in-memory,
    // sub-millisecond) RTT; the live samples must replace the seed.
    const char* payload     = "initial RTT seed";
    const int   payload_len = (int)strlen(payload);
    char        buf[1456];

    for (int i = 0; i < 20; ++i)
    {
        ASSERT_EQ(srt_sendmsg(m_caller_sock, payload, payload_len, SRT_MSGTTL_INF, false), payload_len)
            << srt_getlasterror_str();
        ASSERT_EQ(srt_recvmsg(m_accepted_sock, buf, (int)sizeof buf), payload_len) << srt_getlasterror_str();
        ASSERT_EQ(srt_sendmsg(m_accepted_sock, payload, payload_len, SRT_MSGTTL_INF, false), payload_len)
            << srt_getlasterror_str();
        ASSERT_EQ(srt_recvmsg(m_caller_sock, buf, (int)sizeof buf), payload_len) << srt_getlasterror_str();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    {
        SRT_TRACEBSTATS perf;
        ASSERT_EQ(srt_bstats(m_caller_sock, &perf, 0), 0);
        EXPECT_LT(perf.msRTT, 100.0) << "caller: the live RTT did not replace the seed";
        ASSERT_EQ(srt_bstats(m_accepted_sock, &perf, 0), 0);
        EXPECT_LT(perf.msRTT, 100.0) << "accepted: the live RTT did not replace the seed";
    }

    EXPECT_EQ(srt_close(m_accepted_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_accepted_sock = SRT_INVALID_SOCK;
    EXPECT_EQ(srt_close(m_caller_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_caller_sock = SRT_INVALID_SOCK;
    EXPECT_EQ(srt_close(m_listener_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_listener_sock = SRT_INVALID_SOCK;

    // ---- Second session on the SAME labels, through a FRESH listener. ----
    //
    // A closing socket would hand its last RTT values to the per-address
    // cache keyed by the peer label (the first session just closed two
    // such sockets), and a cache hit in postConnect (peer = the listener
    // label) or acceptAndRespond (peer = the caller label) would override
    // the configured seed with the first session's stale live values. The
    // virtual transport config must skip the cache on both sides. The
    // fresh listener keeps the duplicate-source-label rule out of the
    // picture: its brand new multiplexer serves no socket yet.

    m_listener_sock = srt_create_socket();
    ASSERT_NE(m_listener_sock, SRT_INVALID_SOCK);
    {
        const SRT_VirtualTransportConfig cfg = m_listener_queue.getConfig(seed_rtt_ms, 1);
        ASSERT_EQ(srt_bind_virtual(m_listener_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr, &cfg),
                  SRT_STATUS_OK)
            << srt_getlasterror_str();
    }
    ASSERT_NE(srt_listen(m_listener_sock, 4), SRT_ERROR) << srt_getlasterror_str();

    m_caller_sock = srt_create_socket();
    ASSERT_NE(m_caller_sock, SRT_INVALID_SOCK);
    {
        const SRT_VirtualTransportConfig cfg = m_caller_queue.getConfig(seed_rtt_ms, 1);
        ASSERT_EQ(srt_bind_virtual(m_caller_sock, (const sockaddr*)&caller_addr, (int)sizeof caller_addr, &cfg),
                  SRT_STATUS_OK)
            << srt_getlasterror_str();
    }

    ASSERT_NE(srt_connect(m_caller_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr), SRT_ERROR)
        << srt_getlasterror_str();

    ASSERT_TRUE(WaitReadable(m_listener_sock, 15000)) << "no connection was ever queued on the second listener";

    accept_len      = (int)sizeof accept_addr;
    m_accepted_sock = srt_accept(m_listener_sock, (sockaddr*)&accept_addr, &accept_len);
    ASSERT_NE(m_accepted_sock, SRT_INVALID_SOCK) << srt_getlasterror_str();

    // Pre-data again, on the reused labels: the seed, not the first
    // session's leftovers.
    {
        SRT_TRACEBSTATS perf;
        ASSERT_EQ(srt_bstats(m_caller_sock, &perf, 0), 0);
        EXPECT_DOUBLE_EQ(perf.msRTT, (double)seed_rtt_ms)
            << "caller: a stale per-address cache value replaced the seed on the reused label";
        ASSERT_EQ(srt_bstats(m_accepted_sock, &perf, 0), 0);
        EXPECT_DOUBLE_EQ(perf.msRTT, (double)seed_rtt_ms)
            << "accepted: a stale per-address cache value replaced the seed on the reused label";
    }

    EXPECT_EQ(srt_close(m_accepted_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_accepted_sock = SRT_INVALID_SOCK;
    EXPECT_EQ(srt_close(m_caller_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_caller_sock = SRT_INVALID_SOCK;
    EXPECT_EQ(srt_close(m_listener_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_listener_sock = SRT_INVALID_SOCK;
}

// SRTO_RENDEZVOUS has no virtual transport counterpart: a rendezvous
// connection has no listener that could accept a Conclusion-first
// handshake, so the cookie-less opener cannot be authenticated by either
// side. srt_bind_virtual() refuses a socket that has rendezvous already
// set (pinned by BindVirtualDoubleBindRejected); this test covers the
// reverse order - rendezvous set AFTER the virtual bind - where the
// refusal happens at connect time, inside startConnect, with the
// MJ_NOTSUP/MN_INVAL error. The refused connect must also leave the
// socket closable without a hang: the refusal unregisters the connector
// before throwing, and an entry abandoned in the rendezvous queue would
// otherwise live until its TTL (the rendezvous connect timeout times
// ten) and deadlock the close against the receiving worker.
TEST_F(TestVirtualTransport, RendezvousWithVirtualRejected)
{
    const sockaddr_in self_addr = FillV4("10.218.0.1", 5555);
    const sockaddr_in peer_addr = FillV4("10.218.0.2", 5555);

    // A skip-induction multiplexer, the config the refusal is guarding.
    m_caller_sock = srt_create_socket();
    ASSERT_NE(m_caller_sock, SRT_INVALID_SOCK);
    m_caller_wire.sock = m_caller_sock;
    {
        const SRT_VirtualTransportConfig cfg = m_caller_queue.getConfig(0, 1);
        ASSERT_EQ(srt_bind_virtual(m_caller_sock, (const sockaddr*)&self_addr, (int)sizeof self_addr, &cfg),
                  SRT_STATUS_OK)
            << srt_getlasterror_str();
    }

    // Rendezvous set AFTER the virtual bind: accepted at set time (the
    // option only demands that the socket not be connecting yet)...
    const int yes = 1;
    ASSERT_NE(srt_setsockopt(m_caller_sock, 0, SRTO_RENDEZVOUS, &yes, sizeof yes), SRT_ERROR)
        << srt_getlasterror_str();

    // ...but refused at connect time, synchronously - the refusal must
    // not decay into a waveahand-retransmit loop ended by a timeout. The
    // measured duration doubles as the guard against that regression.
    const std::chrono::steady_clock::time_point connect_start = std::chrono::steady_clock::now();
    EXPECT_EQ(srt_connect(m_caller_sock, (const sockaddr*)&peer_addr, (int)sizeof peer_addr), SRT_ERROR);
    // MJ_NOTSUP/MN_INVAL, the synchronous refusal of startConnect.
    ExpectLastErrno(SRT_EINVPARAM);
    const long long connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - connect_start)
                                     .count();
    EXPECT_LT(connect_ms, 1500) << "the refusal took the retransmit-until-timeout path";

    // The CRITICAL pin: closing the refused socket must not hang. The
    // connector must have been unregistered at throw time; a leaked entry
    // would stall the close until the rendezvous-queue TTL expires (tens
    // of seconds with the default connect timeout), far past this bound.
    const std::chrono::steady_clock::time_point close_start = std::chrono::steady_clock::now();
    EXPECT_EQ(srt_close(m_caller_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    const long long close_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - close_start).count();
    EXPECT_LT(close_ms, 10000) << "closing the refused rendezvous socket stalled - a connector leaked into the queue";
    m_caller_sock = SRT_INVALID_SOCK;
}

// The peer-label uniqueness rule of a virtual multiplexer: the source
// label is an owner-assigned identity, so a second caller reusing the
// label of a connection the listener already serves must be rejected -
// two concurrent connections sharing one label would make the per-socket
// link data ambiguous. The first connection must be unaffected: it keeps
// passing data, and repeats of ITS handshake (same peer socket id and
// ISN) keep being re-answered rather than caught by the duplicate rule.
TEST_F(TestVirtualTransport, DuplicateSourceLabelRejected)
{
    const sockaddr_in listener_addr = FillV4("10.219.0.2", 5555);
    // The shared source label: both callers report it to the listener.
    const sockaddr_in shared_addr = FillV4("10.219.0.1", 5556);

    PairWires(shared_addr, listener_addr);

    // The listener in the intended mode: skip_induction.
    m_listener_sock = srt_create_socket();
    ASSERT_NE(m_listener_sock, SRT_INVALID_SOCK);
    m_listener_wire.sock = m_listener_sock;
    {
        const SRT_VirtualTransportConfig cfg = m_listener_queue.getConfig(0, 1);
        ASSERT_EQ(srt_bind_virtual(m_listener_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr, &cfg),
                  SRT_STATUS_OK)
            << srt_getlasterror_str();
    }
    ASSERT_NE(srt_listen(m_listener_sock, 4), SRT_ERROR) << srt_getlasterror_str();

    // The FIRST caller on the label connects fine.
    m_caller_sock = srt_create_socket();
    ASSERT_NE(m_caller_sock, SRT_INVALID_SOCK);
    m_caller_wire.sock = m_caller_sock;
    {
        const SRT_VirtualTransportConfig cfg = m_caller_queue.getConfig(0, 1);
        ASSERT_EQ(srt_bind_virtual(m_caller_sock, (const sockaddr*)&shared_addr, (int)sizeof shared_addr, &cfg),
                  SRT_STATUS_OK)
            << srt_getlasterror_str();
    }

    ASSERT_NE(srt_connect(m_caller_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr), SRT_ERROR)
        << srt_getlasterror_str();

    ASSERT_TRUE(WaitReadable(m_listener_sock, 15000)) << "no connection was ever queued on the listener";

    sockaddr_in accept_addr;
    int         accept_len = (int)sizeof accept_addr;
    m_accepted_sock        = srt_accept(m_listener_sock, (sockaddr*)&accept_addr, &accept_len);
    ASSERT_NE(m_accepted_sock, SRT_INVALID_SOCK) << srt_getlasterror_str();

    const int rcv_timeout_ms = 5000;
    ASSERT_NE(srt_setsockopt(m_caller_sock, 0, SRTO_RCVTIMEO, &rcv_timeout_ms, sizeof rcv_timeout_ms), SRT_ERROR)
        << srt_getlasterror_str();
    ASSERT_NE(srt_setsockopt(m_accepted_sock, 0, SRTO_RCVTIMEO, &rcv_timeout_ms, sizeof rcv_timeout_ms), SRT_ERROR)
        << srt_getlasterror_str();

    // Sanity: the first connection passes data before the duplicate
    // arrives, and its opening flight was the conclusion-first shape.
    ExpectFirstHandshake(m_caller_wire, srt::URQ_CONCLUSION);
    const char* payload     = "first connection stays alive";
    const int   payload_len = (int)strlen(payload);
    char        buf[1456];
    ASSERT_EQ(srt_sendmsg(m_caller_sock, payload, payload_len, SRT_MSGTTL_INF, false), payload_len)
        << srt_getlasterror_str();
    ASSERT_EQ(srt_recvmsg(m_accepted_sock, buf, (int)sizeof buf), payload_len) << srt_getlasterror_str();

    // The SECOND caller on the SAME label, through its own queue and wire
    // (the listener's responses route back over the shared label to the
    // first caller's queue, so the second caller observes the refusal
    // through its bounded connect timeout).
    Wire                   dup_wire;
    srt::SRTTransportQueue dup_queue(&WireSend, &dup_wire);
    dup_wire.peer = &m_listener_queue;
    FillWireSource(dup_wire, shared_addr);
    SRTSOCKET dup_sock = srt_create_socket();
    ASSERT_NE(dup_sock, SRT_INVALID_SOCK);
    dup_wire.sock = dup_sock;
    {
        const SRT_VirtualTransportConfig cfg = dup_queue.getConfig(0, 1);
        ASSERT_EQ(srt_bind_virtual(dup_sock, (const sockaddr*)&shared_addr, (int)sizeof shared_addr, &cfg),
                  SRT_STATUS_OK)
            << srt_getlasterror_str();
    }
    const int conn_timeout_ms = 500;
    ASSERT_NE(srt_setsockopt(dup_sock, 0, SRTO_CONNTIMEO, &conn_timeout_ms, sizeof conn_timeout_ms), SRT_ERROR)
        << srt_getlasterror_str();

    EXPECT_EQ(srt_connect(dup_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr), SRT_ERROR);
    // The refusal observed from the second caller: bounded by its connect
    // timeout, as the rejection response routes to the first caller.
    ExpectLastErrno(SRT_ENOSERVER);

    // The refusal was a rejection, not a queueing: no second connection
    // may appear on the listener, and the listener stays listening.
    EXPECT_FALSE(WaitReadable(m_listener_sock, 500)) << "a second connection was queued from the duplicate label";
    EXPECT_EQ(srt_getsockstate(m_listener_sock), SRTS_LISTENING);

    // The FIRST connection still passes data, both ways, after the
    // duplicate was rejected.
    ASSERT_EQ(srt_sendmsg(m_caller_sock, payload, payload_len, SRT_MSGTTL_INF, false), payload_len)
        << srt_getlasterror_str();
    ASSERT_EQ(srt_recvmsg(m_accepted_sock, buf, (int)sizeof buf), payload_len) << srt_getlasterror_str();
    ASSERT_EQ(srt_sendmsg(m_accepted_sock, payload, payload_len, SRT_MSGTTL_INF, false), payload_len)
        << srt_getlasterror_str();
    ASSERT_EQ(srt_recvmsg(m_caller_sock, buf, (int)sizeof buf), payload_len) << srt_getlasterror_str();

    // Close the duplicate before its local wire and queue go away.
    EXPECT_EQ(srt_close(dup_sock), SRT_STATUS_OK) << srt_getlasterror_str();

    // Repeats of the FIRST connection's handshake keep being re-answered:
    // replay the captured opening flight into the listener's queue. The
    // re-answer is observed on the listener's wire - the response
    // datagram leaves through it - while the duplicate rule would have
    // swallowed the request with no listener response at all. The replay
    // must also not queue anything new.
    std::vector<char> replay;
    {
        std::lock_guard<std::mutex> lock(m_caller_wire.first_datagram_lock);
        replay = m_caller_wire.first_datagram;
    }
    ASSERT_FALSE(replay.empty());
    const long long sends_before = m_listener_wire.send_count.load();
    ASSERT_EQ(m_listener_queue.push(replay.data(), replay.size(), (const struct sockaddr*)&shared_addr,
                                    (int)sizeof shared_addr),
              0);

    bool reanswered = false;
    for (int i = 0; i < 500 && !reanswered; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        reanswered = m_listener_wire.send_count.load() > sends_before;
    }
    EXPECT_TRUE(reanswered) << "the repeat handshake of the existing connection was not re-answered";

    EXPECT_FALSE(WaitReadable(m_listener_sock, 500)) << "the replayed handshake queued a second connection";
    EXPECT_EQ(srt_getsockstate(m_listener_sock), SRTS_LISTENING);

    // And the first connection is still fully alive after the replay.
    ASSERT_EQ(srt_sendmsg(m_caller_sock, payload, payload_len, SRT_MSGTTL_INF, false), payload_len)
        << srt_getlasterror_str();
    ASSERT_EQ(srt_recvmsg(m_accepted_sock, buf, (int)sizeof buf), payload_len) << srt_getlasterror_str();

    // Clean close - the first connection and the listener.
    EXPECT_EQ(srt_close(m_accepted_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_accepted_sock = SRT_INVALID_SOCK;
    EXPECT_EQ(srt_close(m_caller_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_caller_sock = SRT_INVALID_SOCK;
    EXPECT_EQ(srt_close(m_listener_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_listener_sock = SRT_INVALID_SOCK;
}
