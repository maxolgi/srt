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
#include <cstdio>
#include <cstring>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <dirent.h>
#include <sys/socket.h>
#include <unistd.h>

#include "srt.h"
#include "srttransport.h"

#include "core.h" // CHandShake, CPacket: the wire-level handshake pins; CUDT: the internal bind entry

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

// The same source-address fill for the switch below, which reports the
// shared listener address as the source of everything it forwards.
void FillSource(sockaddr_storage& addr, socklen_t& addr_len, const sockaddr_in& sa)
{
    memset(&addr, 0, sizeof addr);
    memcpy(&addr, &sa, sizeof sa);
    addr_len = sizeof sa;
}

// Routes the datagrams sent by ONE shared transport queue to one of several
// peer queues, by destination address - a miniature of a gateway
// demultiplexing WebTransport sessions onto SRT sockets. Used where several
// callers are served by one listener: every accepted socket sends through
// the listener's queue, and the destination address (the caller's source
// label) picks the caller whose queue must receive it.
struct Switch
{
    struct Route
    {
        sockaddr_in                  dst;
        srt::SRTTransportQueue* peer;
    };
    std::vector<Route> routes;
    sockaddr_storage         source_addr;
    socklen_t                source_len = 0;
};

int SwitchSend(void* opaq, const char* data, int len, const struct sockaddr* dst, int /*dstlen*/)
{
    Switch*            sw = (Switch*)opaq;
    const sockaddr_in* d  = (const sockaddr_in*)dst;
    for (Switch::Route& r : sw->routes)
    {
        if (d->sin_family == AF_INET && d->sin_port == r.dst.sin_port && d->sin_addr.s_addr == r.dst.sin_addr.s_addr)
        {
            if (r.peer->push(data, (size_t)len, (const struct sockaddr*)&sw->source_addr, sw->source_len) == -1)
                return -1;
            break;
        }
    }

    // An unroutable datagram is swallowed, as a datagram lost on a wire.
    return len;
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

// Bounded wait for a socket state, so that a connection that never
// completes fails the test instead of hanging a subsequent call.
bool WaitState(SRTSOCKET sock, SRT_SOCKSTATUS state, int timeout_ms)
{
    for (int waited = 0; waited < timeout_ms; waited += 10)
    {
        if (srt_getsockstate(sock) == state)
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return srt_getsockstate(sock) == state;
}

// Counts the open file descriptors of the current process that are sockets
// (Linux-only; the feature itself is Linux/Emscripten-only). A virtual
// binding creates no OS socket, so the count must not move across a whole
// virtual-socket lifecycle. (An SRT epoll id is an anon_inode, not a
// socket, so epoll-based waits do not disturb this count.)
static int CountSocketFds()
{
    DIR* dir = opendir("/proc/self/fd");
    if (!dir)
        return -1;

    int            count = 0;
    struct dirent* entry;
    char           link[64];
    while ((entry = readdir(dir)))
    {
        if (entry->d_name[0] == '.')
            continue;
        const std::string path  = std::string("/proc/self/fd/") + entry->d_name;
        const ssize_t     nread = readlink(path.c_str(), link, sizeof link - 1);
        if (nread <= 0)
            continue;
        link[nread] = 0;
        if (strncmp(link, "socket:", 7) == 0)
            ++count;
    }
    closedir(dir);
    return count;
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

// Binds a socket over a virtual transport in the conclusion-first
// handshake form. The form is an INTERNAL srtcore setting, deliberately
// not reachable through the public API - the public srt_bind_virtual
// always binds with the stock handshake form - so the in-tree tests
// enter it through the internal C++ configuration path, exactly like the
// other in-tree components that need it.
void BindVirtualConclusionFirst(SRTSOCKET sock, const sockaddr_in& label, const SRT_VirtualTransportConfig& cfg)
{
    ASSERT_EQ(srt::CUDT::bind_virtual(sock, (const sockaddr*)&label, (int)sizeof label, &cfg, true), SRT_STATUS_OK)
        << srt_getlasterror_str();
}

// A send callback for the queues that only ever RECEIVE in the channel
// test below: nothing is ever sent through them, so every datagram is
// simply accepted and dropped.
int NullSend(void* /*opaq*/, const char* /*data*/, int len, const struct sockaddr* /*dst*/, int /*dstlen*/)
{
    return len;
}

// Lying deliver callbacks for TestVirtualTransport
// ChannelBoundsDeliverReportByCapacity: both call the queue's honest
// deliver() - so the datagram is really picked up and scattered into the
// provided buffers - but then report a size those buffers do not carry:
// one past the provided capacity, and a negative value other than -1.
int DeliverLyingLarge(void* opaq, struct sockaddr* w_src, int* w_srclen, SRT_VTBUF* w_vec, int nvec)
{
    srt::SRTTransportQueue* queue = (srt::SRTTransportQueue*)opaq;
    const int               honest = queue->deliver(w_src, w_srclen, w_vec, nvec);
    return honest == -1 ? -1 : honest + 1000;
}

int DeliverLyingNegative(void* opaq, struct sockaddr* w_src, int* w_srclen, SRT_VTBUF* w_vec, int nvec)
{
    srt::SRTTransportQueue* queue = (srt::SRTTransportQueue*)opaq;
    const int               honest = queue->deliver(w_src, w_srclen, w_vec, nvec);
    return honest == -1 ? -1 : -7;
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
    // handshake form (what the public bind configures), the first datagram
    // is the Induction handshake.
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
// anything up later. A NULL config, a missing callback and an out-of-range
// initial_rtt_ms are all rejected
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
        const SRT_VirtualTransportConfig cfg0  = m_listener_queue.getConfig(0);
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
        const SRT_VirtualTransportConfig cfg_max = m_listener_queue.getConfig(30000);
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

// The same wire as in BindVirtualConnectListenSendReceive, but with BOTH
// endpoints bound through the INTERNAL conclusion-first configuration
// (the skip-induction form, not reachable through the public API): the
// caller's opening flight is the CONCLUSION handshake - HS_VERSION_SRT1,
// cookie 0, carrying the HSv5 extension blocks - and the listener's
// multiplexer accepts it without the Induction/cookie exchange. The
// wire-level pins make the mode's defining behavior falsifiable: a virtual
// listener would complete a session against a stock caller too (it answers
// Inductions), so the conclusion-first shape is only observable in the
// caller's very first datagram. Proves the skip-induction path leaves the
// connected state and the bidirectional data flow intact.
TEST_F(TestVirtualTransport, BindVirtualSkipInductionRoundTrip)
{
    const sockaddr_in listener_addr = FillV4("10.215.0.2", 5555);
    const sockaddr_in caller_addr   = FillV4("10.215.0.1", 5556);

    PairWires(caller_addr, listener_addr);

    // Listener side: bound through the internal conclusion-first entry, so
    // its channel reports it and processConnectRequest bypasses the cookie
    // check for a conclusion-first request.
    m_listener_sock = srt_create_socket();
    ASSERT_NE(m_listener_sock, SRT_INVALID_SOCK);
    m_listener_wire.sock = m_listener_sock;
    BindVirtualConclusionFirst(m_listener_sock, listener_addr, m_listener_queue.getConfig());
    ASSERT_NE(srt_listen(m_listener_sock, 4), SRT_ERROR) << srt_getlasterror_str();

    // Caller side: the internal conclusion-first bind turns the first
    // handshake into the CONCLUSION.
    m_caller_sock = srt_create_socket();
    ASSERT_NE(m_caller_sock, SRT_INVALID_SOCK);
    m_caller_wire.sock = m_caller_sock;
    BindVirtualConclusionFirst(m_caller_sock, caller_addr, m_caller_queue.getConfig());

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

// The per-multiplexer gate of the conclusion-first form: the cookie bypass
// belongs to the listener's OWN bind configuration, not to the medium. A
// listener bound through the PUBLIC srt_bind_virtual (the stock handshake
// form) must keep the stock cookie validation even against a
// conclusion-first request that arrived over a virtual transport: a wrong
// cookie (0, as a conclusion-first caller sends) is silently ignored, no
// connection may ever be queued on it, and the listener stays in the
// listening state. The caller observes the refusal through its bounded
// connect timeout. This pins that the handshake form is a contract between
// the two endpoints' configurations, not a global property of the virtual
// transport seam.
TEST_F(TestVirtualTransport, VirtualListenerWithoutSkipStillRequiresCookie)
{
    const sockaddr_in listener_addr = FillV4("10.216.0.2", 5555);
    const sockaddr_in caller_addr   = FillV4("10.216.0.1", 5556);

    PairWires(caller_addr, listener_addr);

    // Listener side: the PUBLIC bind - the stock handshake form.
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

    // Caller side: the INTERNAL conclusion-first bind, so its opening flight
    // is a cookie-0 CONCLUSION. The connect timeout bounds the refusal: the
    // listener ignores every retransmission of the wrong-cookie request, so
    // the caller can only run out of its connect timeout.
    m_caller_sock = srt_create_socket();
    ASSERT_NE(m_caller_sock, SRT_INVALID_SOCK);
    m_caller_wire.sock = m_caller_sock;
    const int conn_timeout_ms = 500;
    ASSERT_NE(srt_setsockopt(m_caller_sock, 0, SRTO_CONNTIMEO, &conn_timeout_ms, sizeof conn_timeout_ms), SRT_ERROR)
        << srt_getlasterror_str();
    BindVirtualConclusionFirst(m_caller_sock, caller_addr, m_caller_queue.getConfig());

    EXPECT_EQ(srt_connect(m_caller_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr), SRT_ERROR);
    // The bounded refusal: the caller can only run out of its connect
    // timeout, the shape the wrong-cookie silence produces.
    ExpectLastErrno(SRT_ENOSERVER);

    // The refusal was about the listener's stock handshake form, not about
    // the caller's opening flight: it was the conclusion-first shape.
    const int       hs_version_srt1 = srt::CUDT::HS_VERSION_SRT1;
    srt::CHandShake first_flight;
    ExpectFirstHandshake(m_caller_wire, srt::URQ_CONCLUSION, &first_flight);
    ASSERT_EQ(first_flight.m_iVersion, hs_version_srt1);
    ASSERT_EQ(first_flight.m_iCookie, 0);

    // Nothing was ever queued on the listener, and it stays listening.
    EXPECT_FALSE(WaitReadable(m_listener_sock, 500)) << "a connection was queued on the stock-form listener";
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
    // Both endpoints skip the Induction round trip (bound conclusion-first
    // through the internal entry) and seed the estimator explicitly, as a
    // WebTransport gateway does with the QUIC smoothed RTT.
    BindVirtualConclusionFirst(m_listener_sock, listener_addr, m_listener_queue.getConfig(seed_rtt_ms));
    ASSERT_NE(srt_listen(m_listener_sock, 4), SRT_ERROR) << srt_getlasterror_str();

    m_caller_sock = srt_create_socket();
    ASSERT_NE(m_caller_sock, SRT_INVALID_SOCK);
    m_caller_wire.sock = m_caller_sock;
    ASSERT_NE(srt_setsockopt(m_caller_sock, 0, SRTO_RCVTIMEO, &rcv_timeout_ms, sizeof rcv_timeout_ms), SRT_ERROR)
        << srt_getlasterror_str();
    BindVirtualConclusionFirst(m_caller_sock, caller_addr, m_caller_queue.getConfig(seed_rtt_ms));

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
    BindVirtualConclusionFirst(m_listener_sock, listener_addr, m_listener_queue.getConfig(seed_rtt_ms));
    ASSERT_NE(srt_listen(m_listener_sock, 4), SRT_ERROR) << srt_getlasterror_str();

    m_caller_sock = srt_create_socket();
    ASSERT_NE(m_caller_sock, SRT_INVALID_SOCK);
    BindVirtualConclusionFirst(m_caller_sock, caller_addr, m_caller_queue.getConfig(seed_rtt_ms));

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

    // A conclusion-first multiplexer through the internal bind - the
    // configuration the refusal is guarding.
    m_caller_sock = srt_create_socket();
    ASSERT_NE(m_caller_sock, SRT_INVALID_SOCK);
    m_caller_wire.sock = m_caller_sock;
    BindVirtualConclusionFirst(m_caller_sock, self_addr, m_caller_queue.getConfig());

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

    // The listener in the intended mode: conclusion-first through the
    // internal bind.
    m_listener_sock = srt_create_socket();
    ASSERT_NE(m_listener_sock, SRT_INVALID_SOCK);
    m_listener_wire.sock = m_listener_sock;
    BindVirtualConclusionFirst(m_listener_sock, listener_addr, m_listener_queue.getConfig());
    ASSERT_NE(srt_listen(m_listener_sock, 4), SRT_ERROR) << srt_getlasterror_str();

    // The FIRST caller on the label connects fine.
    m_caller_sock = srt_create_socket();
    ASSERT_NE(m_caller_sock, SRT_INVALID_SOCK);
    m_caller_wire.sock = m_caller_sock;
    BindVirtualConclusionFirst(m_caller_sock, shared_addr, m_caller_queue.getConfig());

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
    BindVirtualConclusionFirst(dup_sock, shared_addr, dup_queue.getConfig());
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

// The dedicated-muxer async teardown race: a paced sender and a verifying
// receiver run as real concurrent threads, and srt_close() of the caller
// strikes in the middle of the live stream, on its own thread. The close
// path must tear down the caller's dedicated multiplexer - stopping its
// sender and receiver workers and joining them - while the sending
// application thread is still inside srt_sendmsg on the same socket, so
// every join here is bounded and any deadlock fails the test instead of
// hanging it. Once srt_close() has returned, SRT must never invoke the
// transport callbacks of that socket again: the wire and the queue are
// application objects now (see SRTTransportQueue), so the owner must be
// free to release them - the send callback count must be frozen, which
// pins that SRT truly stops the workers rather than leaving them to fire
// into freed memory. The peer must observe the end of the stream through
// its bounded receive, never by waiting forever, and the accepted socket
// and the listener must close cleanly afterwards (the check-close mode of
// the test binary must stay happy about them).
TEST_F(TestVirtualTransport, CloseDuringLiveTraffic)
{
    const sockaddr_in listener_addr = FillV4("10.220.0.2", 5555);
    const sockaddr_in caller_addr   = FillV4("10.220.0.1", 5556);

    PairWires(caller_addr, listener_addr);

    // Listener side: conclusion-first both ways (the internal bind), as a
    // WebTransport gateway would configure its sessions.
    m_listener_sock = srt_create_socket();
    ASSERT_NE(m_listener_sock, SRT_INVALID_SOCK);
    m_listener_wire.sock = m_listener_sock;
    BindVirtualConclusionFirst(m_listener_sock, listener_addr, m_listener_queue.getConfig());
    ASSERT_NE(srt_listen(m_listener_sock, 4), SRT_ERROR) << srt_getlasterror_str();

    m_caller_sock = srt_create_socket();
    ASSERT_NE(m_caller_sock, SRT_INVALID_SOCK);
    m_caller_wire.sock = m_caller_sock;
    BindVirtualConclusionFirst(m_caller_sock, caller_addr, m_caller_queue.getConfig());

    ASSERT_NE(srt_connect(m_caller_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr), SRT_ERROR)
        << srt_getlasterror_str();

    ASSERT_TRUE(WaitReadable(m_listener_sock, 15000)) << "no connection was ever queued on the listener";

    sockaddr_in accept_addr;
    int         accept_len = (int)sizeof accept_addr;
    m_accepted_sock        = srt_accept(m_listener_sock, (sockaddr*)&accept_addr, &accept_len);
    ASSERT_NE(m_accepted_sock, SRT_INVALID_SOCK) << srt_getlasterror_str();

    // Fail fast instead of hanging should the stream end go unobserved.
    // The window still sits well above the default 120 ms TSBPD latency,
    // so the healthy stream is never cut by it.
    const int rcv_timeout_ms = 500;
    ASSERT_NE(srt_setsockopt(m_accepted_sock, 0, SRTO_RCVTIMEO, &rcv_timeout_ms, sizeof rcv_timeout_ms), SRT_ERROR)
        << srt_getlasterror_str();

    // A sanity round trip first, so the stream provably flows before the
    // close.
    const char* warm_up     = "vt-close warm-up";
    const int   warm_up_len = (int)strlen(warm_up);
    char        buf[1456];
    ASSERT_EQ(srt_sendmsg(m_caller_sock, warm_up, warm_up_len, SRT_MSGTTL_INF, false), warm_up_len)
        << srt_getlasterror_str();
    ASSERT_EQ(srt_recvmsg(m_accepted_sock, buf, (int)sizeof buf), warm_up_len) << srt_getlasterror_str();

    // The mid-stream signal: the receiver announces through the promise
    // once a fair chunk of the stream has been delivered, and the main
    // thread waits for that with a deadline before closing. The promise
    // is shared so that a failure path cannot leave it dangling.
    std::shared_ptr<std::promise<void> > stream_flowing(new std::promise<void>);
    auto                                 stream_flowing_f = stream_flowing->get_future();

    struct RecvStats
    {
        int  received   = 0;
        bool ended      = false;
        bool sequence_ok = true;
        int  last_error = 0;
    };

    const int stream_msgs = 2000;

    // The sender paces the stream so that it is guaranteed to still be
    // flowing when the close strikes; the pacing shapes the traffic, it
    // is not a wait for a condition.
    auto sender = std::async(std::launch::async,
                             [this, stream_msgs]()
                             {
                                 int sent_ok = 0;
                                 for (int i = 0; i < stream_msgs; ++i)
                                 {
                                     char      msg[64];
                                     const int len = snprintf(msg, sizeof msg, "vt-close stream %05d", i);
                                     if (srt_sendmsg(m_caller_sock, msg, len, SRT_MSGTTL_INF, false) == SRT_ERROR)
                                         break; // a clean refusal is acceptable; a hang or a crash is not
                                     ++sent_ok;
                                     std::this_thread::sleep_for(std::chrono::microseconds(500));
                                 }
                                 return sent_ok;
                             });

    auto receiver = std::async(std::launch::async,
                               [this, stream_flowing]()
                               {
                                   RecvStats st;
                                   char      buf2[1456];
                                   for (;;)
                                   {
                                       const int len = srt_recvmsg(m_accepted_sock, buf2, (int)sizeof buf2);
                                       if (len == SRT_ERROR)
                                       {
                                           // The bounded stream-end signal: the receive timeout,
                                           // or the connection broken by the peer's shutdown.
                                           st.last_error = srt_getlasterror(NULL);
                                           if (st.received >= 50)
                                               st.ended = true;
                                           break;
                                       }

                                       char      want[64];
                                       const int wlen = snprintf(want, sizeof want, "vt-close stream %05d", st.received);
                                       if (len != wlen || memcmp(buf2, want, len) != 0)
                                       {
                                           st.sequence_ok = false;
                                           break;
                                       }
                                       ++st.received;
                                       if (st.received == 50)
                                           stream_flowing->set_value();
                                   }
                                   return st;
                               });

    // Wait until the stream is provably flowing, bounded.
    ASSERT_EQ(stream_flowing_f.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "the stream never flowed before the close";

    // The close itself, on its own thread and bounded: it must return
    // even while the sender is in mid-stream.
    auto closer = std::async(std::launch::async, [this]() { return srt_close(m_caller_sock); });
    ASSERT_EQ(closer.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "srt_close deadlocked against the live traffic";
    EXPECT_EQ(closer.get(), SRT_STATUS_OK) << srt_getlasterror_str();
    // The caller socket is closed exactly once - by the closer thread.
    m_caller_sock = SRT_INVALID_SOCK;

    // Both traffic threads must finish well within their bounds - the
    // sender runs until its sends start failing on the closed socket, the
    // receiver until the stream end is reported.
    ASSERT_EQ(sender.wait_for(std::chrono::seconds(15)), std::future_status::ready)
        << "the sender thread hung after the close";
    const int sent_ok = sender.get();
    ASSERT_EQ(receiver.wait_for(std::chrono::seconds(15)), std::future_status::ready)
        << "the receiver thread hung after the close";
    const RecvStats rs = receiver.get();

    EXPECT_GE(sent_ok, 1);
    EXPECT_TRUE(rs.sequence_ok) << "the received stream broke its sequence";
    EXPECT_GE(rs.received, 50);
    EXPECT_TRUE(rs.ended) << "the peer never observed the end of the stream";
    EXPECT_TRUE(rs.last_error == SRT_ETIMEOUT || rs.last_error == SRT_ECONNLOST)
        << "the stream end was reported as an unexpected error " << rs.last_error;

    // After the close has returned (and the application has stopped
    // sending), SRT must never invoke the send callback again: the wire is
    // an application object, and this freeze is what frees the owner to
    // release it. A short grace period lets any callback already in
    // flight when srt_close returned complete, so the freeze window
    // measures the steady state, not the tail of the race.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    const long long callbacks_frozen = m_caller_wire.send_count.load();
    bool           frozen           = true;
    for (int waited = 0; waited < 1000 && frozen; waited += 10)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (m_caller_wire.send_count.load() != callbacks_frozen)
            frozen = false;
    }
    EXPECT_TRUE(frozen) << "the send callback fired again after srt_close returned";

    // The teardown of the peer side must stay clean and bounded: the
    // accepted socket observed the stream end, and the listener leaves
    // with its accepted socket gone.
    const std::chrono::steady_clock::time_point teardown_start = std::chrono::steady_clock::now();
    EXPECT_EQ(srt_close(m_accepted_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_accepted_sock = SRT_INVALID_SOCK;
    EXPECT_EQ(srt_close(m_listener_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_listener_sock = SRT_INVALID_SOCK;
    const long long teardown_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                      std::chrono::steady_clock::now() - teardown_start)
                                      .count();
    EXPECT_LT(teardown_ms, 10000) << "closing the peer side after the mid-stream close stalled";
}

// Several callers, ONE listener: every accepted socket shares the
// listener's virtual multiplexer, so all three sessions exchange their
// datagrams through the same listener queue, with the switch
// demultiplexing by the destination address (the caller's source label) -
// the shape of a gateway serving several WebTransport sessions over one SRT
// listener. The callers connect sequentially, and every accepted socket
// must independently carry payload, both ways, with all three connections
// open at once and no cross-talk between them.
TEST_F(TestVirtualTransport, MultiAcceptSharedListenerMultiplexer)
{
    const sockaddr_in listener_addr = FillV4("10.221.0.2", 5555);

    // Everything lives in this struct because the queues and wires must
    // outlive the sockets: the destructor closes the sockets first - which
    // sends their shutdown through the wires - and destroys the queues
    // and wires only afterwards.
    struct Session
    {
        SRTSOCKET caller   = SRT_INVALID_SOCK;
        SRTSOCKET accepted = SRT_INVALID_SOCK;
        Wire      caller_wire;
        sockaddr_in caller_addr;
        // The wire must be declared before the queue that hands it to the
        // send callback: members are destroyed in reverse order, so the
        // queue goes away first.
        srt::SRTTransportQueue caller_queue{ &WireSend, &caller_wire };
    };

    struct Rig
    {
        SRTSOCKET listener = SRT_INVALID_SOCK;
        Switch    listener_switch;
        srt::SRTTransportQueue listener_queue{ &SwitchSend, &listener_switch };
        Session              sessions[3];

        ~Rig()
        {
            for (Session& s : sessions)
            {
                if (s.accepted != SRT_INVALID_SOCK)
                    srt_close(s.accepted);
                if (s.caller != SRT_INVALID_SOCK)
                    srt_close(s.caller);
            }
            if (listener != SRT_INVALID_SOCK)
                srt_close(listener);
        }
    } rig;

    rig.listener = srt_create_socket();
    ASSERT_NE(rig.listener, SRT_INVALID_SOCK);
    BindVirtualConclusionFirst(rig.listener, listener_addr, rig.listener_queue.getConfig());
    // Everything the shared queue sends out reports the listener's label as
    // its source; the switch routes it to the caller the datagram is
    // addressed to.
    FillSource(rig.listener_switch.source_addr, rig.listener_switch.source_len, listener_addr);
    ASSERT_NE(srt_listen(rig.listener, 4), SRT_ERROR) << srt_getlasterror_str();

    // Three callers, sequentially - deterministically - each with its own
    // queue wired into the shared listener queue.
    const int num_sessions = (int)(sizeof rig.sessions / sizeof rig.sessions[0]);
    for (int i = 0; i < num_sessions; ++i)
    {
        Session& s    = rig.sessions[i];
        s.caller_addr = FillV4("10.221.1.1", (uint16_t)(5556 + i));

        s.caller = srt_create_socket();
        ASSERT_NE(s.caller, SRT_INVALID_SOCK);
        s.caller_wire.sock = s.caller;
        BindVirtualConclusionFirst(s.caller, s.caller_addr, s.caller_queue.getConfig());
        s.caller_wire.peer = &rig.listener_queue;
        FillWireSource(s.caller_wire, s.caller_addr);
        rig.listener_switch.routes.push_back(Switch::Route{ s.caller_addr, &s.caller_queue });

        ASSERT_NE(srt_connect(s.caller, (const sockaddr*)&listener_addr, (int)sizeof listener_addr), SRT_ERROR)
            << srt_getlasterror_str();

        ASSERT_TRUE(WaitReadable(rig.listener, 15000)) << "no connection was ever queued on the listener";

        sockaddr_in accept_addr;
        int         accept_len = (int)sizeof accept_addr;
        s.accepted             = srt_accept(rig.listener, (sockaddr*)&accept_addr, &accept_len);
        ASSERT_NE(s.accepted, SRT_INVALID_SOCK) << srt_getlasterror_str();

        EXPECT_EQ(accept_addr.sin_addr.s_addr, s.caller_addr.sin_addr.s_addr);
        EXPECT_EQ(accept_addr.sin_port, s.caller_addr.sin_port);
        EXPECT_EQ(srt_getsockstate(s.caller), SRTS_CONNECTED);
        EXPECT_EQ(srt_getsockstate(s.accepted), SRTS_CONNECTED);

        // Fail fast instead of hanging should the shared-multiplexer
        // routing ever cross the sessions.
        const int rcv_timeout_ms = 5000;
        ASSERT_NE(srt_setsockopt(s.accepted, 0, SRTO_RCVTIMEO, &rcv_timeout_ms, sizeof rcv_timeout_ms), SRT_ERROR)
            << srt_getlasterror_str();
        ASSERT_NE(srt_setsockopt(s.caller, 0, SRTO_RCVTIMEO, &rcv_timeout_ms, sizeof rcv_timeout_ms), SRT_ERROR)
            << srt_getlasterror_str();
    }

    // Interleaved traffic with all three connections open: every caller
    // sends, every accepted socket receives its own - and only its own -
    // message; then the reverse direction.
    char payloads[3][64];
    char buf[1456];
    for (int i = 0; i < num_sessions; ++i)
    {
        snprintf(payloads[i], sizeof payloads[i], "multi-accept session %d", i);
        const int len = (int)strlen(payloads[i]);
        ASSERT_EQ(srt_sendmsg(rig.sessions[i].caller, payloads[i], len, SRT_MSGTTL_INF, false), len)
            << srt_getlasterror_str();
    }
    for (int i = 0; i < num_sessions; ++i)
    {
        const int len = (int)strlen(payloads[i]);
        ASSERT_EQ(srt_recvmsg(rig.sessions[i].accepted, buf, (int)sizeof buf), len) << srt_getlasterror_str();
        EXPECT_EQ(memcmp(buf, payloads[i], len), 0) << "session " << i << " received a foreign message";
    }
    for (int i = 0; i < num_sessions; ++i)
    {
        const int len = (int)strlen(payloads[i]);
        ASSERT_EQ(srt_sendmsg(rig.sessions[i].accepted, payloads[i], len, SRT_MSGTTL_INF, false), len)
            << srt_getlasterror_str();
    }
    for (int i = 0; i < num_sessions; ++i)
    {
        const int len = (int)strlen(payloads[i]);
        ASSERT_EQ(srt_recvmsg(rig.sessions[i].caller, buf, (int)sizeof buf), len) << srt_getlasterror_str();
        EXPECT_EQ(memcmp(buf, payloads[i], len), 0) << "session " << i << " received a foreign message";
    }

    // Clean close - the accepted sockets, the callers, then the listener.
    for (Session& s : rig.sessions)
    {
        EXPECT_EQ(srt_close(s.accepted), SRT_STATUS_OK) << srt_getlasterror_str();
        s.accepted = SRT_INVALID_SOCK;
    }
    for (Session& s : rig.sessions)
    {
        EXPECT_EQ(srt_close(s.caller), SRT_STATUS_OK) << srt_getlasterror_str();
        s.caller = SRT_INVALID_SOCK;
    }
    EXPECT_EQ(srt_close(rig.listener), SRT_STATUS_OK) << srt_getlasterror_str();
    rig.listener = SRT_INVALID_SOCK;
}

// Two callers bound virtually to the IDENTICAL name/label: every
// srt_bind_virtual() call creates a dedicated multiplexer that is never
// reused by another socket, so the two callers coexist despite reporting
// the same source label - their connections are told apart by which
// listener they went to, not by the label alone. Both sessions are open at
// the same time and carry independent traffic. The whole lifecycle must
// also create not a single OS socket: a virtual binding owns no OS
// resource, pinned by counting the socket fds in /proc/self/fd before,
// during and after the sessions (the feature is Linux-only, and so is the
// check).
TEST_F(TestVirtualTransport, DedicatedMuxerSameLabel)
{
    // The identical label both callers report to their listeners.
    const sockaddr_in shared_label = FillV4("10.222.0.1", 5556);

    const int sockets_before = CountSocketFds();
    ASSERT_GE(sockets_before, 0);

    // Everything lives in this struct because the queues and wires must
    // outlive the sockets (see MultiAcceptSharedListenerMultiplexer).
    struct Pair
    {
        SRTSOCKET listener  = SRT_INVALID_SOCK;
        SRTSOCKET caller    = SRT_INVALID_SOCK;
        SRTSOCKET accepted  = SRT_INVALID_SOCK;
        sockaddr_in listener_addr;
        Wire        caller_wire;   // the caller's outgoing datagrams, sourced by the shared label
        Wire        listener_wire; // the listener's outgoing datagrams, sourced by its own label
        srt::SRTTransportQueue caller_queue{ &WireSend, &caller_wire };
        srt::SRTTransportQueue listener_queue{ &WireSend, &listener_wire };

        ~Pair()
        {
            if (accepted != SRT_INVALID_SOCK)
                srt_close(accepted);
            if (caller != SRT_INVALID_SOCK)
                srt_close(caller);
            if (listener != SRT_INVALID_SOCK)
                srt_close(listener);
        }
    };

    struct Rig
    {
        Pair pairs[2];
    } rig;
    rig.pairs[0].listener_addr = FillV4("10.222.0.2", 5555);
    rig.pairs[1].listener_addr = FillV4("10.222.0.3", 5555);

    // Two listeners, each on its own label and its own queue.
    for (Pair& p : rig.pairs)
    {
        p.listener = srt_create_socket();
        ASSERT_NE(p.listener, SRT_INVALID_SOCK);
        p.listener_wire.sock = p.listener;
        BindVirtualConclusionFirst(p.listener, p.listener_addr, p.listener_queue.getConfig());
        p.listener_wire.peer = &p.caller_queue;
        FillWireSource(p.listener_wire, p.listener_addr);
        ASSERT_NE(srt_listen(p.listener, 4), SRT_ERROR) << srt_getlasterror_str();
    }

    // Two callers, both bound virtually to the IDENTICAL label, each wired
    // to its own listener.
    for (Pair& p : rig.pairs)
    {
        p.caller = srt_create_socket();
        ASSERT_NE(p.caller, SRT_INVALID_SOCK);
        p.caller_wire.sock = p.caller;
        BindVirtualConclusionFirst(p.caller, shared_label, p.caller_queue.getConfig());
        ExpectSockName(p.caller, shared_label);
        p.caller_wire.peer = &p.listener_queue;
        FillWireSource(p.caller_wire, shared_label);
    }

    // Both connections at the same time: both connects are placed before
    // either accept is taken.
    for (Pair& p : rig.pairs)
    {
        ASSERT_NE(srt_connect(p.caller, (const sockaddr*)&p.listener_addr, (int)sizeof p.listener_addr), SRT_ERROR)
            << srt_getlasterror_str();
    }
    for (Pair& p : rig.pairs)
    {
        ASSERT_TRUE(WaitReadable(p.listener, 15000)) << "no connection was ever queued on the listener";

        sockaddr_in accept_addr;
        int         accept_len = (int)sizeof accept_addr;
        p.accepted             = srt_accept(p.listener, (sockaddr*)&accept_addr, &accept_len);
        ASSERT_NE(p.accepted, SRT_INVALID_SOCK) << srt_getlasterror_str();
        // Both listeners see the very same peer label - harmless, because
        // neither multiplexer serves any other peer.
        EXPECT_EQ(accept_addr.sin_addr.s_addr, shared_label.sin_addr.s_addr);
        EXPECT_EQ(accept_addr.sin_port, shared_label.sin_port);
    }

    const int rcv_timeout_ms = 5000;
    for (Pair& p : rig.pairs)
    {
        ASSERT_TRUE(WaitState(p.caller, SRTS_CONNECTED, 5000)) << "the caller never completed the connection";
        EXPECT_EQ(srt_getsockstate(p.accepted), SRTS_CONNECTED);
        ASSERT_NE(srt_setsockopt(p.caller, 0, SRTO_RCVTIMEO, &rcv_timeout_ms, sizeof rcv_timeout_ms), SRT_ERROR)
            << srt_getlasterror_str();
        ASSERT_NE(srt_setsockopt(p.accepted, 0, SRTO_RCVTIMEO, &rcv_timeout_ms, sizeof rcv_timeout_ms), SRT_ERROR)
            << srt_getlasterror_str();
    }

    // The identical label must not cross the two sessions: each pair
    // exchanges its own payload, both ways, with both open at once.
    const char* payloads[2] = { "same-label session zero", "same-label session one" };
    char        buf[1456];
    for (int i = 0; i < 2; ++i)
    {
        const int len = (int)strlen(payloads[i]);
        ASSERT_EQ(srt_sendmsg(rig.pairs[i].caller, payloads[i], len, SRT_MSGTTL_INF, false), len)
            << srt_getlasterror_str();
    }
    for (int i = 0; i < 2; ++i)
    {
        const int len = (int)strlen(payloads[i]);
        ASSERT_EQ(srt_recvmsg(rig.pairs[i].accepted, buf, (int)sizeof buf), len) << srt_getlasterror_str();
        EXPECT_EQ(memcmp(buf, payloads[i], len), 0) << "session " << i << " received a foreign message";
    }
    for (int i = 0; i < 2; ++i)
    {
        const int len = (int)strlen(payloads[i]);
        ASSERT_EQ(srt_sendmsg(rig.pairs[i].accepted, payloads[i], len, SRT_MSGTTL_INF, false), len)
            << srt_getlasterror_str();
    }
    for (int i = 0; i < 2; ++i)
    {
        const int len = (int)strlen(payloads[i]);
        ASSERT_EQ(srt_recvmsg(rig.pairs[i].caller, buf, (int)sizeof buf), len) << srt_getlasterror_str();
        EXPECT_EQ(memcmp(buf, payloads[i], len), 0) << "session " << i << " received a foreign message";
    }

    // The whole two-session lifecycle ran without creating a single OS
    // socket - this is the peak, with four sockets connected.
    EXPECT_EQ(CountSocketFds(), sockets_before) << "a virtual binding created an OS socket";

    // Clean close - the accepted sockets, the callers, then the listeners.
    for (Pair& p : rig.pairs)
    {
        EXPECT_EQ(srt_close(p.accepted), SRT_STATUS_OK) << srt_getlasterror_str();
        p.accepted = SRT_INVALID_SOCK;
    }
    for (Pair& p : rig.pairs)
    {
        EXPECT_EQ(srt_close(p.caller), SRT_STATUS_OK) << srt_getlasterror_str();
        p.caller = SRT_INVALID_SOCK;
    }
    for (Pair& p : rig.pairs)
    {
        EXPECT_EQ(srt_close(p.listener), SRT_STATUS_OK) << srt_getlasterror_str();
        p.listener = SRT_INVALID_SOCK;
    }

    // And nothing OS-level leaked, either.
    EXPECT_LE(CountSocketFds(), sockets_before);
}

// The receiver-side contract of SRTO_TLPKTDROP: a data packet lost on the
// wire while later packets keep flowing must be dropped as too-late-to-play
// once the first subsequent packet passes its TSBPD play time, instead of
// holding the stream back waiting for a retransmission. The wire swallows
// every copy (original and retransmissions) of one message; the stream must
// complete with exactly the other messages delivered in order, and the
// receiver must count the dropped packet in the stats. This is the receive
// side that makes the sender's too-late retransmit skip correct: rexmitting
// a packet the receiver would drop anyway wastes bandwidth.
TEST_F(TestVirtualTransport, ReceiverDropsTooLateMissingPacket)
{
    const sockaddr_in listener_addr = FillV4("10.223.0.2", 5555);
    const sockaddr_in caller_addr   = FillV4("10.223.0.1", 5556);

    PairWires(caller_addr, listener_addr);

    const int latency_ms = 60;

    m_listener_sock = srt_create_socket();
    ASSERT_NE(m_listener_sock, SRT_INVALID_SOCK);
    ASSERT_NE(srt_setsockopt(m_listener_sock, 0, SRTO_LATENCY, &latency_ms, sizeof latency_ms), SRT_ERROR)
        << srt_getlasterror_str();
    m_listener_wire.sock = m_listener_sock;
    BindVirtualConclusionFirst(m_listener_sock, listener_addr, m_listener_queue.getConfig());
    ASSERT_NE(srt_listen(m_listener_sock, 4), SRT_ERROR) << srt_getlasterror_str();

    m_caller_sock = srt_create_socket();
    ASSERT_NE(m_caller_sock, SRT_INVALID_SOCK);
    ASSERT_NE(srt_setsockopt(m_caller_sock, 0, SRTO_LATENCY, &latency_ms, sizeof latency_ms), SRT_ERROR)
        << srt_getlasterror_str();
    m_caller_wire.sock = m_caller_sock;
    BindVirtualConclusionFirst(m_caller_sock, caller_addr, m_caller_queue.getConfig());

    ASSERT_NE(srt_connect(m_caller_sock, (const sockaddr*)&listener_addr, (int)sizeof listener_addr), SRT_ERROR)
        << srt_getlasterror_str();

    ASSERT_TRUE(WaitReadable(m_listener_sock, 15000)) << "no connection was ever queued on the listener";

    sockaddr_in accept_addr;
    int         accept_len = (int)sizeof accept_addr;
    m_accepted_sock        = srt_accept(m_listener_sock, (sockaddr*)&accept_addr, &accept_len);
    ASSERT_NE(m_accepted_sock, SRT_INVALID_SOCK) << srt_getlasterror_str();

    // Fail fast instead of hanging should the too-late drop not happen.
    const int rcv_timeout_ms = 5000;
    ASSERT_NE(srt_setsockopt(m_accepted_sock, 0, SRTO_RCVTIMEO, &rcv_timeout_ms, sizeof rcv_timeout_ms), SRT_ERROR)
        << srt_getlasterror_str();

    // From now on every datagram carrying the victim message disappears.
    m_caller_wire.swallow_tag = "SWALLOW-ME";

    const int num_msgs = 10;
    char      payloads[num_msgs][64];
    for (int i = 0; i < num_msgs; ++i)
    {
        snprintf(payloads[i], sizeof payloads[i], "vt-late msg %02d%s", i + 1, i == 0 ? " SWALLOW-ME" : "");
        const int len = (int)strlen(payloads[i]);
        ASSERT_EQ(srt_sendmsg(m_caller_sock, payloads[i], len, SRT_MSGTTL_INF, false), len) << srt_getlasterror_str();
    }

    // Messages 2..N must be delivered, in order. The delivery of message 2
    // at all IS the too-late drop under test: TSBPD does not play a packet
    // positioned after a sequence gap until the gap is either filled by a
    // retransmission (swallowed here) or dropped as too late.
    char buf[1456];
    for (int i = 1; i < num_msgs; ++i)
    {
        const int recv_len = srt_recvmsg(m_accepted_sock, buf, (int)sizeof buf);
        ASSERT_GT(recv_len, 0) << srt_getlasterror_str();
        ASSERT_EQ(recv_len, (int)strlen(payloads[i]));
        EXPECT_EQ(memcmp(buf, payloads[i], recv_len), 0) << "unexpected message at position " << i;
    }

    // The victim packet was counted as too-late-to-play on the receiver.
    SRT_TRACEBSTATS perf;
    ASSERT_EQ(srt_bstats(m_accepted_sock, &perf, 0), 0);
    EXPECT_GE(perf.pktRcvDropTotal, 1);

    // Clean close - the shutdown flights go through the wires too.
    EXPECT_EQ(srt_close(m_accepted_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_accepted_sock = SRT_INVALID_SOCK;
    EXPECT_EQ(srt_close(m_caller_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_caller_sock = SRT_INVALID_SOCK;
    EXPECT_EQ(srt_close(m_listener_sock), SRT_STATUS_OK) << srt_getlasterror_str();
    m_listener_sock = SRT_INVALID_SOCK;
}

// A connecting socket must never be observable as SRTS_BROKEN while its
// connection is still being established or completed.
// CUDTSocket::getStatus() used to synthesize SRTS_BROKEN out of the pair
// (m_State not in {CONNECTING, CONNECTED, BROKEN}, m_Status ==
// SRTS_CONNECTING) - a combination that every state/status transition of a
// connecting caller produces on another thread's read interleaving (the
// two atomics are stored one after the other). An application polling
// srt_getsockstate() - the QuicSRT gateway polls every session on its
// ~2 ms registry tick - could catch such a pair and tear down a live
// connection: freshly connected sessions were intermittently reaped and
// their sockets went silent until the peer's peer-idle timeout. This test
// drives many conclusion-first connects while one thread churns
// global-lock-holding API calls (stretching the transition windows) and
// another samples the socket state exactly the way the gateway does;
// over lossless in-memory wires a BROKEN observation can only be the bug.
TEST_F(TestVirtualTransport, ConnectingStateNeverFalselyBroken)
{
    const int num_pairs = 100;

    // A churn thread: bare create/close cycles hold the global control
    // lock briefly each time, contending the very locks the connect
    // completion path takes (the more contention, the wider the
    // state/status transition windows - the test must catch them).
    std::atomic<bool> churn_stop{false};
    std::thread churn(
        [&churn_stop]
        {
            while (!churn_stop.load(std::memory_order_relaxed))
            {
                const SRTSOCKET dummy = srt_create_socket();
                if (dummy != SRT_INVALID_SOCK)
                    srt_close(dummy);
                std::this_thread::yield();
            }
        });

    for (int i = 0; i < num_pairs; ++i)
    {
        // Unique labels per iteration (the virtual demux keys off them).
        const sockaddr_in listener_addr = FillV4("10.215.7.9", uint16_t(30000 + (i % 1000)));
        const sockaddr_in caller_addr   = FillV4("10.215.7.8", uint16_t(30000 + (i % 1000)));

        Wire               caller_wire, listener_wire;
        srt::SRTTransportQueue caller_queue(&WireSend, &caller_wire);
        srt::SRTTransportQueue listener_queue(&WireSend, &listener_wire);
        caller_wire.peer = &listener_queue;
        FillWireSource(caller_wire, caller_addr);
        listener_wire.peer = &caller_queue;
        FillWireSource(listener_wire, listener_addr);

        SRTSOCKET listener_sock = srt_create_socket();
        ASSERT_NE(listener_sock, SRT_INVALID_SOCK);
        BindVirtualConclusionFirst(listener_sock, listener_addr, listener_queue.getConfig());
        ASSERT_NE(srt_listen(listener_sock, 4), SRT_ERROR) << srt_getlasterror_str();

        SRTSOCKET caller_sock = srt_create_socket();
        ASSERT_NE(caller_sock, SRT_INVALID_SOCK);
        const int no_block = 0; // asynchronous connect, like the gateway initiator
        ASSERT_EQ(srt_setsockopt(caller_sock, 0, SRTO_RCVSYN, &no_block, sizeof no_block), 0);
        BindVirtualConclusionFirst(caller_sock, caller_addr, caller_queue.getConfig());

        // The state sampler: spins on srt_getsockstate like the gateway's
        // registry tick, until the socket is connected (or broken, or the
        // deadline hits). Any SRTS_BROKEN over a lossless wire is the bug.
        std::atomic<bool> seen_broken{false};
        std::atomic<bool> seen_connected{false};
        std::thread sampler(
            [caller_sock, &seen_broken, &seen_connected]
            {
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
                while (std::chrono::steady_clock::now() < deadline)
                {
                    const SRT_SOCKSTATUS st = srt_getsockstate(caller_sock);
                    if (st == SRTS_BROKEN)
                    {
                        seen_broken.store(true, std::memory_order_relaxed);
                        return;
                    }
                    if (st == SRTS_CONNECTED)
                    {
                        seen_connected.store(true, std::memory_order_relaxed);
                        return;
                    }
                    std::this_thread::yield();
                }
            });

        ASSERT_NE(srt_connect(caller_sock, (const sockaddr*)&listener_addr, sizeof listener_addr), SRT_ERROR)
            << srt_getlasterror_str();

        sampler.join();
        EXPECT_TRUE(seen_connected.load()) << "pair " << i << ": the connection never completed";
        EXPECT_FALSE(seen_broken.load()) << "pair " << i
                                         << ": a connecting socket was reported SRTS_BROKEN "
                                            "(false-broken window in postConnect)";

        // Accept and close, in the teardown order the other tests use.
        if (WaitReadable(listener_sock, 5000))
        {
            sockaddr_in accept_addr;
            int         accept_len = (int)sizeof accept_addr;
            const SRTSOCKET accepted = srt_accept(listener_sock, (sockaddr*)&accept_addr, &accept_len);
            if (accepted != SRT_INVALID_SOCK)
            {
                EXPECT_EQ(srt_close(accepted), SRT_STATUS_OK);
            }
        }
        EXPECT_EQ(srt_close(caller_sock), SRT_STATUS_OK);
        EXPECT_EQ(srt_close(listener_sock), SRT_STATUS_OK);

        if (HasFailure())
            break;
    }

    churn_stop.store(true, std::memory_order_relaxed);
    churn.join();
}

// The buffer-capacity contract of CChannelVirtual::recvfrom, exercised
// directly on the channel (a unit test of the channel, not an end-to-end
// wire test): the size the owner's deliver callback reports may be
// trusted only as far as the buffers SRT handed it. On a UDP socket the
// kernel enforces this for free - recvmsg() never writes past the
// iovecs and reports MSG_TRUNC for a datagram that does not fit, which
// the UDP path treats as a drop - but the owner callback is arbitrary
// code, so the channel must enforce the same bound itself: a report
// beyond the provided capacity would make setLength() plant a length
// past the payload buffer for downstream SRT to read out of bounds, and
// a negative report other than -1 wraps around an unsigned lower-bound
// check into a huge size. Each case runs on a fresh queue+channel with
// one datagram pushed - datagrams are consumed - and the packet gets the
// same shape of receive buffer the queue worker provides
// (CRcvQueue::worker_RetrieveAndProcessUnit sets the payload size on its
// unit's packet before every recvfrom): a 1500-byte payload buffer.
TEST_F(TestVirtualTransport, ChannelBoundsDeliverReportByCapacity)
{
    const sockaddr_in label_addr = FillV4("10.224.0.2", 5555);
    const sockaddr_in src_addr   = FillV4("10.224.0.1", 5556);

    // One valid SRT datagram in the network byte order the queue
    // expects: the fixed 16-byte header - a solo DATA packet, sequence
    // 1, message 1 - followed by the payload. The payload is big enough
    // that the +1000 lie of the second case pushes the reported size
    // past the provided 16 + 1500 bytes of capacity.
    const size_t       payload_len = 600;
    std::vector<char>  datagram(srt::CPacket::HDR_SIZE + payload_len);
    uint32_t*          hdr = (uint32_t*)datagram.data();
    hdr[0]                = htonl(1);                                        // SEQNO: data, sequence 1
    hdr[1]                = htonl((uint32_t)srt::PacketBoundaryBits(srt::PB_SOLO) | 1u); // MSGNO: solo, message 1
    hdr[2]                = htonl(0);                                        // TIMESTAMP
    hdr[3]                = htonl(2);                                        // destination socket id
    for (size_t i = 0; i < payload_len; ++i)
        datagram[srt::CPacket::HDR_SIZE + i] = (char)(i & 0xff);

    // The honest deliver: the reported size is the size of the datagram,
    // and the datagram is taken in whole.
    {
        srt::SRTTransportQueue queue(&NullSend, NULL);
        ASSERT_EQ(queue.push(datagram.data(), datagram.size(), (const struct sockaddr*)&src_addr, sizeof src_addr),
                  0);

        const srt::CChannelVirtual channel(
            queue.getConfig(), srt::sockaddr_any((const struct sockaddr*)&label_addr, sizeof label_addr), false);

        srt::CPacket packet;
        packet.allocate(1500);
        srt::sockaddr_any from(AF_INET);

        EXPECT_EQ(channel.recvfrom(from, packet), srt::RST_OK);
        EXPECT_EQ(packet.getLength(), payload_len);
        // The datagram was really scattered into the provided buffers
        // (a data packet's payload stays in the network byte order).
        EXPECT_EQ(memcmp(packet.getData(), datagram.data() + srt::CPacket::HDR_SIZE, payload_len), 0);
    }

    // deliver reports 1000 more than it wrote - past the provided
    // buffers. Like MSG_TRUNC on a UDP socket, the datagram must be
    // dropped: RST_AGAIN with the packet length reset, never a length
    // planted beyond the payload buffer.
    {
        srt::SRTTransportQueue queue(&NullSend, NULL);
        ASSERT_EQ(queue.push(datagram.data(), datagram.size(), (const struct sockaddr*)&src_addr, sizeof src_addr),
                  0);

        SRT_VirtualTransportConfig cfg = queue.getConfig();
        cfg.deliver = &DeliverLyingLarge; // the config's opaq stays the queue

        const srt::CChannelVirtual channel(
            cfg, srt::sockaddr_any((const struct sockaddr*)&label_addr, sizeof label_addr), false);

        srt::CPacket packet;
        packet.allocate(1500);
        srt::sockaddr_any from(AF_INET);

        EXPECT_EQ(channel.recvfrom(from, packet), srt::RST_AGAIN);
        EXPECT_EQ(packet.getLength(), (size_t)-1) << "a size past the provided buffers was planted as the length";
    }

    // deliver reports a negative size other than -1: it must not wrap
    // around into a huge unsigned value, but drop the datagram the same
    // way.
    {
        srt::SRTTransportQueue queue(&NullSend, NULL);
        ASSERT_EQ(queue.push(datagram.data(), datagram.size(), (const struct sockaddr*)&src_addr, sizeof src_addr),
                  0);

        SRT_VirtualTransportConfig cfg = queue.getConfig();
        cfg.deliver = &DeliverLyingNegative;

        const srt::CChannelVirtual channel(
            cfg, srt::sockaddr_any((const struct sockaddr*)&label_addr, sizeof label_addr), false);

        srt::CPacket packet;
        packet.allocate(1500);
        srt::sockaddr_any from(AF_INET);

        EXPECT_EQ(channel.recvfrom(from, packet), srt::RST_AGAIN);
        EXPECT_EQ(packet.getLength(), (size_t)-1) << "a negative report wrapped into a bogus length";
    }
}
