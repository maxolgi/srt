/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2026 maxolgi.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "gtest/gtest.h"

#include "srttransport.h"

using namespace std;
using srt::SRTTransportQueue;

namespace {

// The SRT packet header size (srtcore's CPacket::HDR_SIZE), restated here
// because the public headers do not expose it.
const size_t HDR_SIZE = 16;

// The bound on the number of pending datagrams in the queue
// (VT_MAX_PENDING in srttransport.cpp).
const size_t MAX_PENDING = 1024;

// The sanity bound for a single datagram (VT_MAX_DATAGRAM in
// srttransport.cpp).
const size_t MAX_DATAGRAM = 65536;

// A test source address: 192.168.10.<last> : 0x10<last>.
sockaddr_in TestSource(int last)
{
    sockaddr_in src;
    memset(&src, 0, sizeof src);
    src.sin_family      = AF_INET;
    src.sin_port        = htons(0x1000 + last);
    src.sin_addr.s_addr = htonl(0xC0A80A00 + last); // 192.168.10.last
    return src;
}

// Check that a delivered source address equals TestSource(last).
void ExpectSource(const sockaddr_in& got, int last)
{
    EXPECT_EQ(got.sin_family, AF_INET);
    EXPECT_EQ(got.sin_port, htons(0x1000 + last));
    EXPECT_EQ(got.sin_addr.s_addr, htonl(0xC0A80A00 + last));
}

// A whole SRT-sized datagram for index i: a distinguishable header block
// plus a payload block.
string TestDatagram(int i, size_t payload_size)
{
    string dg;
    dg.resize(HDR_SIZE + payload_size);
    dg[0] = 'H';
    dg[1] = 'D';
    dg[2] = 'R';
    dg[3] = (char)i; // the index, to verify the FIFO order
    for (size_t j = 0; j < payload_size; ++j)
        dg[HDR_SIZE + j] = (char)('a' + ((i + j) % 26));
    return dg;
}

// Deliver one datagram through the queue into header/payload buffers of
// the given payload capacity, the way the SRT receive worker does.
// Returns the deliver() result and fills the written length.
int DeliverOne(SRTTransportQueue& q, char* hdr, size_t hdr_cap, char* payload, size_t payload_cap, sockaddr_in& w_src,
               size_t& w_total)
{
    sockaddr_in src;
    memset(&src, 0, sizeof src);
    int srclen = (int)sizeof src;

    SRT_VTBUF vec[2];
    vec[0].data = hdr;
    vec[0].len  = (int)hdr_cap;
    vec[1].data = payload;
    vec[1].len  = (int)payload_cap;

    const int res = q.deliver(reinterpret_cast<sockaddr*>(&src), &srclen, vec, 2);
    w_src         = src;
    w_total       = res > 0 ? (size_t)res : 0;
    return res;
}

// The plain contiguous send callback the gather adapter wraps: captures
// the datagram and the destination.
struct SendCapture
{
    mutex mx;
    condition_variable cv;
    vector<string> datagrams;
    vector<sockaddr_in> dsts;
    int retval = 3; // what the callback reports as accepted

    void add(const char* data, int len, const sockaddr* dst)
    {
        lock_guard<mutex> lk(mx);
        datagrams.push_back(string(data, data + len));
        sockaddr_in d;
        memset(&d, 0, sizeof d);
        if (dst && dst->sa_family == AF_INET)
            memcpy(&d, dst, sizeof d);
        dsts.push_back(d);
        cv.notify_all();
    }

    size_t count()
    {
        lock_guard<mutex> lk(mx);
        return datagrams.size();
    }

    bool waitFor(size_t n, chrono::milliseconds timeout)
    {
        unique_lock<mutex> lk(mx);
        return cv.wait_for(lk, timeout, [&] { return datagrams.size() >= n; });
    }
};

int captureSend(void* opaq, const char* data, int len, const sockaddr* dst, int)
{
    static_cast<SendCapture*>(opaq)->add(data, len, dst);
    return static_cast<SendCapture*>(opaq)->retval;
}

} // namespace

// Pushing datagrams wakes the waiting side and delivers them unchanged,
// in the FIFO order, with their source addresses.
TEST(TransportQueue, PushDeliverOrder)
{
    SendCapture cap;
    SRTTransportQueue q(&captureSend, &cap);

    const string dg0 = TestDatagram(0, 20);
    const string dg1 = TestDatagram(1, 300);
    const string dg2 = TestDatagram(2, 1);
    const sockaddr_in src0 = TestSource(1);
    const sockaddr_in src1 = TestSource(2);
    const sockaddr_in src2 = TestSource(3);

    EXPECT_EQ(q.push(dg0.data(), dg0.size(), (sockaddr*)&src0, sizeof src0), 0);
    EXPECT_EQ(q.push(dg1.data(), dg1.size(), (sockaddr*)&src1, sizeof src1), 0);
    EXPECT_EQ(q.push(dg2.data(), dg2.size(), (sockaddr*)&src2, sizeof src2), 0);

    const string* expected[3] = {&dg0, &dg1, &dg2};
    const int         expected_src[3] = {1, 2, 3};

    for (int i = 0; i < 3; ++i)
    {
        // The queued datagrams are reported ready without waiting; the
        // wake flag is re-raised by deliver() while datagrams remain.
        EXPECT_EQ(q.waitread(0), SRT_VTWAIT_READY);

        char        hdr[HDR_SIZE];
        char        payload[1500];
        sockaddr_in got_src;
        size_t      total = 0;
        memset(hdr, 0, sizeof hdr);
        memset(payload, 0xEE, sizeof payload);

        ASSERT_GT(DeliverOne(q, hdr, sizeof hdr, payload, sizeof payload, got_src, total), 0);
        ASSERT_EQ(total, expected[i]->size());
        EXPECT_EQ(0, memcmp(hdr, expected[i]->data(), HDR_SIZE));
        EXPECT_EQ(0, memcmp(payload, expected[i]->data() + HDR_SIZE, total - HDR_SIZE));
        ExpectSource(got_src, expected_src[i]);
    }

    // Nothing left: waiting times out (zero wait) and delivering fails.
    EXPECT_EQ(q.waitread(0), SRT_VTWAIT_TIMEOUT);

    char        hdr[HDR_SIZE];
    char        payload[8];
    sockaddr_in got_src;
    size_t      total = 0;
    EXPECT_EQ(DeliverOne(q, hdr, sizeof hdr, payload, sizeof payload, got_src, total), -1);
}

// A header-only (16-byte) datagram is delivered whole with an empty
// payload - the one-past-the-end regression of the old implementation,
// which read &data[HDR_SIZE] on a 16-byte buffer.
TEST(TransportQueue, HeaderOnlyDatagram)
{
    SendCapture cap;
    SRTTransportQueue q(&captureSend, &cap);

    const string dg = TestDatagram(7, 0);
    ASSERT_EQ(dg.size(), HDR_SIZE);

    const sockaddr_in src = TestSource(4);
    ASSERT_EQ(q.push(dg.data(), dg.size(), (sockaddr*)&src, sizeof src), 0);
    EXPECT_EQ(q.waitread(100), SRT_VTWAIT_READY);

    char        hdr[HDR_SIZE];
    char        payload[1500];
    sockaddr_in got_src;
    size_t      total = 0;
    memset(payload, 0xEE, sizeof payload);

    ASSERT_EQ(DeliverOne(q, hdr, sizeof hdr, payload, sizeof payload, got_src, total), (int)HDR_SIZE);
    EXPECT_EQ(total, HDR_SIZE);
    EXPECT_EQ(0, memcmp(hdr, dg.data(), HDR_SIZE));
    // The payload buffer is not touched and the source is delivered.
    EXPECT_EQ(payload[0], (char)0xEE);
    ExpectSource(got_src, 4);

    EXPECT_EQ(q.waitread(0), SRT_VTWAIT_TIMEOUT);
}

// A datagram that does not fit the provided buffers is discarded, and the
// following one is delivered intact.
TEST(TransportQueue, OversizeDatagramDiscarded)
{
    SendCapture cap;
    SRTTransportQueue q(&captureSend, &cap);

    const string        dg0 = TestDatagram(0, 100);
    const string        dg1 = TestDatagram(1, 10);
    const sockaddr_in   src = TestSource(5);

    ASSERT_EQ(q.push(dg0.data(), dg0.size(), (sockaddr*)&src, sizeof src), 0);
    ASSERT_EQ(q.push(dg1.data(), dg1.size(), (sockaddr*)&src, sizeof src), 0);

    // A payload buffer for 50 bytes only: the 100-byte payload cannot fit.
    char        hdr[HDR_SIZE];
    char        payload[50];
    sockaddr_in got_src;
    size_t      total = 0;
    EXPECT_EQ(q.waitread(0), SRT_VTWAIT_READY);
    EXPECT_EQ(DeliverOne(q, hdr, sizeof hdr, payload, sizeof payload, got_src, total), -1);

    // The next datagram is delivered intact.
    EXPECT_EQ(q.waitread(0), SRT_VTWAIT_READY);
    ASSERT_GT(DeliverOne(q, hdr, sizeof hdr, payload, sizeof payload, got_src, total), 0);
    EXPECT_EQ(total, dg1.size());
    EXPECT_EQ(0, memcmp(hdr, dg1.data(), HDR_SIZE));
    EXPECT_EQ(0, memcmp(payload, dg1.data() + HDR_SIZE, dg1.size() - HDR_SIZE));
}

// Invalid pushes are rejected: a datagram below the SRT header size, one
// above the datagram bound, and a source pointer with a zero length.
TEST(TransportQueue, PushValidation)
{
    SendCapture cap;
    SRTTransportQueue q(&captureSend, &cap);

    const string tooshort = TestDatagram(0, 0).substr(0, HDR_SIZE - 1);
    const string huge(MAX_DATAGRAM + 1, 'x');
    const sockaddr_in src = TestSource(6);

    EXPECT_EQ(q.push(tooshort.data(), tooshort.size(), (sockaddr*)&src, sizeof src), -1);
    EXPECT_EQ(q.push(huge.data(), huge.size(), (sockaddr*)&src, sizeof src), -1);
    EXPECT_EQ(q.push(TestDatagram(0, 4).data(), HDR_SIZE + 4, (sockaddr*)&src, 0), -1);

    // A null source with a zero length is accepted - the datagram is then
    // delivered with an empty source address. Only the two datagrams
    // above were rejected, so exactly one is deliverable.
    const string ok = TestDatagram(0, 4);
    EXPECT_EQ(q.push(ok.data(), ok.size(), nullptr, 0), 0);

    EXPECT_EQ(q.waitread(0), SRT_VTWAIT_READY);
    sockaddr_in got_src;
    memset(&got_src, 0, sizeof got_src);
    int srclen = sizeof got_src;
    char     hdr[HDR_SIZE];
    char     payload[8];
    SRT_VTBUF vec[2];
    vec[0].data = hdr;
    vec[0].len  = sizeof hdr;
    vec[1].data = payload;
    vec[1].len  = sizeof payload;
    EXPECT_EQ(q.deliver((sockaddr*)&got_src, &srclen, vec, 2), (int)ok.size());
    EXPECT_EQ(srclen, 0);

    // Nothing remains.
    EXPECT_EQ(q.waitread(0), SRT_VTWAIT_TIMEOUT);
}

// While the queue is full (VT_MAX_PENDING), pushes fail for as long as it
// stays full - like a full kernel socket buffer - and succeed again once
// the queue is drained. The delivered order is preserved.
TEST(TransportQueue, OverflowStickyThenRecover)
{
    SendCapture cap;
    SRTTransportQueue q(&captureSend, &cap);

    const sockaddr_in src = TestSource(7);

    for (size_t i = 0; i < MAX_PENDING; ++i)
    {
        const string dg = TestDatagram((int)i, 4);
        ASSERT_EQ(q.push(dg.data(), dg.size(), (sockaddr*)&src, sizeof src), 0) << "i=" << i;
    }

    // Full: a push is dropped, and keeps failing on retries (sticky).
    const string extra = TestDatagram(200, 4);
    EXPECT_EQ(q.push(extra.data(), extra.size(), (sockaddr*)&src, sizeof src), -1);
    EXPECT_EQ(q.push(extra.data(), extra.size(), (sockaddr*)&src, sizeof src), -1);

    // Draining one datagram makes room for exactly one more push.
    char        hdr[HDR_SIZE];
    char        payload[8];
    sockaddr_in got_src;
    size_t      total = 0;
    ASSERT_GT(DeliverOne(q, hdr, sizeof hdr, payload, sizeof payload, got_src, total), 0);
    ASSERT_EQ(total, HDR_SIZE + 4);
    EXPECT_EQ(hdr[3], (char)0); // the earliest datagram, index 0

    // Recovery per the old behavior: pushing works again.
    const string recovered = TestDatagram(201, 4);
    EXPECT_EQ(q.push(recovered.data(), recovered.size(), (sockaddr*)&src, sizeof src), 0);

    // The whole queue comes out in the pushed order, recovered one last.
    for (size_t i = 1; i < MAX_PENDING; ++i)
    {
        ASSERT_EQ(q.waitread(0), SRT_VTWAIT_READY) << "i=" << i;
        ASSERT_EQ(DeliverOne(q, hdr, sizeof hdr, payload, sizeof payload, got_src, total), (int)(HDR_SIZE + 4))
            << "i=" << i;
        ASSERT_EQ(hdr[3], (char)i) << "i=" << i;
    }
    ASSERT_EQ(q.waitread(0), SRT_VTWAIT_READY);
    ASSERT_EQ(DeliverOne(q, hdr, sizeof hdr, payload, sizeof payload, got_src, total), (int)(HDR_SIZE + 4));
    EXPECT_EQ(hdr[3], (char)201);

    EXPECT_EQ(q.waitread(0), SRT_VTWAIT_TIMEOUT);
}

// The gather adapter hands the app's plain send callback one contiguous
// datagram, byte-exact, with the destination address, and passes the
// callback's return value through.
TEST(TransportQueue, GatherAdapter)
{
    SendCapture cap;
    cap.retval = 42;
    SRTTransportQueue q(&captureSend, &cap);

    // The two blocks the SRT send callback passes: header and payload.
    const string hdr     = TestDatagram(0, 0); // 16 bytes
    const string payload = "The quick brown fox jumps over the lazy dog";

    SRT_VTBUF vec[2];
    vec[0].data = const_cast<char*>(hdr.data());
    vec[0].len  = (int)hdr.size();
    vec[1].data = const_cast<char*>(payload.data());
    vec[1].len  = (int)payload.size();

    const sockaddr_in dst = TestSource(8);
    EXPECT_EQ(q.send((sockaddr*)&dst, sizeof dst, vec, 2), 42);

    ASSERT_EQ(cap.count(), (size_t)1);
    EXPECT_EQ(cap.datagrams[0], hdr + payload);
    ExpectSource(cap.dsts[0], 8);

    // A header-only datagram gathers to just the header block.
    vec[1].data = nullptr;
    vec[1].len  = 0;
    const sockaddr_in dst2 = TestSource(9);
    EXPECT_EQ(q.send((sockaddr*)&dst2, sizeof dst2, vec, 2), 42);
    ASSERT_EQ(cap.count(), (size_t)2);
    EXPECT_EQ(cap.datagrams[1], hdr);
    ExpectSource(cap.dsts[1], 9);
}

// After detach(): push fails, waitread reports the medium broken, and the
// send callback is no longer called (quiescence); detach() itself blocks
// until an in-flight send callback returns.
TEST(TransportQueue, DetachBreaksAndQuiesces)
{
    SendCapture cap;
    SRTTransportQueue q(&captureSend, &cap);

    const sockaddr_in dst = TestSource(10);

    // A send callback that blocks until released, to check that detach()
    // waits for the in-flight callback.
    struct Blocking
    {
        mutex              mx;
        condition_variable cv;
        bool arrived = false;
        bool release = false;

        void waitArrival()
        {
            unique_lock<mutex> lk(mx);
            cv.wait(lk, [&] { return arrived; });
        }

        void letGo()
        {
            lock_guard<mutex> lk(mx);
            release = true;
            cv.notify_all();
        }
    } blk;

    auto blockingSend = [](void* opaq, const char*, int, const sockaddr*, int) {
        Blocking* b = static_cast<Blocking*>(opaq);
        {
            lock_guard<mutex> lk(b->mx);
            b->arrived = true;
            b->cv.notify_all();
        }
        unique_lock<mutex> lk(b->mx);
        b->cv.wait(lk, [&] { return b->release; });
        return 0;
    };

    SRTTransportQueue qblock(blockingSend, &blk);
    const string      hdr = TestDatagram(0, 0);

    thread sender([&] {
        SRT_VTBUF vec[1];
        vec[0].data = const_cast<char*>(hdr.data());
        vec[0].len  = (int)hdr.size();
        qblock.send((sockaddr*)&dst, sizeof dst, vec, 1);
    });
    blk.waitArrival();

    atomic<bool> detached(false);
    thread detacher([&] {
        qblock.detach();
        detached = true;
    });

    // The callback is still in flight, so detach() must not have returned.
    this_thread::sleep_for(chrono::milliseconds(200));
    EXPECT_FALSE(detached.load());

    blk.letGo();
    detacher.join();
    sender.join();
    EXPECT_TRUE(detached.load());

    // After detach: pushes fail, waitread reports broken, sends are
    // dropped without calling the callback.
    const string        dg  = TestDatagram(0, 4);
    const sockaddr_in   src = TestSource(11);
    EXPECT_EQ(q.push(dg.data(), dg.size(), (sockaddr*)&src, sizeof src), 0); // pushed before q's detach
    q.detach();
    EXPECT_EQ(q.push(dg.data(), dg.size(), (sockaddr*)&src, sizeof src), -1);
    EXPECT_EQ(q.waitread(100), SRT_VTWAIT_BROKEN);

    SRT_VTBUF vec[1];
    vec[0].data = const_cast<char*>(hdr.data());
    vec[0].len  = (int)hdr.size();
    const size_t sent_before = cap.count();
    EXPECT_EQ(q.send((sockaddr*)&dst, sizeof dst, vec, 1), -1);
    EXPECT_EQ(cap.count(), sent_before); // the callback was NOT invoked
}

// A push wakes a waitread() that is already blocked in waiting.
TEST(TransportQueue, PushWakesWaitingReader)
{
    SendCapture cap;
    SRTTransportQueue q(&captureSend, &cap);

    const sockaddr_in src = TestSource(12);

    thread reader([&] { EXPECT_EQ(q.waitread(2000), SRT_VTWAIT_READY); });

    // Give the reader time to block in the wait, then push.
    this_thread::sleep_for(chrono::milliseconds(100));
    const string dg = TestDatagram(0, 4);
    EXPECT_EQ(q.push(dg.data(), dg.size(), (sockaddr*)&src, sizeof src), 0);
    reader.join();

    // The datagram is deliverable.
    char        hdr[HDR_SIZE];
    char        payload[8];
    sockaddr_in got_src;
    size_t      total = 0;
    ASSERT_EQ(DeliverOne(q, hdr, sizeof hdr, payload, sizeof payload, got_src, total), (int)dg.size());
}

// With nothing pushed, waitread() reports a timeout after (at least) the
// requested time.
TEST(TransportQueue, WaitTimeout)
{
    SendCapture cap;
    SRTTransportQueue q(&captureSend, &cap);

    const auto start = chrono::steady_clock::now();
    EXPECT_EQ(q.waitread(120), SRT_VTWAIT_TIMEOUT);
    const auto elapsed = chrono::steady_clock::now() - start;
    EXPECT_GE(chrono::duration_cast<chrono::milliseconds>(elapsed).count(), 100);

    // A second wait after a timeout behaves the same.
    EXPECT_EQ(q.waitread(0), SRT_VTWAIT_TIMEOUT);
}

// getConfig() wires all three callbacks of the seam to the queue object,
// carries the settings, and the callbacks work through the config.
TEST(TransportQueue, GetConfigWiring)
{
    SendCapture cap;
    SRTTransportQueue q(&captureSend, &cap);

    const SRT_VirtualTransportConfig cfg = q.getConfig(2500, 1);
    EXPECT_EQ(cfg.initial_rtt_ms, 2500);
    EXPECT_EQ(cfg.skip_induction, 1);
    EXPECT_EQ(cfg.opaq, &q);
    ASSERT_NE(cfg.send, nullptr);
    ASSERT_NE(cfg.waitread, nullptr);
    ASSERT_NE(cfg.deliver, nullptr);

    // The seam callbacks drive the queue through the config, exactly what
    // srt_bind_virtual will do with it.
    const sockaddr_in src = TestSource(13);
    const string      dg  = TestDatagram(0, 4);
    ASSERT_EQ(q.push(dg.data(), dg.size(), (sockaddr*)&src, sizeof src), 0);

    EXPECT_EQ(cfg.waitread(cfg.opaq, 10), SRT_VTWAIT_READY);

    sockaddr_in got_src;
    memset(&got_src, 0, sizeof got_src);
    int srclen = sizeof got_src;

    char     hdr[HDR_SIZE];
    char     payload[8];
    SRT_VTBUF dvec[2];
    dvec[0].data = hdr;
    dvec[0].len  = sizeof hdr;
    dvec[1].data = payload;
    dvec[1].len  = sizeof payload;
    EXPECT_EQ(cfg.deliver(cfg.opaq, (sockaddr*)&got_src, &srclen, dvec, 2), (int)dg.size());
    ExpectSource(got_src, 13);

    // And the send side gathers into the app callback.
    SRT_VTBUF svec[2];
    svec[0].data = const_cast<char*>(dg.data());
    svec[0].len  = (int)HDR_SIZE;
    svec[1].data = const_cast<char*>(dg.data() + HDR_SIZE);
    svec[1].len  = (int)(dg.size() - HDR_SIZE);
    const sockaddr_in dst = TestSource(14);
    EXPECT_EQ(cfg.send(cfg.opaq, (sockaddr*)&dst, sizeof dst, svec, 2), 3); // cap.retval
    ASSERT_EQ(cap.count(), (size_t)1);
    EXPECT_EQ(cap.datagrams[0], dg);
}
