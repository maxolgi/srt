/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2026 maxolgi.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

// The microbenchmark of the send-path cost of the abstract-channel split
// (the CChannel base with CChannelUDP/CChannelVirtual under it): one
// virtual dispatch per outbound packet, against the direct call of the
// former single-class channel. Three arms, all sending the same packet
// through the same code:
// - direct: a qualified call of CChannelUDP::sendto - statically bound,
//   the exact call form of the stock path before the split (sendto was
//   a non-virtual member of the single-class CChannel), running the
//   same function body the split left untouched.
// - virtual: the same object and the same function, called through a
//   CChannel* - the form every outbound packet takes after the split.
// - vt-seam: CChannelVirtual::sendto with the minimal owner transport,
//   a send callback that copies the datagram into a sink - what the
//   virtual transport feature itself adds per packet, for context.
//
// The arm pointers are volatile, so the compiler must reload them for
// every call and cannot see the object behind them; both UDP arms pay
// the identical volatile load, so their difference is exactly the
// dispatch: a direct CALL of the qualified arm against the vtable hop
// of the base-pointer arm (a plain unqualified call through
// CChannelUDP* would not do - it is itself a virtual call, the override
// is not final).
//
// This is a print-only benchmark: the sends are checked for success, but
// the timings are only REPORTED, never asserted - they depend on the
// machine and its load, so an assertion on them could only ever flake.
// Run: test-srt --gtest_filter='*ChannelBench*'

#include "gtest/gtest.h"
#include "test_env.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

#include "srt.h"

#include "channel.h" // CChannel, CChannelUDP, CChannelVirtual
#include "common.h"  // CNetworkInterface
#include "packet.h"  // CPacket

namespace
{

// The payload of a 1500-byte-MSS SRT data packet: the 16-byte header
// (CPacket's own) plus this many payload bytes go into every sendmsg.
const size_t PAYLOAD_SIZE = 1316;

// One measurement is BLOCKS timed blocks of SENDS_PER_BLOCK sends; every
// arm is measured ROUNDS times and its best round is reported, so a
// scheduler hiccup can only worsen, never improve, a reported number.
const int BLOCKS          = 4;
const int SENDS_PER_BLOCK = 12500;
const int ROUNDS          = 3;

// The sink that publishes the accumulated send results out of the
// compiler's reach, so the send loops cannot be discarded as dead code.
volatile long long g_bench_sink = 0;

// The sink of the minimal owner transport of the vt-seam arm.
char g_vt_sink[PAYLOAD_SIZE + 64];

sockaddr_in FillV4(const char* ip, uint16_t port)
{
    sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    inet_pton(AF_INET, ip, &sa.sin_addr);
    return sa;
}

// The minimal send callback: one copy of the datagram into the sink -
// the cheapest thing a real transport's send can do.
int BenchVTSend(void*, const struct sockaddr*, int, const SRT_VTBUF* vec, int nvec)
{
    size_t off = 0;
    for (int i = 0; i < nvec; ++i)
    {
        if (vec[i].len > 0 && off + (size_t)vec[i].len <= sizeof g_vt_sink)
            memcpy(g_vt_sink + off, vec[i].data, (size_t)vec[i].len);
        off += (size_t)vec[i].len;
    }
    return (int)off;
}

// Never called in this benchmark: the vt-seam arm only sends.
SRT_VTWAIT BenchVTWaitRead(void*, int)
{
    return SRT_VTWAIT_TIMEOUT;
}

int BenchVTDeliver(void*, struct sockaddr*, int*, SRT_VTBUF*, int)
{
    return -1;
}

} // namespace

class TestChannelBench: public srt::Test
{
protected:
    void setup() override {}

    void teardown() override {}
};

TEST_F(TestChannelBench, SendtoDispatchCost)
{
    using namespace srt;
    using clock = std::chrono::steady_clock;

    // The two UDP channels of the loopback wire, bound to kernel-picked
    // ports, per the suite's no-fixed-ports discipline. The sender is
    // configured the way CMultiplexer::configure configures it.
    const CSrtMuxerConfig mcfg;
    const sockaddr_in    loopback_addr = FillV4("127.0.0.1", 0);
    const sockaddr_any   loopback((const sockaddr*)&loopback_addr, sizeof loopback_addr);

    CChannelUDP sender;
    sender.setConfig(mcfg);
    sender.open(loopback);

    CChannelUDP receiver;
    receiver.setConfig(mcfg);
    receiver.open(loopback);
    const sockaddr_any dst = receiver.getSockAddr();
    ASSERT_EQ(dst.family(), AF_INET);
    ASSERT_NE(dst.hport(), 0);

    // The packet every arm sends: the fixed 16-byte header plus a
    // 1316-byte payload, the shape of a 1500-byte-MSS SRT data packet.
    // The header fields mean nothing to sendto() - they are only
    // byte-swapped on the way through.
    CPacket packet;
    packet.allocate(PAYLOAD_SIZE);
    packet.setLength(PAYLOAD_SIZE);
    for (size_t i = 0; i < PAYLOAD_SIZE; ++i)
        packet.getData()[i] = (char)(i & 0xff);

    // The empty source interface: no ancillary data, the plain sendmsg
    // path, exactly what an unbound wildcard sender takes.
    const CNetworkInterface no_source;

    // The laundering pointers, volatile per the file header. via_udp and
    // via_base alias the same sender object; via_vt is the virtual
    // transport channel, called the way the queue calls every channel -
    // through the base.
    CChannelUDP* volatile via_udp  = &sender;
    CChannel* volatile    via_base = &sender;
    const SRT_VirtualTransportConfig vt_cfg = [] {
        SRT_VirtualTransportConfig cfg;
        memset(&cfg, 0, sizeof cfg);
        cfg.send           = &BenchVTSend;
        cfg.waitread       = &BenchVTWaitRead;
        cfg.deliver        = &BenchVTDeliver;
        cfg.opaq           = NULL;
        cfg.initial_rtt_ms = 0;
        return cfg;
    }();
    const sockaddr_in label_addr = FillV4("10.224.0.1", 5555);
    CChannelVirtual vt_channel(vt_cfg, sockaddr_any((const sockaddr*)&label_addr, sizeof label_addr), false);
    CChannel* volatile via_vt = &vt_channel;

    // The packet the drain reads into.
    CPacket drain_packet;
    drain_packet.allocate(PAYLOAD_SIZE);

    // Drains the receiver's queue; the call past the last datagram waits
    // out one 10ms select granularity (CChannelUDP::recvfrom's waiting
    // quantum). Runs strictly outside the timed regions.
    const auto drain = [&]() {
        sockaddr_any from(AF_INET);
        while (receiver.recvfrom(from, drain_packet) == RST_OK)
        {
        }
    };

    // One measurement: BLOCKS timed blocks, each SENDS_PER_BLOCK calls of
    // the given send closure, with the receiver drained after every
    // block, outside the timed region. Reports ns/packet and the number
    // of calls that did not report the full datagram size.
    struct ArmRun
    {
        double ns_per_pkt;
        int failures;
    };
    const auto measure = [&](auto&& send) {
        long long total_ns = 0;
        int failures       = 0;
        for (int b = 0; b < BLOCKS; ++b)
        {
            const clock::time_point t0 = clock::now();
            long long acc              = 0;
            for (int i = 0; i < SENDS_PER_BLOCK; ++i)
            {
                const int res = send();
                acc += res;
                if (res == -1)
                    ++failures;
            }
            const clock::time_point t1 = clock::now();
            total_ns += std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
            g_bench_sink = acc;
            drain();
        }
        return ArmRun{ double(total_ns) / (double(BLOCKS) * double(SENDS_PER_BLOCK)), failures };
    };

    double ns_direct[ROUNDS];
    double ns_virtual[ROUNDS];
    double ns_vt_seam[ROUNDS];
    int fails_direct = 0, fails_virtual = 0, fails_vt = 0;

    // Warm up every arm once (page faults, caches, branch predictors);
    // not measured.
    (void)measure([&] { return via_udp->CChannelUDP::sendto(dst, packet, no_source); });
    (void)measure([&] { return via_base->sendto(dst, packet, no_source); });
    (void)measure([&] { return via_vt->sendto(dst, packet, no_source); });

    for (int r = 0; r < ROUNDS; ++r)
    {
        const ArmRun run_direct  = measure([&] { return via_udp->CChannelUDP::sendto(dst, packet, no_source); });
        const ArmRun run_virtual = measure([&] { return via_base->sendto(dst, packet, no_source); });
        const ArmRun run_vt      = measure([&] { return via_vt->sendto(dst, packet, no_source); });
        ns_direct[r]  = run_direct.ns_per_pkt;
        ns_virtual[r] = run_virtual.ns_per_pkt;
        ns_vt_seam[r] = run_vt.ns_per_pkt;
        fails_direct += run_direct.failures;
        fails_virtual += run_virtual.failures;
        fails_vt += run_vt.failures;
    }

    const int total_sends_per_arm = ROUNDS * BLOCKS * SENDS_PER_BLOCK;

    // Correctness sanity, nothing more: every arm did real work (see the
    // file header for why the timings are not asserted). A failed send is
    // possible on a saturated loopback - a full receiver queue surfaces
    // as an error on some platforms and as a silent drop on others - so
    // the counts are reported, not asserted.
    EXPECT_GT(total_sends_per_arm - fails_direct, 0);
    EXPECT_GT(total_sends_per_arm - fails_virtual, 0);
    EXPECT_EQ(fails_vt, 0);
    EXPECT_NE(g_bench_sink, 0);

    // The best round of every arm, the numbers the report carries.
    const auto best_of = [&](const double (&ns)[ROUNDS]) {
        double b = ns[0];
        for (int r = 1; r < ROUNDS; ++r)
            if (ns[r] < b)
                b = ns[r];
        return b;
    };
    const double best_direct  = best_of(ns_direct);
    const double best_virtual = best_of(ns_virtual);
    const double best_vt_seam = best_of(ns_vt_seam);
    const double delta = best_virtual - best_direct;

    char rounds_direct[128], rounds_virtual[128], rounds_vt[128];
    snprintf(rounds_direct, sizeof rounds_direct, "%.1f / %.1f / %.1f", ns_direct[0], ns_direct[1], ns_direct[2]);
    snprintf(rounds_virtual, sizeof rounds_virtual, "%.1f / %.1f / %.1f", ns_virtual[0], ns_virtual[1], ns_virtual[2]);
    snprintf(rounds_vt, sizeof rounds_vt, "%.1f / %.1f / %.1f", ns_vt_seam[0], ns_vt_seam[1], ns_vt_seam[2]);

    std::ostringstream rep;
    rep << "\n"
        << "send-path dispatch cost, ns/packet (best of " << ROUNDS << " rounds; " << BLOCKS << " blocks x "
        << SENDS_PER_BLOCK << " sends per round)\n"
        << "  direct  (qualified call, pre-split stock form):   " << best_direct << " ns  [rounds: " << rounds_direct
        << "]\n"
        << "  virtual (CChannel* call, post-split stock path):    " << best_virtual << " ns  [rounds: " << rounds_virtual
        << "]\n"
        << "  vt-seam  (CChannelVirtual + minimal send callback): " << best_vt_seam << " ns  [rounds: " << rounds_vt
        << "]\n"
        << "  virtual - direct = " << delta << " ns ("
        << (best_direct > 0 ? 100.0 * delta / best_direct : 0.0) << "% of one sendto, itself dominated by sendmsg)\n"
        << "  failed sends of " << total_sends_per_arm << " per arm: direct=" << fails_direct
        << " virtual=" << fails_virtual << " vt-seam=" << fails_vt;
    // Printed straight to stdout: gtest does not display SUCCEED()
    // messages by default, and these numbers are the point of the test.
    std::cout << rep.str() << std::endl;
}
