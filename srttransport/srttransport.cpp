/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2026 maxolgi.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#include "srttransport.h"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace srt
{

// Bound on the number of datagrams pending reception. This takes the role
// of the kernel socket buffer of a UDP socket; when full, pushed datagrams
// are dropped, like UDP would do.
static const size_t VT_MAX_PENDING = 1024;

// Sanity bound for the size of a single pushed datagram.
static const size_t VT_MAX_DATAGRAM = 65536;

// The SRT packet header size, in bytes. Not exposed in the public
// headers, so restated here (srtcore's CPacket::HDR_SIZE): a pushed
// datagram must carry at least this much to be a whole SRT packet.
static const size_t SRT_PACKET_HDR_SIZE = 16;

SRTTransportQueue::SRTTransportQueue(SRTTransportSendFunc* send_fn, void* opaq)
    : m_SendFn(send_fn)
    , m_Opaq(opaq)
    , m_bSendActive(true)
    , m_bDetached(false)
    , m_bWoken(false)
{
}

SRTTransportQueue::~SRTTransportQueue() {}

int SRTTransportQueue::push(const void* data, size_t len, const struct sockaddr* src, socklen_t srclen)
{
    if (!data || len < SRT_PACKET_HDR_SIZE || len > VT_MAX_DATAGRAM)
        return -1;

    if ((src == nullptr) != (srclen == 0) || srclen > sizeof(struct sockaddr_storage))
        return -1;

    std::lock_guard<std::mutex> lk(m_QueueLock);

    if (m_bDetached)
        return -1;

    if (m_Queue.size() >= VT_MAX_PENDING)
        return -1;

    Datagram dg;
    dg.data.assign(static_cast<const char*>(data), static_cast<const char*>(data) + len);
    if (srclen)
    {
        memcpy(&dg.src, src, srclen);
        dg.srclen = srclen;
    }
    else
        dg.srclen = 0;
    m_Queue.push_back(std::move(dg));

    // Wake up the receiving side. The flag is raised under the wake mutex
    // before the notification so that a wake arriving while the waiter is
    // between waits stays set and can never be lost. notify_all, not
    // notify_one: every waiter must be sent to the queue check, since
    // with a condition variable there is no level-kept signal that would
    // keep a later wait from blocking.
    {
        std::lock_guard<std::mutex> wlk(m_WakeMutex);
        m_bWoken = true;
    }
    m_WakeCV.notify_all();
    return 0;
}

void SRTTransportQueue::detach()
{
    {
        // Wait for a possible in-flight send callback to return before
        // the application considers the callback resources freed.
        std::lock_guard<std::mutex> lk(m_SendLock);
        m_bSendActive = false;
    }

    std::lock_guard<std::mutex> lk(m_QueueLock);
    m_bDetached = true;

    // Release a possible waiter promptly - it must report BROKEN now, not
    // after its timeout expires.
    {
        std::lock_guard<std::mutex> wlk(m_WakeMutex);
        m_bWoken = true;
    }
    m_WakeCV.notify_all();
}

SRT_VirtualTransportConfig SRTTransportQueue::getConfig(int initial_rtt_ms, int skip_induction)
{
    SRT_VirtualTransportConfig cfg;
    cfg.send           = &SRTTransportQueue::stubSend;
    cfg.waitread       = &SRTTransportQueue::stubWaitRead;
    cfg.deliver        = &SRTTransportQueue::stubDeliver;
    cfg.opaq           = this;
    cfg.initial_rtt_ms = initial_rtt_ms;
    cfg.skip_induction = skip_induction;
    return cfg;
}

int SRTTransportQueue::send(const struct sockaddr* dst, int dstlen, const SRT_VTBUF* vec, int nvec)
{
    if (!dst || !vec || nvec < 0)
        return -1;

    std::lock_guard<std::mutex> lk(m_SendLock);

    if (!m_bSendActive)
        return -1;

    // Gather the entries into one contiguous datagram for the callback.
    // The scratch buffer is only reallocated when a larger datagram is
    // sent; m_SendLock held above serializes the calls, so reusing it
    // needs no further protection.
    size_t len = 0;
    for (int i = 0; i < nvec; ++i)
    {
        if (vec[i].len < 0)
            return -1;
        len += (size_t)vec[i].len;
    }

    m_SendScratch.resize(len);
    size_t offset = 0;
    for (int i = 0; i < nvec; ++i)
    {
        if (vec[i].len)
            memcpy(m_SendScratch.data() + offset, vec[i].data, (size_t)vec[i].len);
        offset += (size_t)vec[i].len;
    }

    return m_SendFn(m_Opaq, m_SendScratch.data(), (int)len, dst, dstlen);
}

SRT_VTWAIT SRTTransportQueue::waitread(int timeout_ms)
{
    {
        std::lock_guard<std::mutex> lk(m_QueueLock);
        if (m_bDetached)
            return SRT_VTWAIT_BROKEN;
    }

    // Wait for a pushed datagram, up to the given timeout. The persistent
    // woken flag mirrors a level-kept signal: set by push() before the
    // notification and drained here, so a wake is never lost.
    std::unique_lock<std::mutex> wlk(m_WakeMutex);
    if (!m_bWoken)
        m_WakeCV.wait_for(wlk, std::chrono::milliseconds(timeout_ms));

    if (!m_bWoken) // timed out and still no wake
        return SRT_VTWAIT_TIMEOUT;

    m_bWoken = false;
    return SRT_VTWAIT_READY;
}

int SRTTransportQueue::deliver(struct sockaddr* w_src, int* w_srclen, SRT_VTBUF* w_vec, int nvec)
{
    if (!w_src || !w_srclen || !w_vec || nvec <= 0)
        return -1;

    Datagram dg;
    {
        std::lock_guard<std::mutex> lk(m_QueueLock);
        if (m_Queue.empty())
        {
            // Spurious wakeup, nothing to deliver.
            return -1;
        }

        dg = std::move(m_Queue.front());
        m_Queue.pop_front();
        if (!m_Queue.empty())
        {
            // Signal again so that the receiving side keeps picking up the
            // remaining datagrams without waiting for the timeout.
            {
                std::lock_guard<std::mutex> wlk(m_WakeMutex);
                m_bWoken = true;
            }
            m_WakeCV.notify_all();
        }
    }

    // Scatter the datagram over the caller's buffer entries, the header
    // block first, the remainder into the next buffers - the way recvmsg
    // scatters a datagram.
    //
    // dg.data.data() + offset is also used with offset == dg.data.size()
    // and a zero copy length (a header-only datagram): pointer arithmetic
    // through data() is well-defined there, and memcpy of zero bytes from
    // the one-past-the-end pointer is legal (unlike &dg.data[offset],
    // which would be out of bounds).
    size_t remaining = dg.data.size();
    size_t offset    = 0;
    for (int i = 0; i < nvec && remaining > 0; ++i)
    {
        const size_t n = std::min(remaining, (size_t)(w_vec[i].len > 0 ? w_vec[i].len : 0));
        if (n)
            memcpy(w_vec[i].data, dg.data.data() + offset, n);
        offset += n;
        remaining -= n;
    }

    if (remaining)
    {
        // Doesn't fit into the entries - a UDP socket would report
        // MSG_TRUNC for it and the packet would be dropped.
        return -1;
    }

    if (dg.srclen)
    {
        const size_t n = std::min(*w_srclen > 0 ? (size_t)*w_srclen : (size_t)0, (size_t)dg.srclen);
        memcpy(w_src, &dg.src, n);
        *w_srclen = (int)n;
    }
    else
        *w_srclen = 0;

    return (int)dg.data.size();
}

int SRTTransportQueue::stubSend(void* opaq, const struct sockaddr* dst, int dstlen, const SRT_VTBUF* vec, int nvec)
{
    return static_cast<SRTTransportQueue*>(opaq)->send(dst, dstlen, vec, nvec);
}

SRT_VTWAIT SRTTransportQueue::stubWaitRead(void* opaq, int timeout_ms)
{
    return static_cast<SRTTransportQueue*>(opaq)->waitread(timeout_ms);
}

int SRTTransportQueue::stubDeliver(void* opaq, struct sockaddr* w_src, int* w_srclen, SRT_VTBUF* w_vec, int nvec)
{
    return static_cast<SRTTransportQueue*>(opaq)->deliver(w_src, w_srclen, w_vec, nvec);
}

} // namespace srt
