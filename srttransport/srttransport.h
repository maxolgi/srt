/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2026 maxolgi.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#ifndef INC_SRT_TRANSPORT_QUEUE_H
#define INC_SRT_TRANSPORT_QUEUE_H

// This file is part of the OPTIONAL srttransport helper library (built
// only with ENABLE_VIRTUAL_TRANSPORT). It is a separate facility, not a
// part of the SRT library: it implements the push-queue "injection" model
// on top of the virtual transport callback seam declared in the public
// srt.h, so that an application owning a datagram medium (e.g. WebTransport)
// gets back the easy API. It uses no srtcore internals and calls no srt_*
// function, so nothing from libsrt is needed to use it - the callbacks are
// pure function pointers.

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
// <sys/socket.h> is fine here: this header is part of the srttransport
// helper, built only with ENABLE_VIRTUAL_TRANSPORT (Linux and Emscripten
// only, enforced in CMakeLists.txt), so POSIX definitions always exist.
#include <sys/socket.h>
#include <vector>

#include "srt.h"

namespace srt
{

/// @brief A plain contiguous-datagram send callback for the medium.
///
/// The common case: most medium APIs (e.g. WebTransport datagrams) accept
/// one contiguous buffer, so SRTTransportQueue gathers the buffer array
/// the SRT send callback receives into one block before calling this.
///
/// @param [in] opaq opaque value given to the SRTTransportQueue constructor.
/// @param [in] data the whole outgoing datagram, network byte order.
/// @param [in] len datagram size in bytes.
/// @param [in] dst destination address of the datagram.
/// @param [in] dstlen size of the address at @a dst.
/// @return The number of bytes accepted, or -1 if the datagram failed.
typedef int SRTTransportSendFunc(void* opaq, const char* data, int len, const struct sockaddr* dst, int dstlen);

/// @brief The push-queue model on top of the virtual transport seam.
///
/// The application pushes datagrams received from its medium into this
/// queue (push()) and supplies a plain contiguous send callback in the
/// constructor; getConfig() then returns an SRT_VirtualTransportConfig
/// wiring all three callbacks of the seam to this object, ready to be
/// passed to srt_bind_virtual(). Outgoing datagrams are gathered into one
/// block and handed to the send callback; incoming datagrams wait in a
/// bounded queue (the role of the kernel socket buffer of a UDP socket)
/// until the SRT receive worker picks them up.
///
/// Lifetime: the config hands this object over to SRT as the callbacks'
/// opaque value, so the object must outlive every socket bound with it.
/// All methods are thread-safe and may be called from any thread,
/// including concurrently; the class calls no SRT library function.
class SRTTransportQueue
{
public:
    /// @brief Construct the queue around a plain send callback.
    /// @param [in] send_fn callback an outgoing datagram is handed to,
    /// gathered into one contiguous block. Must not be null.
    /// @param [in] opaq opaque value passed back to @a send_fn.
    SRTTransportQueue(SRTTransportSendFunc* send_fn, void* opaq);

    ~SRTTransportQueue();

    SRTTransportQueue(const SRTTransportQueue&)            = delete;
    SRTTransportQueue& operator=(const SRTTransportQueue&) = delete;

    /// @brief Push a datagram as if received from the given source (any thread).
    ///
    /// The datagram is queued and the receiving side is woken up. Exactly
    /// one datagram per call. The queue is bounded (VT_MAX_PENDING): when
    /// full, the datagram is dropped and -1 is returned, for as long as
    /// the queue stays full - like a UDP socket dropping into a full
    /// kernel buffer; pushing succeeds again once the queue is drained.
    /// A datagram must be a whole SRT packet (at least the 16-byte header)
    /// and no larger than VT_MAX_DATAGRAM.
    ///
    /// @param [in] data the serialized datagram, network byte order.
    /// @param [in] len datagram size in bytes.
    /// @param [in] src source address to report for the datagram (may be
    /// null only when @a srclen is 0).
    /// @param [in] srclen size of the address at @a src.
    /// @return 0 on success, -1 on error (detached, storage depleted,
    /// invalid arguments).
    int push(const void* data, size_t len, const struct sockaddr* src, socklen_t srclen);

    /// An alias of push(), kept under the name the former in-core
    /// implementation used.
    int inject(const void* data, size_t len, const struct sockaddr* src, socklen_t srclen)
    {
        return push(data, len, src, srclen);
    }

    /// @brief Disable the transport (any thread).
    ///
    /// After this call push() and the send callback fail, and waitread()
    /// reports the medium as broken. Blocks until an in-flight send
    /// callback returns, so once detach() returns the application is free
    /// to release the resources the callback uses.
    void detach();

    /// @brief Get the config wiring the seam callbacks to this object.
    ///
    /// The returned config models the PUBLIC virtual transport
    /// configuration; it does not set the handshake form - the
    /// conclusion-first form is an internal srtcore setting, not part of
    /// the public API.
    ///
    /// @param [in] initial_rtt_ms initial RTT to assume for the connection
    /// (0 = disabled, otherwise 1..30000).
    /// @return The config to pass to srt_bind_virtual().
    SRT_VirtualTransportConfig getConfig(int initial_rtt_ms = 0);

    /// @brief Gather an outgoing datagram and hand it to the send callback.
    ///
    /// Implements the send side of the seam: the buffer entries are
    /// gathered into one reusable scratch block (normally two entries, the
    /// packet header block and the payload block), which is passed to the
    /// plain send callback together with the destination address.
    ///
    /// @param [in] dst destination address for the datagram.
    /// @param [in] dstlen size of the address at @a dst.
    /// @param [in] vec buffer entries of the datagram, network byte order.
    /// @param [in] nvec number of entries at @a vec.
    /// @return The value returned by the callback, or -1 if detached.
    int send(const struct sockaddr* dst, int dstlen, const SRT_VTBUF* vec, int nvec);

    /// @brief Wait for a pushed datagram to become ready (seam side).
    ///
    /// Implements the waitread callback: waits for up to @a timeout_ms
    /// milliseconds for a datagram to be deliverable. Wakes are level-kept
    /// in an internal flag, so a push arriving while the caller is between
    /// waits is never lost.
    ///
    /// @param [in] timeout_ms maximum time to wait, in milliseconds.
    /// @return SRT_VTWAIT_READY if a datagram can be picked by deliver(),
    /// SRT_VTWAIT_TIMEOUT if none arrived in time, SRT_VTWAIT_BROKEN if
    /// detached.
    SRT_VTWAIT waitread(int timeout_ms);

    /// @brief Pick up the earliest pushed datagram (seam side).
    ///
    /// Implements the deliver callback: copies the earliest queued
    /// datagram into the provided buffer entries, the header block first
    /// and the remainder into the next buffers, and its source address
    /// into @a w_src. Like a datagram too big for the receiving unit on a
    /// UDP socket, a datagram that does not fit the entries is discarded.
    ///
    /// @param [out] w_src buffer for the source address of the datagram.
    /// @param [in,out] w_srclen capacity of @a w_src on entry, the number
    /// of bytes written on return.
    /// @param [out] w_vec buffer entries to scatter the datagram into.
    /// @param [in] nvec number of entries at @a w_vec.
    /// @return The total number of bytes written, or -1 on error (nothing
    /// queued, datagram discarded).
    int deliver(struct sockaddr* w_src, int* w_srclen, SRT_VTBUF* w_vec, int nvec);

private:
    // Static trampolines for SRT_VirtualTransportConfig: the config's
    // opaque value is this object.
    static int    stubSend(void* opaq, const struct sockaddr* dst, int dstlen, const SRT_VTBUF* vec, int nvec);
    static SRT_VTWAIT stubWaitRead(void* opaq, int timeout_ms);
    static int    stubDeliver(void* opaq, struct sockaddr* w_src, int* w_srclen, SRT_VTBUF* w_vec, int nvec);

    struct Datagram
    {
        std::vector<char>      data;
        struct sockaddr_storage src;
        socklen_t              srclen;
    };

    SRTTransportSendFunc* const m_SendFn;
    void* const                 m_Opaq;

    std::mutex      m_SendLock; // serializes send callback invocations, protects the members below
    bool            m_bSendActive;
    std::vector<char> m_SendScratch; // gather area for the send callback, reused across calls

    std::mutex          m_QueueLock; // protects the members below
    std::deque<Datagram> m_Queue;
    bool                m_bDetached;

    // Wake primitive for the receiving side. The persistent m_bWoken flag
    // mirrors a level-kept signal: raised before the notification, drained
    // by the waiter, so a wake that arrives while the waiter is between
    // waits is never lost.
    std::mutex              m_WakeMutex;
    std::condition_variable m_WakeCV;
    bool                    m_bWoken;
};

} // namespace srt

#endif // INC_SRT_TRANSPORT_QUEUE_H
