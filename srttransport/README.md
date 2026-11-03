# srttransport

An optional owner-side helper for the SRT [virtual transport](../docs/API/API-functions.md#srt_bind_virtual):
a push queue that implements the three callbacks of
`SRT_VirtualTransportConfig`, so that an application owning a datagram medium
(for example WebTransport) gets back an easy push API instead of writing the
`send`/`waitread`/`deliver` callback contract by hand.

The helper is built as a static library together with
`-DENABLE_VIRTUAL_TRANSPORT=ON` and is NOT part of the SRT library proper: it
uses only the public types from `srt.h`, calls no `srt_*` function, and needs
nothing from `libsrt` to be linked against it. Being outside of srtcore, it is
also free of srtcore's portability constraints (C++98 compatibility, the
`srt::sync` wrappers) and may use the standard C++ library directly.

## Usage

```cpp
#include <srt/srt.h>
#include "srttransport.h"

// 1. A plain send callback: the medium accepts one contiguous buffer.
int MySend(void* opaq, const char* data, int len,
           const struct sockaddr* dst, int dstlen)
{
    MyMedium* medium = (MyMedium*)opaq;
    return medium->sendDatagram(data, len);  // bytes accepted, or -1 to drop
}

// 2. Create the queue around the callback, and bind a socket with its config.
srt::SRTTransportQueue queue(&MySend, &medium);
SRTSOCKET sock = srt_create_socket();
SRT_VirtualTransportConfig cfg = queue.getConfig(/*initial_rtt_ms=*/0,
                                                 /*skip_induction=*/1);
sockaddr_in label = ...;                    // only a label, nothing OS-bound
srt_bind_virtual(sock, (sockaddr*)&label, sizeof label, &cfg);
srt_listen(sock, 5);                        // or srt_connect(sock, ...)

// 3. Push every datagram the medium receives; SRT picks them up.
//    (any thread; exactly one datagram per call)
queue.push(datagram, len, (sockaddr*)&src, sizeof src);

// 4. On shutdown, break the transport and wait for in-flight sends.
srt_close(sock);
queue.detach();
```

Notes:

* The queue is bounded: when full, `push()` drops the datagram and returns -1,
  like a UDP socket dropping into a full kernel buffer.
* `detach()` makes `push()` and the send callback fail and makes the SRT side
  see a broken medium; it blocks until an in-flight send callback returns.
* The object must outlive every socket bound with its config - the config
  passes the object to SRT as the callbacks' opaque value.

See `srttransport.h` for the complete reference.
