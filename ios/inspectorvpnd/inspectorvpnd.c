/*
 * inspectorvpnd - answers libnetguard application discovery queries for the App Store
 * build of InspectorVpn on jailbroken iOS.
 *
 * libnetguard (eu.faircode.netguard.ServiceSinkhole) sends a UDP query for every new TCP
 * connection to the remote address of the tunnel connection, i.e. the local address and
 * port of the InspectorVpnTunnel extension's TCP socket on the device. The extension does
 * not listen there, so this daemon finds that socket and binds a UDP socket to the same
 * address and port (UDP and TCP port spaces are separate), then answers each query with
 * the process that owns the connection.
 *
 * Connection ownership comes from the NetworkStatistics kernel control
 * (com.apple.network.statistics). It covers kernel sockets as well as user space (Skywalk)
 * TCP flows, and reports the effective process of delegated flows (for example Safari for
 * a connection made by com.apple.WebKit.Networking).
 *
 * Query (eu.faircode.netguard.Packet#sendAllowed, Java DataOutput encoding):
 *   u8 0x1, u8 protocol, UTF saddr, u16 sport, UTF daddr, u16 dport
 *
 * Response (decoded by eu.faircode.netguard.ApplicationDiscoveryResponse):
 *   u8 0x3, u8 protocol, UTF saddr, u16 sport, UTF daddr, u16 dport,
 *   Process owner, bool delegated, [Process delegate]
 * Process:
 *   i32 pid, UTF processName, UTF executablePath, bool bundle,
 *   [UTF CFBundleIdentifier, OptUTF CFBundleDisplayName, OptUTF CFBundleName,
 *    OptUTF CFBundleShortVersionString, OptUTF CFBundleVersion]
 * OptUTF: bool present, [UTF value]
 *
 * The owner is the effective process of the flow; when it differs from the process that
 * holds the socket, the holder is sent as the delegate. A flow delegated by executable UUID
 * only is attributed to the running process with that executable.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioccom.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define EXTENSION_BUNDLE_ID "com.github.zhkl0228.inspector.vpn.extension"
#define SCAN_INTERVAL_MS 200
#define MAX_DATAGRAM 65507
#define MAX_BINDINGS 16
#define EXTENSION_CACHE_SIZE 256

#define QUERY_TYPE 0x1
#define RESPONSE_TYPE 0x3
#define IPPROTO_TCP_VALUE 6

/* ---- Private declarations that the iOS SDK does not ship (copied from XNU) ---- */

/* <sys/sys_domain.h>, <sys/kern_control.h> */
#define SYSPROTO_CONTROL 2
#define AF_SYS_CONTROL 2
#define MAX_KCTL_NAME 96
struct ctl_info {
    uint32_t ctl_id;
    char ctl_name[MAX_KCTL_NAME];
};
struct sockaddr_ctl {
    u_char sc_len;
    u_char sc_family;
    uint16_t ss_sysaddr;
    uint32_t sc_id;
    uint32_t sc_unit;
    uint32_t sc_reserved[5];
};
#define CTLIOCGINFO _IOWR('N', 3, struct ctl_info)

/* <libproc.h>, <sys/proc_info.h>, <sys/proc_info_private.h> */
#define PROC_PIDPATHINFO_MAXSIZE (4 * MAXPATHLEN)
#define PROC_PIDUNIQIDENTIFIERINFO 17
struct proc_uniqidentifierinfo {
    uint8_t p_uuid[16];
    uint64_t p_uniqueid;
    uint64_t p_puniqueid;
    int32_t p_idversion;
    int32_t p_orig_ppidversion;
    uint64_t p_reserve2;
    uint64_t p_reserve3;
};
int proc_listallpids(void *buffer, int buffersize);
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
int proc_name(int pid, void *buffer, uint32_t buffersize);

/* <netinet/tcp_fsm.h> */
#define TCPS_ESTABLISHED 4

/* <net/ntstat.h> */
#define NSTAT_CONTROL_NAME "com.apple.network.statistics"
#define NSTAT_PROVIDER_TCP_KERNEL 2
#define NSTAT_PROVIDER_TCP_USERLAND 3
#define NSTAT_MSG_TYPE_SUCCESS 0
#define NSTAT_MSG_TYPE_ERROR 1
#define NSTAT_MSG_TYPE_ADD_ALL_SRCS 1002
#define NSTAT_MSG_TYPE_GET_SRC_DESC 1005
#define NSTAT_MSG_TYPE_SRC_ADDED 10001
#define NSTAT_MSG_TYPE_SRC_REMOVED 10002
#define NSTAT_MSG_TYPE_SRC_DESC 10003
#define NSTAT_MSG_TYPE_SRC_COUNTS 10004
#define NSTAT_MSG_HDR_FLAG_SUPPORTS_AGGREGATE (1 << 0)
#define NSTAT_MSG_HDR_FLAG_CONTINUATION (1 << 1)
#define NSTAT_MSG_HDR_FLAG_CLOSING (1 << 2)
#define NSTAT_MSG_SRC_REMOVED_LENGTH 24
#define NSTAT_MSG_SRC_COUNTS_LENGTH 144
#define NSTAT_SRC_REF_ALL 0xffffffffffffffffULL

typedef struct {
    uint64_t context __attribute__((aligned(8)));
    uint32_t type;
    uint16_t length;
    uint16_t flags;
} nstat_msg_hdr;

typedef struct {
    nstat_msg_hdr hdr;
    uint64_t filter __attribute__((aligned(8)));
    uint64_t events __attribute__((aligned(8)));
    uint32_t provider;
    int32_t target_pid;
    uint8_t target_uuid[16];
} nstat_msg_add_all_srcs;

typedef struct {
    nstat_msg_hdr hdr;
    uint64_t srcref __attribute__((aligned(8)));
} nstat_msg_get_src_description;

typedef struct {
    nstat_msg_hdr hdr;
    uint32_t error;
    uint8_t reserved[4];
} nstat_msg_error;

typedef struct {
    nstat_msg_hdr hdr;
    uint64_t srcref __attribute__((aligned(8)));
    uint32_t provider;
    uint8_t reserved[4];
} nstat_msg_src_added;

typedef struct {
    nstat_msg_hdr hdr;
    uint64_t srcref __attribute__((aligned(8)));
    uint64_t event_flags __attribute__((aligned(8)));
    uint32_t provider;
    uint8_t reserved[4];
} nstat_msg_src_description_header;

typedef struct {
    uint64_t start;
    uint64_t bitmap[2];
} activity_bitmap_t;

typedef struct {
    uint64_t upid __attribute__((aligned(8)));
    uint64_t eupid __attribute__((aligned(8)));
    uint64_t start_timestamp __attribute__((aligned(8)));
    uint64_t timestamp __attribute__((aligned(8)));
    uint64_t rx_transfer_size __attribute__((aligned(8)));
    uint64_t tx_transfer_size __attribute__((aligned(8)));
    activity_bitmap_t activity_bitmap;
    uint32_t ifindex;
    uint32_t state;
    uint32_t sndbufsize;
    uint32_t sndbufused;
    uint32_t rcvbufsize;
    uint32_t rcvbufused;
    uint32_t txunacked;
    uint32_t txwindow;
    uint32_t txcwindow;
    uint32_t traffic_class;
    uint32_t traffic_mgt_flags;
    uint32_t pid;
    uint32_t epid;
    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } local;
    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } remote;
    char cc_algo[16];
    char pname[64];
    uint8_t uuid[16];
    uint8_t euuid[16];
    uint8_t vuuid[16];
    uint8_t fuuid[16];
    uid_t persona_id;
    uid_t uid;
    uint8_t connstatus[4];
    uint32_t ifnet_properties __attribute__((aligned(4)));
    uint8_t fallback_mode;
    uint8_t reserved[3];
} nstat_tcp_descriptor;

_Static_assert(sizeof(nstat_msg_hdr) == 16, "nstat_msg_hdr");
_Static_assert(sizeof(nstat_msg_add_all_srcs) == 56, "nstat_msg_add_all_srcs");
_Static_assert(sizeof(nstat_msg_get_src_description) == 24, "nstat_msg_get_src_description");
_Static_assert(sizeof(nstat_msg_error) == 24, "nstat_msg_error");
_Static_assert(sizeof(nstat_msg_src_added) == 32, "nstat_msg_src_added");
_Static_assert(sizeof(nstat_msg_src_description_header) == 40, "nstat_msg_src_description_header");
_Static_assert(sizeof(nstat_tcp_descriptor) == 344, "nstat_tcp_descriptor");
_Static_assert(offsetof(nstat_tcp_descriptor, state) == 76, "nstat_tcp_descriptor.state");
_Static_assert(offsetof(nstat_tcp_descriptor, pid) == 116, "nstat_tcp_descriptor.pid");
_Static_assert(offsetof(nstat_tcp_descriptor, local) == 124, "nstat_tcp_descriptor.local");
_Static_assert(offsetof(nstat_tcp_descriptor, remote) == 152, "nstat_tcp_descriptor.remote");
_Static_assert(offsetof(nstat_tcp_descriptor, pname) == 196, "nstat_tcp_descriptor.pname");
_Static_assert(offsetof(nstat_tcp_descriptor, uuid) == 260, "nstat_tcp_descriptor.uuid");
_Static_assert(offsetof(nstat_tcp_descriptor, euuid) == 276, "nstat_tcp_descriptor.euuid");
_Static_assert(sizeof(struct proc_uniqidentifierinfo) == 56, "proc_uniqidentifierinfo");

/* ---- Logging ---- */

static bool verbose;

static void log_line(const char *level, const char *fmt, va_list ap) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(stderr, "%s.%03d %s ", ts, (int) (tv.tv_usec / 1000), level);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

#define DEFINE_LOG(name, level, enabled)                                        \
    static void name(const char *fmt, ...) __attribute__((format(printf, 1, 2))); \
    static void name(const char *fmt, ...) {                                    \
        if (!(enabled)) {                                                       \
            return;                                                             \
        }                                                                       \
        va_list ap;                                                             \
        va_start(ap, fmt);                                                      \
        log_line(level, fmt, ap);                                               \
        va_end(ap);                                                             \
    }

DEFINE_LOG(log_debug, "DEBUG", verbose)
DEFINE_LOG(log_info, "INFO", true)
DEFINE_LOG(log_warn, "WARN", true)
DEFINE_LOG(log_error, "ERROR", true)

/* Returns a malloc'ed lowercase hex string of the bytes. */
static char *hex_alloc(const void *data, size_t len) {
    static const char digits[] = "0123456789abcdef";
    const uint8_t *p = data;
    char *out = malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = digits[p[i] >> 4];
        out[i * 2 + 1] = digits[p[i] & 0xf];
    }
    out[len * 2] = '\0';
    return out;
}

static void format_uuid(const uint8_t uuid[16], char out[37]) {
    snprintf(out, 37, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
             uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}

/* ---- NetworkStatistics client ---- */

struct flow {
    uint32_t provider;
    nstat_tcp_descriptor desc;
};

static int nstat_fd = -1;
static uint64_t nstat_context;
static uint64_t nstat_buf[512 * 1024 / sizeof(uint64_t)];
static struct flow *flows;
static size_t flow_count;
static size_t flow_capacity;

static void log_nstat_message(const char *what, const nstat_msg_hdr *hdr, size_t available) {
    size_t len = hdr->length < available ? hdr->length : available;
    char *h = hex_alloc(hdr, len);
    log_error("%s: type=%u length=%u context=%llu flags=0x%x hex=%s", what, hdr->type, hdr->length,
              (unsigned long long) hdr->context, hdr->flags, h);
    free(h);
}

/*
 * Messages that are not replies to our requests. The kernel announces every new TCP source with
 * SRC_ADDED, and every closed one with SRC_COUNTS and SRC_DESC flagged CLOSING followed by SRC_REMOVED.
 */
static void nstat_async(const nstat_msg_hdr *hdr) {
    if (hdr->context == 0 &&
        ((hdr->type == NSTAT_MSG_TYPE_SRC_ADDED && hdr->flags == 0 && hdr->length == sizeof(nstat_msg_src_added)) ||
         (hdr->type == NSTAT_MSG_TYPE_SRC_COUNTS && hdr->flags == NSTAT_MSG_HDR_FLAG_CLOSING &&
          hdr->length == NSTAT_MSG_SRC_COUNTS_LENGTH) ||
         (hdr->type == NSTAT_MSG_TYPE_SRC_DESC && hdr->flags == NSTAT_MSG_HDR_FLAG_CLOSING &&
          hdr->length == sizeof(nstat_msg_src_description_header) + sizeof(nstat_tcp_descriptor)) ||
         (hdr->type == NSTAT_MSG_TYPE_SRC_REMOVED && hdr->flags == 0 &&
          hdr->length == NSTAT_MSG_SRC_REMOVED_LENGTH))) {
        return;
    }
    char *h = hex_alloc(hdr, hdr->length);
    log_warn("Unexpected NStat message: type=%u length=%u context=%llu flags=0x%x hex=%s", hdr->type, hdr->length,
             (unsigned long long) hdr->context, hdr->flags, h);
    free(h);
}

static bool collect_flow(const nstat_msg_hdr *hdr) {
    if (hdr->length != sizeof(nstat_msg_src_description_header) + sizeof(nstat_tcp_descriptor)) {
        log_nstat_message("Unexpected NStat source description length", hdr, hdr->length);
        return false;
    }
    const nstat_msg_src_description_header *msg = (const nstat_msg_src_description_header *) hdr;
    if (msg->provider != NSTAT_PROVIDER_TCP_KERNEL && msg->provider != NSTAT_PROVIDER_TCP_USERLAND) {
        log_nstat_message("NStat source description from unsubscribed provider", hdr, hdr->length);
        return false;
    }
    if (flow_count == flow_capacity) {
        flow_capacity = flow_capacity == 0 ? 256 : flow_capacity * 2;
        flows = realloc(flows, flow_capacity * sizeof(struct flow));
    }
    flows[flow_count].provider = msg->provider;
    memcpy(&flows[flow_count].desc, (const uint8_t *) hdr + sizeof(*msg), sizeof(nstat_tcp_descriptor));
    flow_count++;
    return true;
}

static bool nstat_send(const void *msg, size_t len) {
    ssize_t n = send(nstat_fd, msg, len, 0);
    if (n != (ssize_t) len) {
        log_error("NStat send type=%u failed: ret=%zd errno=%d (%s)", ((const nstat_msg_hdr *) msg)->type, n, errno,
                  strerror(errno));
        return false;
    }
    return true;
}

/*
 * Reads until the SUCCESS or ERROR reply for `context`. Source descriptions for the context are
 * collected into `flows` when `descriptions` is set. A datagram may aggregate several messages.
 */
static bool nstat_wait(uint64_t context, bool descriptions, uint16_t *success_flags) {
    for (;;) {
        ssize_t n = recv(nstat_fd, nstat_buf, sizeof(nstat_buf), 0);
        if (n <= 0) {
            log_error("NStat recv for context=%llu failed: ret=%zd errno=%d (%s)", (unsigned long long) context, n,
                      errno, strerror(errno));
            return false;
        }
        const uint8_t *buf = (const uint8_t *) nstat_buf;
        bool done = false;
        bool ok = true;
        size_t off = 0;
        while (off < (size_t) n) {
            const nstat_msg_hdr *hdr = (const nstat_msg_hdr *) (buf + off);
            size_t available = (size_t) n - off;
            if (available < sizeof(nstat_msg_hdr) || hdr->length < sizeof(nstat_msg_hdr) || hdr->length > available ||
                hdr->length % 8 != 0) {
                char *h = hex_alloc(buf + off, available);
                log_error("Malformed NStat datagram at offset %zu of %zd: hex=%s", off, n, h);
                free(h);
                return false;
            }
            if (descriptions && hdr->type == NSTAT_MSG_TYPE_SRC_DESC && hdr->context == 0 && hdr->flags == 0) {
                /*
                 * nstat_client_append_description() leaves the context and flags of the descriptions
                 * it aggregates zeroed; only the closing SUCCESS carries the context of the poll.
                 * Descriptions of closed sources arrive with the same zero context but flagged CLOSING.
                 */
                if (!collect_flow(hdr)) {
                    return false;
                }
            } else if (hdr->context != context) {
                nstat_async(hdr);
            } else if (hdr->type == NSTAT_MSG_TYPE_SUCCESS && hdr->length == sizeof(nstat_msg_hdr)) {
                *success_flags = hdr->flags;
                done = true;
            } else if (hdr->type == NSTAT_MSG_TYPE_ERROR && hdr->length == sizeof(nstat_msg_error)) {
                uint32_t error = ((const nstat_msg_error *) hdr)->error;
                log_error("NStat request context=%llu failed: errno=%u (%s)", (unsigned long long) context, error,
                          strerror((int) error));
                ok = false;
                done = true;
            } else {
                log_nstat_message("Unexpected NStat reply", hdr, available);
                return false;
            }
            off += hdr->length;
        }
        if (done) {
            return ok;
        }
    }
}

static bool nstat_open(void) {
    nstat_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (nstat_fd < 0) {
        log_error("NStat socket failed: errno=%d (%s)", errno, strerror(errno));
        return false;
    }
    struct ctl_info info;
    memset(&info, 0, sizeof(info));
    strlcpy(info.ctl_name, NSTAT_CONTROL_NAME, sizeof(info.ctl_name));
    if (ioctl(nstat_fd, CTLIOCGINFO, &info) != 0) {
        log_error("CTLIOCGINFO %s failed: errno=%d (%s)", NSTAT_CONTROL_NAME, errno, strerror(errno));
        return false;
    }
    struct sockaddr_ctl addr;
    memset(&addr, 0, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = info.ctl_id;
    if (connect(nstat_fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        log_error("NStat connect failed: errno=%d (%s)", errno, strerror(errno));
        return false;
    }
    int rcvbuf = 4 * 1024 * 1024;
    if (setsockopt(nstat_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) != 0) {
        log_error("NStat SO_RCVBUF failed: errno=%d (%s)", errno, strerror(errno));
        return false;
    }
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    if (setsockopt(nstat_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        log_error("NStat SO_RCVTIMEO failed: errno=%d (%s)", errno, strerror(errno));
        return false;
    }
    const uint32_t providers[] = {NSTAT_PROVIDER_TCP_KERNEL, NSTAT_PROVIDER_TCP_USERLAND};
    for (size_t i = 0; i < sizeof(providers) / sizeof(providers[0]); i++) {
        nstat_msg_add_all_srcs req;
        memset(&req, 0, sizeof(req));
        req.hdr.context = ++nstat_context;
        req.hdr.type = NSTAT_MSG_TYPE_ADD_ALL_SRCS;
        req.hdr.length = sizeof(req);
        req.hdr.flags = NSTAT_MSG_HDR_FLAG_SUPPORTS_AGGREGATE;
        req.provider = providers[i];
        uint16_t flags = 0;
        if (!nstat_send(&req, sizeof(req)) || !nstat_wait(req.hdr.context, false, &flags)) {
            log_error("Subscribing to NStat provider %u failed", providers[i]);
            return false;
        }
    }
    return true;
}

/* Reads every TCP flow into `flows`, following the kernel's continuation pacing. */
static bool nstat_snapshot(void) {
    flow_count = 0;
    nstat_msg_get_src_description req;
    memset(&req, 0, sizeof(req));
    req.hdr.context = ++nstat_context;
    req.hdr.type = NSTAT_MSG_TYPE_GET_SRC_DESC;
    req.hdr.length = sizeof(req);
    req.hdr.flags = NSTAT_MSG_HDR_FLAG_SUPPORTS_AGGREGATE | NSTAT_MSG_HDR_FLAG_CONTINUATION;
    req.srcref = NSTAT_SRC_REF_ALL;
    for (;;) {
        uint16_t flags = 0;
        if (!nstat_send(&req, sizeof(req)) || !nstat_wait(req.hdr.context, true, &flags)) {
            return false;
        }
        if ((flags & NSTAT_MSG_HDR_FLAG_CONTINUATION) == 0) {
            return true;
        }
    }
}

/* Consumes kernel announcements that arrive between requests. */
static bool nstat_drain(void) {
    for (;;) {
        ssize_t n = recv(nstat_fd, nstat_buf, sizeof(nstat_buf), MSG_DONTWAIT);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return true;
        }
        if (n <= 0) {
            log_error("NStat recv failed: ret=%zd errno=%d (%s)", n, errno, strerror(errno));
            return false;
        }
        const uint8_t *buf = (const uint8_t *) nstat_buf;
        size_t off = 0;
        while (off < (size_t) n) {
            const nstat_msg_hdr *hdr = (const nstat_msg_hdr *) (buf + off);
            size_t available = (size_t) n - off;
            if (available < sizeof(nstat_msg_hdr) || hdr->length < sizeof(nstat_msg_hdr) || hdr->length > available ||
                hdr->length % 8 != 0) {
                char *h = hex_alloc(buf + off, available);
                log_error("Malformed NStat datagram at offset %zu of %zd: hex=%s", off, n, h);
                free(h);
                return false;
            }
            nstat_async(hdr);
            off += hdr->length;
        }
    }
}

/* ---- Process identity ---- */

struct process_info {
    pid_t pid;
    char name[64];
    char path[PROC_PIDPATHINFO_MAXSIZE];
    bool bundle;
    CFStringRef bundle_identifier;
    CFStringRef bundle_display_name;
    CFStringRef bundle_name;
    CFStringRef short_version_string;
    CFStringRef bundle_version;
};

static void process_info_release(struct process_info *p) {
    CFStringRef *fields[] = {&p->bundle_identifier, &p->bundle_display_name, &p->bundle_name,
                             &p->short_version_string, &p->bundle_version};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        if (*fields[i] != NULL) {
            CFRelease(*fields[i]);
            *fields[i] = NULL;
        }
    }
}

static char *cfstring_alloc(CFStringRef s) {
    CFIndex size = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
    char *out = malloc((size_t) size);
    CFStringGetCString(s, out, size, kCFStringEncodingUTF8);
    return out;
}

/* Reads an optional string value; a present value of another type is an error. */
static bool plist_string(CFDictionaryRef dict, const char *key, const char *plist_path, bool required,
                         CFStringRef *out) {
    CFStringRef cfkey = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    CFTypeRef value = CFDictionaryGetValue(dict, cfkey);
    CFRelease(cfkey);
    if (value == NULL) {
        if (required) {
            log_error("%s has no %s", plist_path, key);
            return false;
        }
        *out = NULL;
        return true;
    }
    if (CFGetTypeID(value) != CFStringGetTypeID()) {
        CFStringRef desc = CFCopyDescription(value);
        char *d = cfstring_alloc(desc);
        log_error("%s: %s is not a string: %s", plist_path, key, d);
        free(d);
        CFRelease(desc);
        return false;
    }
    *out = CFRetain(value);
    return true;
}

static CFDictionaryRef read_plist(const char *plist_path) {
    int fd = open(plist_path, O_RDONLY);
    if (fd < 0) {
        log_error("Open %s failed: errno=%d (%s)", plist_path, errno, strerror(errno));
        return NULL;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        log_error("Stat %s failed: errno=%d (%s)", plist_path, errno, strerror(errno));
        close(fd);
        return NULL;
    }
    uint8_t *bytes = malloc((size_t) st.st_size);
    ssize_t n = read(fd, bytes, (size_t) st.st_size);
    int read_errno = errno;
    close(fd);
    if (n != st.st_size) {
        log_error("Read %s failed: ret=%zd of %lld errno=%d (%s)", plist_path, n, (long long) st.st_size, read_errno,
                  strerror(read_errno));
        free(bytes);
        return NULL;
    }
    CFDataRef data = CFDataCreateWithBytesNoCopy(NULL, bytes, (CFIndex) n, kCFAllocatorMalloc);
    CFErrorRef error = NULL;
    CFPropertyListRef plist = CFPropertyListCreateWithData(NULL, data, kCFPropertyListImmutable, NULL, &error);
    CFRelease(data);
    if (plist == NULL) {
        CFStringRef desc = CFErrorCopyDescription(error);
        char *d = cfstring_alloc(desc);
        log_error("Parse %s failed: %s", plist_path, d);
        free(d);
        CFRelease(desc);
        CFRelease(error);
        return NULL;
    }
    if (CFGetTypeID(plist) != CFDictionaryGetTypeID()) {
        log_error("%s is not a dictionary", plist_path);
        CFRelease(plist);
        return NULL;
    }
    return plist;
}

/*
 * Fills the bundle fields when the executable is the main executable of the bundle it sits in:
 * Info.plist next to it whose CFBundleExecutable is the executable's file name. Daemons hosted in
 * a framework directory (e.g. /System/Library/Frameworks/Accounts.framework/accountsd) sit next
 * to the framework's Info.plist, which names the framework binary instead.
 */
static bool read_bundle(struct process_info *p) {
    const char *slash = strrchr(p->path, '/');
    const char *exe = slash + 1;
    char plist_path[PROC_PIDPATHINFO_MAXSIZE + 16];
    snprintf(plist_path, sizeof(plist_path), "%.*s/Info.plist", (int) (slash - p->path), p->path);
    struct stat st;
    if (stat(plist_path, &st) != 0) {
        if (errno == ENOENT) {
            p->bundle = false;
            return true;
        }
        log_error("Stat %s failed: errno=%d (%s)", plist_path, errno, strerror(errno));
        return false;
    }
    CFDictionaryRef dict = read_plist(plist_path);
    if (dict == NULL) {
        return false;
    }
    CFStringRef executable = NULL;
    bool ok = plist_string(dict, "CFBundleExecutable", plist_path, false, &executable);
    if (ok) {
        CFStringRef exe_name = CFStringCreateWithFileSystemRepresentation(NULL, exe);
        p->bundle = executable != NULL && CFEqual(executable, exe_name);
        CFRelease(exe_name);
        if (executable != NULL) {
            CFRelease(executable);
        }
    }
    if (ok && p->bundle) {
        ok = plist_string(dict, "CFBundleIdentifier", plist_path, true, &p->bundle_identifier) &&
             plist_string(dict, "CFBundleDisplayName", plist_path, false, &p->bundle_display_name) &&
             plist_string(dict, "CFBundleName", plist_path, false, &p->bundle_name) &&
             plist_string(dict, "CFBundleShortVersionString", plist_path, false, &p->short_version_string) &&
             plist_string(dict, "CFBundleVersion", plist_path, false, &p->bundle_version);
    }
    CFRelease(dict);
    return ok;
}

/*
 * Checks that `pid` is still the process the flow names and that its executable matches. The unique pid
 * also catches pid reuse; user space (Skywalk) sources leave the effective one zero, so only the
 * executable UUID is compared for those (`upid` 0).
 */
static bool same_process(pid_t pid, uint64_t upid, const uint8_t uuid[16], const char *role, bool quiet) {
    struct proc_uniqidentifierinfo info;
    int n = proc_pidinfo(pid, PROC_PIDUNIQIDENTIFIERINFO, 0, &info, sizeof(info));
    if (n != (int) sizeof(info)) {
        if (!quiet) {
            log_warn("%s pid %d is gone: proc_pidinfo ret=%d errno=%d (%s)", role, pid, n, errno, strerror(errno));
        }
        return false;
    }
    if (upid != 0 && info.p_uniqueid != upid) {
        if (!quiet) {
            log_warn("%s pid %d was reused: unique id %llu, flow has %llu", role, pid,
                     (unsigned long long) info.p_uniqueid, (unsigned long long) upid);
        }
        return false;
    }
    if (memcmp(info.p_uuid, uuid, 16) != 0) {
        char have[37], want[37];
        format_uuid(info.p_uuid, have);
        format_uuid(uuid, want);
        log_error("%s pid %d executable UUID %s differs from flow UUID %s", role, pid, have, want);
        return false;
    }
    return true;
}

static bool resolve_process(pid_t pid, uint64_t upid, const uint8_t uuid[16], const char *role,
                            struct process_info *p) {
    memset(p, 0, sizeof(*p));
    p->pid = pid;
    if (!same_process(pid, upid, uuid, role, false)) {
        return false;
    }
    if (proc_name(pid, p->name, sizeof(p->name)) <= 0) {
        log_error("%s pid %d: proc_name failed: errno=%d (%s)", role, pid, errno, strerror(errno));
        return false;
    }
    if (proc_pidpath(pid, p->path, sizeof(p->path)) <= 0) {
        log_error("%s pid %d: proc_pidpath failed: errno=%d (%s)", role, pid, errno, strerror(errno));
        return false;
    }
    return read_bundle(p);
}

/* Finds the running processes whose main executable has `uuid`; returns how many, the first in `pid`. */
static int find_processes_by_uuid(const uint8_t uuid[16], pid_t *pid, char *pids, size_t pids_size) {
    int count = proc_listallpids(NULL, 0);
    if (count <= 0) {
        log_error("proc_listallpids failed: ret=%d errno=%d (%s)", count, errno, strerror(errno));
        return -1;
    }
    size_t capacity = (size_t) count + 64;
    pid_t *all = malloc(capacity * sizeof(pid_t));
    count = proc_listallpids(all, (int) (capacity * sizeof(pid_t)));
    if (count <= 0) {
        log_error("proc_listallpids failed: ret=%d errno=%d (%s)", count, errno, strerror(errno));
        free(all);
        return -1;
    }
    int found = 0;
    pids[0] = '\0';
    for (int i = 0; i < count; i++) {
        struct proc_uniqidentifierinfo info;
        if (proc_pidinfo(all[i], PROC_PIDUNIQIDENTIFIERINFO, 0, &info, sizeof(info)) == (int) sizeof(info) &&
            memcmp(info.p_uuid, uuid, 16) == 0) {
            if (found++ == 0) {
                *pid = all[i];
            }
            size_t used = strlen(pids);
            snprintf(pids + used, pids_size - used, "%s%d", used == 0 ? "" : ",", all[i]);
        }
    }
    free(all);
    return found;
}

/* ---- Tunnel connections ---- */

/*
 * Unique pids of a flow: kernel sources fill both, user space (Skywalk) sources fill the holder's and leave
 * the effective one zero (seen for MobileSafari, com.apple.WebKit.Networking, storekitd, geod and others).
 * Returns false for a combination not seen yet.
 */
static bool flow_upids(const struct flow *f, uint64_t *upid, uint64_t *eupid) {
    const nstat_tcp_descriptor *d = &f->desc;
    if (f->provider == NSTAT_PROVIDER_TCP_USERLAND && d->eupid != 0) {
        char *h = hex_alloc(d, sizeof(*d));
        log_error("User space flow of pid %u (%s) has effective unique pid %llu: descriptor=%s", d->pid, d->pname,
                  (unsigned long long) d->eupid, h);
        free(h);
        return false;
    }
    *upid = d->upid;
    *eupid = d->eupid;
    return true;
}

struct extension_cache_entry {
    uint8_t uuid[16];
    bool extension;
};

static struct extension_cache_entry extension_cache[EXTENSION_CACHE_SIZE];
static size_t extension_cache_count;
static size_t extension_cache_next;

/* Whether the process holding the flow is the InspectorVpn tunnel extension, cached per executable UUID. */
static bool is_extension(const struct flow *f) {
    const nstat_tcp_descriptor *d = &f->desc;
    /* kernel_task (pid 0) holds sockets of its own (seen: a loopback pair 127.0.0.1:49285 <-> 49284) and has no executable. */
    if (d->pid == 0) {
        return false;
    }
    for (size_t i = 0; i < extension_cache_count; i++) {
        if (memcmp(extension_cache[i].uuid, d->uuid, 16) == 0) {
            return extension_cache[i].extension;
        }
    }
    uint64_t upid, eupid;
    if (!flow_upids(f, &upid, &eupid) || !same_process((pid_t) d->pid, upid, d->uuid, "socket holder", true)) {
        return false;
    }
    struct process_info p;
    bool extension = false;
    if (resolve_process((pid_t) d->pid, upid, d->uuid, "socket holder", &p) && p.bundle) {
        CFStringRef wanted = CFSTR(EXTENSION_BUNDLE_ID);
        extension = CFEqual(p.bundle_identifier, wanted);
    }
    process_info_release(&p);
    struct extension_cache_entry entry = {.extension = extension};
    memcpy(entry.uuid, d->uuid, 16);
    if (extension_cache_count < EXTENSION_CACHE_SIZE) {
        extension_cache[extension_cache_count++] = entry;
    } else {
        extension_cache[extension_cache_next] = entry;
        extension_cache_next = (extension_cache_next + 1) % EXTENSION_CACHE_SIZE;
    }
    return extension;
}

struct binding {
    struct sockaddr_in local;
    struct in_addr server;
    pid_t pid;
    int fd;
    bool alive;
};

static struct binding bindings[MAX_BINDINGS];
static size_t binding_count;

static void open_binding(const nstat_tcp_descriptor *d) {
    char local[INET_ADDRSTRLEN], server[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &d->local.v4.sin_addr, local, sizeof(local));
    inet_ntop(AF_INET, &d->remote.v4.sin_addr, server, sizeof(server));
    if (binding_count == MAX_BINDINGS) {
        log_error("Too many tunnel connections, ignoring %s:%u -> %s:%u", local, ntohs(d->local.v4.sin_port), server,
                  ntohs(d->remote.v4.sin_port));
        return;
    }
    struct binding *b = &bindings[binding_count++];
    memset(b, 0, sizeof(*b));
    b->local.sin_len = sizeof(b->local);
    b->local.sin_family = AF_INET;
    b->local.sin_addr = d->local.v4.sin_addr;
    b->local.sin_port = d->local.v4.sin_port;
    b->server = d->remote.v4.sin_addr;
    b->pid = (pid_t) d->pid;
    b->alive = true;
    b->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (b->fd < 0) {
        log_error("UDP socket failed: errno=%d (%s)", errno, strerror(errno));
        return;
    }
    if (bind(b->fd, (struct sockaddr *) &b->local, sizeof(b->local)) != 0 ||
        fcntl(b->fd, F_SETFL, O_NONBLOCK) != 0) {
        log_error("Bind UDP %s:%u for tunnel pid %d failed: errno=%d (%s)", local, ntohs(b->local.sin_port), b->pid,
                  errno, strerror(errno));
        close(b->fd);
        b->fd = -1;
        return;
    }
    log_info("Listening on %s:%u for tunnel pid %d to %s:%u", local, ntohs(b->local.sin_port), b->pid, server,
             ntohs(d->remote.v4.sin_port));
}

/* Binds a UDP socket on every established tunnel connection and releases the ones that went away. */
static void scan_tunnels(void) {
    if (!nstat_snapshot()) {
        return;
    }
    for (size_t i = 0; i < binding_count; i++) {
        bindings[i].alive = false;
    }
    for (size_t i = 0; i < flow_count; i++) {
        const nstat_tcp_descriptor *d = &flows[i].desc;
        if (d->state != TCPS_ESTABLISHED || d->local.v4.sin_family != AF_INET || !is_extension(&flows[i])) {
            continue;
        }
        bool found = false;
        for (size_t j = 0; j < binding_count; j++) {
            struct binding *b = &bindings[j];
            if (b->local.sin_addr.s_addr == d->local.v4.sin_addr.s_addr && b->local.sin_port == d->local.v4.sin_port) {
                b->alive = true;
                found = true;
            }
        }
        if (!found) {
            open_binding(d);
        }
    }
    size_t kept = 0;
    for (size_t i = 0; i < binding_count; i++) {
        struct binding *b = &bindings[i];
        if (b->alive) {
            bindings[kept++] = *b;
            continue;
        }
        char local[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &b->local.sin_addr, local, sizeof(local));
        log_info("Tunnel %s:%u of pid %d closed", local, ntohs(b->local.sin_port), b->pid);
        if (b->fd >= 0) {
            close(b->fd);
        }
    }
    binding_count = kept;
}

/* ---- Response encoding (Java DataOutput) ---- */

struct writer {
    uint8_t buf[MAX_DATAGRAM];
    size_t len;
    bool overflow;
};

static void wr_bytes(struct writer *w, const void *p, size_t n) {
    if (w->len + n > sizeof(w->buf)) {
        w->overflow = true;
        return;
    }
    memcpy(w->buf + w->len, p, n);
    w->len += n;
}

static void wr_u8(struct writer *w, uint8_t v) {
    wr_bytes(w, &v, 1);
}

static void wr_u16(struct writer *w, uint16_t v) {
    uint8_t b[2] = {(uint8_t) (v >> 8), (uint8_t) v};
    wr_bytes(w, b, 2);
}

static void wr_i32(struct writer *w, int32_t v) {
    uint32_t u = (uint32_t) v;
    uint8_t b[4] = {(uint8_t) (u >> 24), (uint8_t) (u >> 16), (uint8_t) (u >> 8), (uint8_t) u};
    wr_bytes(w, b, 4);
}

static void wr_bool(struct writer *w, bool v) {
    wr_u8(w, v ? 1 : 0);
}

/* Java modified UTF-8 (DataOutput#writeUTF), encoded from the UTF-16 code units. */
static bool wr_utf(struct writer *w, CFStringRef s) {
    CFIndex count = CFStringGetLength(s);
    UniChar *chars = malloc((size_t) (count > 0 ? count : 1) * sizeof(UniChar));
    CFStringGetCharacters(s, CFRangeMake(0, count), chars);
    size_t encoded = 0;
    for (CFIndex i = 0; i < count; i++) {
        UniChar c = chars[i];
        encoded += (c >= 0x1 && c <= 0x7f) ? 1 : (c <= 0x7ff ? 2 : 3);
    }
    if (encoded > 0xffff) {
        char *d = cfstring_alloc(s);
        log_error("String too long for writeUTF: %zu bytes: %s", encoded, d);
        free(d);
        free(chars);
        return false;
    }
    wr_u16(w, (uint16_t) encoded);
    for (CFIndex i = 0; i < count; i++) {
        UniChar c = chars[i];
        if (c >= 0x1 && c <= 0x7f) {
            wr_u8(w, (uint8_t) c);
        } else if (c <= 0x7ff) {
            wr_u8(w, (uint8_t) (0xc0 | (c >> 6)));
            wr_u8(w, (uint8_t) (0x80 | (c & 0x3f)));
        } else {
            wr_u8(w, (uint8_t) (0xe0 | (c >> 12)));
            wr_u8(w, (uint8_t) (0x80 | ((c >> 6) & 0x3f)));
            wr_u8(w, (uint8_t) (0x80 | (c & 0x3f)));
        }
    }
    free(chars);
    return true;
}

static bool wr_utf_cstr(struct writer *w, const char *s) {
    CFStringRef cf = CFStringCreateWithCString(NULL, s, kCFStringEncodingUTF8);
    if (cf == NULL) {
        char *h = hex_alloc(s, strlen(s));
        log_error("Not UTF-8: hex=%s", h);
        free(h);
        return false;
    }
    bool ok = wr_utf(w, cf);
    CFRelease(cf);
    return ok;
}

static bool wr_opt_utf(struct writer *w, CFStringRef s) {
    wr_bool(w, s != NULL);
    return s == NULL || wr_utf(w, s);
}

static bool wr_process(struct writer *w, const struct process_info *p) {
    wr_i32(w, p->pid);
    if (!wr_utf_cstr(w, p->name) || !wr_utf_cstr(w, p->path)) {
        return false;
    }
    wr_bool(w, p->bundle);
    if (!p->bundle) {
        return true;
    }
    return wr_utf(w, p->bundle_identifier) && wr_opt_utf(w, p->bundle_display_name) &&
           wr_opt_utf(w, p->bundle_name) && wr_opt_utf(w, p->short_version_string) &&
           wr_opt_utf(w, p->bundle_version);
}

/* ---- Queries ---- */

struct query {
    uint8_t protocol;
    char saddr[INET_ADDRSTRLEN];
    uint16_t sport;
    char daddr[INET_ADDRSTRLEN];
    uint16_t dport;
    struct in_addr src;
    struct in_addr dst;
};

/* Reads a Java writeUTF string that holds a dotted IPv4 address. */
static bool read_address(const uint8_t *buf, size_t len, size_t *pos, char out[INET_ADDRSTRLEN], struct in_addr *addr) {
    if (*pos + 2 > len) {
        return false;
    }
    size_t n = ((size_t) buf[*pos] << 8) | buf[*pos + 1];
    *pos += 2;
    if (n >= INET_ADDRSTRLEN || *pos + n > len) {
        return false;
    }
    memcpy(out, buf + *pos, n);
    out[n] = '\0';
    *pos += n;
    return inet_pton(AF_INET, out, addr) == 1;
}

static bool parse_query(const uint8_t *buf, size_t len, struct query *q) {
    size_t pos = 0;
    if (len < 2 || buf[0] != QUERY_TYPE) {
        return false;
    }
    q->protocol = buf[1];
    pos = 2;
    if (!read_address(buf, len, &pos, q->saddr, &q->src) || pos + 2 > len) {
        return false;
    }
    q->sport = (uint16_t) ((buf[pos] << 8) | buf[pos + 1]);
    pos += 2;
    if (!read_address(buf, len, &pos, q->daddr, &q->dst) || pos + 2 > len) {
        return false;
    }
    q->dport = (uint16_t) ((buf[pos] << 8) | buf[pos + 1]);
    pos += 2;
    return pos == len;
}

static void answer(const struct binding *b, const struct query *q, const struct sockaddr_in *from) {
    if (!nstat_snapshot()) {
        return;
    }
    const struct flow *match = NULL;
    size_t matches = 0;
    for (size_t i = 0; i < flow_count; i++) {
        const nstat_tcp_descriptor *d = &flows[i].desc;
        if (d->local.v4.sin_family == AF_INET && d->remote.v4.sin_family == AF_INET &&
            d->local.v4.sin_addr.s_addr == q->src.s_addr && ntohs(d->local.v4.sin_port) == q->sport &&
            d->remote.v4.sin_addr.s_addr == q->dst.s_addr && ntohs(d->remote.v4.sin_port) == q->dport) {
            match = &flows[i];
            matches++;
        }
    }
    if (matches == 0) {
        log_warn("No TCP flow %s:%u -> %s:%u among %zu flows", q->saddr, q->sport, q->daddr, q->dport, flow_count);
        for (size_t i = 0; i < flow_count; i++) {
            const nstat_tcp_descriptor *d = &flows[i].desc;
            if (d->local.v4.sin_family == AF_INET && ntohs(d->local.v4.sin_port) == q->sport) {
                char *h = hex_alloc(d, sizeof(*d));
                log_warn("  same local port: provider=%u pid=%u epid=%u (%s) state=%u descriptor=%s", flows[i].provider,
                         d->pid, d->epid, d->pname, d->state, h);
                free(h);
            }
        }
        return;
    }
    if (matches > 1) {
        log_error("%zu TCP flows match %s:%u -> %s:%u, not answering", matches, q->saddr, q->sport, q->daddr, q->dport);
        for (size_t i = 0; i < flow_count; i++) {
            const nstat_tcp_descriptor *d = &flows[i].desc;
            if (d->local.v4.sin_family == AF_INET && d->local.v4.sin_addr.s_addr == q->src.s_addr &&
                ntohs(d->local.v4.sin_port) == q->sport) {
                char *h = hex_alloc(d, sizeof(*d));
                log_error("  provider=%u pid=%u epid=%u state=%u descriptor=%s", flows[i].provider, d->pid, d->epid,
                          d->state, h);
                free(h);
            }
        }
        return;
    }
    const nstat_tcp_descriptor *d = &match->desc;
    uint64_t upid, eupid;
    if (!flow_upids(match, &upid, &eupid)) {
        return;
    }
    /* Without an effective unique pid (user space sources) the effective pid tells the delegation apart. */
    bool delegated = match->provider == NSTAT_PROVIDER_TCP_USERLAND ? d->epid != d->pid : eupid != upid;
    pid_t owner_pid = (pid_t) d->epid;
    uint64_t owner_upid = eupid;
    if (!delegated && memcmp(d->euuid, d->uuid, 16) != 0) {
        /*
         * Delegated by executable UUID only (so_set_effective_uuid): the effective pid stays the holder's,
         * so the owner is the running process with that executable (seen: nsurlsessiond and cloudd).
         */
        char pids[256];
        int found = find_processes_by_uuid(d->euuid, &owner_pid, pids, sizeof(pids));
        if (found != 1) {
            char euuid[37];
            format_uuid(d->euuid, euuid);
            char *h = hex_alloc(d, sizeof(*d));
            log_warn("Flow %s:%u -> %s:%u of pid %u (%s) is delegated to executable %s, run by %d processes [%s], "
                     "not answering: provider=%u descriptor=%s",
                     q->saddr, q->sport, q->daddr, q->dport, d->pid, d->pname, euuid, found, pids, match->provider, h);
            free(h);
            return;
        }
        owner_upid = 0;
        delegated = true;
    }
    struct process_info owner, delegate;
    memset(&delegate, 0, sizeof(delegate));
    bool ok = resolve_process(owner_pid, owner_upid, d->euuid, "owner", &owner) &&
              (!delegated || resolve_process((pid_t) d->pid, upid, d->uuid, "delegate", &delegate));
    if (ok) {
        struct writer *w = calloc(1, sizeof(struct writer));
        wr_u8(w, RESPONSE_TYPE);
        wr_u8(w, q->protocol);
        ok = wr_utf_cstr(w, q->saddr);
        wr_u16(w, q->sport);
        ok = ok && wr_utf_cstr(w, q->daddr);
        wr_u16(w, q->dport);
        ok = ok && wr_process(w, &owner);
        wr_bool(w, delegated);
        ok = ok && (!delegated || wr_process(w, &delegate));
        if (ok && w->overflow) {
            log_error("Response for %s:%u -> %s:%u exceeds %d bytes", q->saddr, q->sport, q->daddr, q->dport,
                      MAX_DATAGRAM);
        } else if (ok) {
            ssize_t sent = sendto(b->fd, w->buf, w->len, 0, (const struct sockaddr *) from, sizeof(*from));
            if (sent != (ssize_t) w->len) {
                log_error("Send response to %s:%u failed: ret=%zd errno=%d (%s)", inet_ntoa(from->sin_addr),
                          ntohs(from->sin_port), sent, errno, strerror(errno));
            } else {
                log_debug("%s:%u -> %s:%u owner pid=%d %s %s%s%s", q->saddr, q->sport, q->daddr, q->dport, owner.pid,
                          owner.name, owner.path, delegated ? " via " : "", delegated ? delegate.name : "");
            }
        }
        free(w);
    }
    process_info_release(&owner);
    process_info_release(&delegate);
}

static void handle_datagram(const struct binding *b) {
    static uint8_t buf[MAX_DATAGRAM];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    ssize_t n = recvfrom(b->fd, buf, sizeof(buf), 0, (struct sockaddr *) &from, &from_len);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_error("UDP recvfrom failed: errno=%d (%s)", errno, strerror(errno));
        }
        return;
    }
    char from_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from.sin_addr, from_ip, sizeof(from_ip));
    if (from.sin_addr.s_addr != b->server.s_addr) {
        char server[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &b->server, server, sizeof(server));
        char *h = hex_alloc(buf, (size_t) n);
        log_warn("Ignoring datagram from %s:%u, tunnel server is %s: hex=%s", from_ip, ntohs(from.sin_port), server, h);
        free(h);
        return;
    }
    struct query q;
    memset(&q, 0, sizeof(q));
    if (!parse_query(buf, (size_t) n, &q) || q.protocol != IPPROTO_TCP_VALUE) {
        char *h = hex_alloc(buf, (size_t) n);
        log_error("Unrecognized query from %s:%u: hex=%s", from_ip, ntohs(from.sin_port), h);
        free(h);
        return;
    }
    answer(b, &q, &from);
}

/* ---- Main loop ---- */

int main(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "v")) != -1) {
        if (opt == 'v') {
            verbose = true;
        } else {
            fprintf(stderr, "Usage: %s [-v]\n", argv[0]);
            return 2;
        }
    }
    if (optind != argc) {
        fprintf(stderr, "Usage: %s [-v]\n", argv[0]);
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    if (!nstat_open()) {
        return 1;
    }
    log_info("Started, watching tunnel connections of %s", EXTENSION_BUNDLE_ID);
    uint64_t next_scan = 0;
    struct pollfd fds[1 + MAX_BINDINGS];
    size_t owners[1 + MAX_BINDINGS];
    for (;;) {
        uint64_t now = monotonic_ms();
        if (now >= next_scan) {
            scan_tunnels();
            next_scan = monotonic_ms() + SCAN_INTERVAL_MS;
            now = monotonic_ms();
        }
        size_t nfds = 0;
        fds[nfds].fd = nstat_fd;
        fds[nfds].events = POLLIN;
        fds[nfds].revents = 0;
        nfds++;
        for (size_t i = 0; i < binding_count; i++) {
            if (bindings[i].fd >= 0) {
                fds[nfds].fd = bindings[i].fd;
                fds[nfds].events = POLLIN;
                fds[nfds].revents = 0;
                owners[nfds] = i;
                nfds++;
            }
        }
        int timeout = next_scan > now ? (int) (next_scan - now) : 0;
        int ready = poll(fds, (nfds_t) nfds, timeout);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_error("poll failed: errno=%d (%s)", errno, strerror(errno));
            return 1;
        }
        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            log_error("NStat socket failed: revents=0x%x", fds[0].revents);
            return 1;
        }
        if ((fds[0].revents & POLLIN) && !nstat_drain()) {
            return 1;
        }
        for (size_t i = 1; i < nfds; i++) {
            if (fds[i].revents & POLLIN) {
                handle_datagram(&bindings[owners[i]]);
            }
        }
    }
}
