/*
 * libnetcap.so — Universal app network capture via LD_PRELOAD (no APK, no VPN,
 * no Frida, nothing visible inside the app).
 *
 * Interposes the socket-path libc calls and logs every network event to a
 * per-PID JSONL file using raw syscalls only (no libc dependency, safe to
 * preload into complex apps next to libfakemem_min.so):
 *
 *   {"ev":"conn","fd":..,"af":2,"ip":"1.2.3.4","port":443}      connect()
 *   {"ev":"udps","fd":..,"af":2,"ip":"8.8.8.8","port":53,
 *    "n":64,"p":"<hex>"}                                        sendto()
 *   {"ev":"udpr", ...}                                          recvfrom()
 *
 * Why this exists (in-process layer below TLS/QUIC):
 *  - DNS is PLAINTEXT here (UDP/53 payloads captured → full query log)
 *  - QUIC/HTTP3 is visible (UDP/443 endpoints + payload sizes)
 *  - every event is attributed to the exact PID of the app
 *  - combined with the transparent host MITM (sni_proxy→mitmproxy, no VPN,
 *    no system proxy → nothing for the app to detect), this closes the last
 *    per-app visibility gap without any APK installation.
 *
 * Payload logging is capped (NETCAP_MAXP bytes per event) and can be disabled
 * at runtime by touching /data/local/tmp/netcap_off — the hot path stays a
 * single raw syscall passthrough, safe for production use.
 *
 * Compile (x86_64):
 *   gcc -shared -fPIC -nostdlib -fno-stack-protector \
 *       -DNETCAP_PAYLOAD -o libnetcap_x86_64.so libnetcap.c
 */

#define SYS_read                 0
#define SYS_write                1
#define SYS_connect             42
#define SYS_sendto              44
#define SYS_recvfrom            45
#define SYS_sendmsg             46
#define SYS_recvmsg             47
#define SYS_openat             257
#define SYS_getpid              39
#define SYS_getsockopt           54

#define AT_FDCWD               -100
#define O_WRONLY                01
#define O_CREAT                0100
#define O_APPEND               02000
#define O_CLOEXEC            02000000

#define NETCAP_MAXP            384   /* max payload bytes logged per event */
#define NETCAP_LINE           (2 * NETCAP_MAXP + 256)

/* ── Raw x86_64 syscall wrappers ── */

static inline long _sc1(long nr, long a1) {
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "0"(nr), "D"(a1)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline long _sc3(long nr, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "0"(nr), "D"(a1), "S"(a2), "d"(a3)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline long _sc6(long nr, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;
    __asm__ volatile("syscall" : "=a"(ret) : "0"(nr), "D"(a1), "S"(a2), "d"(a3),
                     "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}

static inline long _sc5(long nr, long a1, long a2, long a3, long a4, long a5) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    __asm__ volatile("syscall" : "=a"(ret) : "0"(nr), "D"(a1), "S"(a2), "d"(a3),
                     "r"(r10), "r"(r8) : "rcx", "r11", "memory");
    return ret;
}

/* openat 4-arg helper (kernel arg6=0) */
#define _sc4(nr, a1, a2, a3, a4) _sc6((nr), (a1), (a2), (a3), (a4), 0, 0)

/* ── tiny formatting helpers (no libc) ── */

static char *_s(char *p, const char *s) {
    while (*s) *p++ = *s++;
    return p;
}

static char *_d(char *p, unsigned long v) {
    char t[24]; int i = 0;
    if (!v) { *p++ = '0'; return p; }
    while (v && i < 24) { t[i++] = '0' + (v % 10); v /= 10; }
    while (i) *p++ = t[--i];
    return p;
}

static char *_h(char *p, const unsigned char *b, long n) {
    static const char hx[] = "0123456789abcdef";
    long i;
    for (i = 0; i < n; i++) {
        *p++ = hx[b[i] >> 4];
        *p++ = hx[b[i] & 15];
    }
    return p;
}

/* ── fd -> endpoint map (connected sockets) ── */

#define NCMAP 512

static struct {
    int  fds[NCMAP];
    unsigned char addr[NCMAP][28];   /* sockaddr(28): fam(2) port(2) ip(16..) */
    int  typ[NCMAP];                 /* 1=SOCK_STREAM, 2=SOCK_DGRAM */
    int  used[NCMAP];
} _fdm;

static int _fdm_slot(int fd) {
    int i;
    for (i = 0; i < NCMAP; i++)
        if (_fdm.used[i] && _fdm.fds[i] == fd)
            return i;
    return -1;
}

static int _sock_type(int fd) {
    /* getsockopt(fd, SOL_SOCKET, SO_TYPE) -> 1 stream / 2 dgram */
    int t = 0, len = 4;
    if (_sc5(54, fd, 1, 3, (long)&t, (long)&len) != 0)
        return 0;
    return t;
}

static void _fdm_put(int fd, const unsigned char *addr) {
    int i, ty;
    if (!addr) return;
    if ((addr[0] | (addr[1] << 8)) != 2 && (addr[0] | (addr[1] << 8)) != 10)
        return;
    i = _fdm_slot(fd);
    if (i < 0) {
        for (i = 0; i < NCMAP; i++)
            if (!_fdm.used[i]) break;
        if (i >= NCMAP) return;
        _fdm.used[i] = 1;
        _fdm.fds[i] = fd;
    }
    for (int k = 0; k < 28; k++) _fdm.addr[i][k] = addr[k];
    ty = _sock_type(fd);
    if (ty == 1 || ty == 2) _fdm.typ[i] = ty;
}

/* ── logging state ── */

static int _fd = -1;
static int _payload = 1;
static int _init_done = 0;

static void _lazy_init(void) {
    char path[96];
    char *p;
    if (_init_done) return;
    _init_done = 1;

    /* runtime payload switch: `touch netcap_off` disables payload capture */
    if (_sc4(SYS_openat, AT_FDCWD, (long)"/data/local/tmp/netcap_off", 0, 0) >= 0)
        _payload = 0;

    p = _s(path, "/data/local/tmp/netcap/proc-");
    p = _d(p, (unsigned long)_sc1(SYS_getpid, 0));
    p = _s(p, ".jsonl");
    *p = 0;

    _fd = (int)_sc4(SYS_openat, AT_FDCWD, (long)path,
                    O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
}

/* ── event logging ── */

static void _log_ev(const char *ev, int sfd,
                    const unsigned char *addr,
                    const unsigned char *payload, long plen) {
    char buf[NETCAP_LINE];
    char *p = buf;

    _lazy_init();
    if (_fd < 0) return;

    p = _s(p, "{\"ev\":\"");   p = _s(p, ev);
    p = _s(p, "\",\"fd\":");   p = _d(p, (unsigned long)(sfd < 0 ? 0 : sfd));

    if (addr) {
        /* sockaddr: [0..1]=family BE? (native order via *(sa_family_t*)),
         * [2..3]=port BE, [4..7]=IPv4 | [8..23]=IPv6 */
        unsigned fam = addr[0] | (addr[1] << 8);
        unsigned port = ((unsigned)addr[2] << 8) | addr[3];
        if (fam == 10) { /* AF_INET6 */
            p = _s(p, ",\"af\":10,\"ip6\":\"");
            p = _h(p, addr + 8, 16);
        } else {
            p = _s(p, ",\"af\":2,\"ip\":\"");
            p = _d(p, addr[4]); *p++ = '.'; p = _d(p, addr[5]); *p++ = '.';
            p = _d(p, addr[6]); *p++ = '.'; p = _d(p, addr[7]);
        }
        p = _s(p, "\",\"port\":");
        p = _d(p, port);
    }

    if (plen >= 0) { p = _s(p, ",\"n\":"); p = _d(p, (unsigned long)plen); }
    if (_payload && payload && plen > 0) {
        long cap = plen > NETCAP_MAXP ? NETCAP_MAXP : plen;
        p = _s(p, ",\"p\":\"");
        p = _h(p, payload, cap);
        *p++ = '"';
    }
    *p++ = '}'; *p++ = '\n';
    _sc3(SYS_write, _fd, (long)buf, p - buf);
}

/* ── interposed socket functions (raw syscalls, no libc) ── */

__attribute__((visibility("default")))
int connect(int fd, const void *addr, unsigned addrlen) {
    long r;
    /* napkin safety: only touch log path, never break the syscall */
    r = _sc3(SYS_connect, fd, (long)addr, addrlen);
    if ((r == 0 || r == -115) && addr) {
        unsigned fam = ((const unsigned char *)addr)[0] |
                       (((const unsigned char *)addr)[1] << 8);
        if (fam == 2 || fam == 10) {
            _log_ev("conn", fd, (const unsigned char *)addr, 0, -1);
            _fdm_put(fd, (const unsigned char *)addr);
        }
    }
    return (int)r;
}

__attribute__((visibility("default")))
long sendto(int fd, const void *buf, unsigned long n, int flags,
            const void *dst, unsigned addrlen) {
    long r = _sc6(SYS_sendto, fd, (long)buf, n, flags, (long)dst, addrlen);
    if (r > 0 && dst) {
        _fdm_put(fd, (const unsigned char *)dst);
        _log_ev("udps", fd, (const unsigned char *)dst,
                (const unsigned char *)buf, r);
    }
    return r;
}

__attribute__((visibility("default")))
long recvfrom(int fd, void *buf, unsigned long n, int flags,
              void *src, unsigned *addrlen) {
    long r = _sc6(SYS_recvfrom, fd, (long)buf, n, flags, (long)src, (long)addrlen);
    if (r > 0)
        _log_ev("udpr", fd, (const unsigned char *)src,
                (const unsigned char *)buf, r);
    return r;
}


/* connected-socket byte counters: only trace fds we saw connect() on, so
 * file/stdin writes on the hot path are ignored (zero-op lookup). */

__attribute__((visibility("default")))
long send(int fd, const void *buf, unsigned long n, int flags) {
    long r = _sc4(SYS_sendto, fd, (long)buf, n, flags);
    int i;
    if (r > 0 && (i = _fdm_slot(fd)) >= 0) {
        if (_fdm.typ[i] == 2)
            _log_ev("udps", fd, _fdm.addr[i], (const unsigned char *)buf, r);
        else
            _log_ev("tx", fd, _fdm.addr[i], 0, -1);
    }
    return r;
}

__attribute__((visibility("default")))
long recv(int fd, void *buf, unsigned long n, int flags) {
    long r = _sc4(SYS_recvfrom, fd, (long)buf, n, flags);
    int i;
    if (r > 0 && (i = _fdm_slot(fd)) >= 0) {
        if (_fdm.typ[i] == 2)
            _log_ev("udpr", fd, _fdm.addr[i], (const unsigned char *)buf, r);
        else
            _log_ev("rx", fd, _fdm.addr[i], 0, -1);
    }
    return r;
}

struct _msghdr_shim {
    void  *name;
    unsigned namelen;
    void  *iov;
    unsigned iovlen;
    void  *ctrl;
    unsigned ctrllen;
    unsigned flags;
};

__attribute__((visibility("default")))
long sendmsg(int fd, const struct _msghdr_shim *msg, int flags) {
    long r = _sc3(SYS_sendmsg, fd, (long)msg, flags);
    int i;
    if (r > 0 && msg) {
        const unsigned char *pb = 0; long pl = 0;
        if (msg->name && msg->namelen >= 4) {
            _fdm_put(fd, (const unsigned char *)msg->name);
            if (msg->iov && msg->iovlen > 0) {
                const struct { void *b; unsigned long l; } *iov = msg->iov;
                pb = (const unsigned char *)iov->b; pl = iov->l;
            }
            _log_ev("udps", fd, (const unsigned char *)msg->name, pb, pl > 0 ? pl : 0);
        } else if ((i = _fdm_slot(fd)) >= 0) {
            if (_fdm.typ[i] == 2 && msg->iov && msg->iovlen > 0) {
                const struct { void *b; unsigned long l; } *iov = msg->iov;
                _log_ev("udps", fd, _fdm.addr[i], (const unsigned char *)iov->b, iov->l);
            } else
                _log_ev("tx", fd, _fdm.addr[i], 0, -1);
        }
    }
    return r;
}

__attribute__((visibility("default")))
long recvmsg(int fd, struct _msghdr_shim *msg, int flags) {
    long r = _sc3(SYS_recvmsg, fd, (long)msg, flags);
    int i;
    if (r > 0 && msg) {
        if ((i = _fdm_slot(fd)) >= 0) {
            if (_fdm.typ[i] == 2 && msg->iov && msg->iovlen > 0) {
                const struct { void *b; unsigned long l; } *iov = msg->iov;
                _log_ev("udpr", fd, _fdm.addr[i], (const unsigned char *)iov->b, iov->l);
            } else
                _log_ev("rx", fd, _fdm.addr[i], 0, -1);
        } else if (msg->name && msg->namelen >= 4)
            _log_ev("udpr", fd, (const unsigned char *)msg->name, 0, -1);
    }
    return r;
}
