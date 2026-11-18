/*
 * riptide.c - Riptide: fast concurrent TCP port scanner (single file, no deps)
 *
 * Build:
 *   Windows (MSVC):  cl /O2 riptide.c ws2_32.lib
 *   Windows (MinGW): gcc -O2 riptide.c -o riptide.exe -lws2_32
 *   Linux / macOS:   gcc -O2 riptide.c -o riptide
 *
 * Only scan hosts you own or have permission to test.
 */
#ifdef _WIN32
  #define __USE_MINGW_ANSI_STDIO 1
  #define _CRT_SECURE_NO_WARNINGS
  #define FD_SETSIZE 4096
  #define WIN32_LEAN_AND_MEAN
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  typedef SOCKET sock_t;
  #define BAD_SOCK   INVALID_SOCKET
  #define CLOSESOCK  closesocket
  #define SOCKERR()  WSAGetLastError()
  #define MAX_CONC   FD_SETSIZE
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <fcntl.h>
  #include <unistd.h>
  #include <errno.h>
  #include <poll.h>
  #include <signal.h>
  typedef int sock_t;
  #define BAD_SOCK   (-1)
  #define CLOSESOCK  close
  #define SOCKERR()  errno
  #define MAX_CONC   8192
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/* Service table (also used as the default "top" port list)           */
/* ------------------------------------------------------------------ */
static const struct { int port; const char *name; } SERVICES[] = {
    {21,"ftp"},{22,"ssh"},{23,"telnet"},{25,"smtp"},{53,"dns"},{80,"http"},
    {81,"http-alt"},{88,"kerberos"},{110,"pop3"},{111,"rpcbind"},{135,"msrpc"},
    {139,"netbios-ssn"},{143,"imap"},{389,"ldap"},{443,"https"},{445,"smb"},
    {465,"smtps"},{514,"shell"},{515,"printer"},{548,"afp"},{554,"rtsp"},
    {587,"submission"},{631,"ipp"},{636,"ldaps"},{873,"rsync"},{990,"ftps"},
    {993,"imaps"},{995,"pop3s"},{1080,"socks"},{1194,"openvpn"},{1433,"mssql"},
    {1521,"oracle"},{1723,"pptp"},{1883,"mqtt"},{2049,"nfs"},{2181,"zookeeper"},
    {2375,"docker"},{2376,"docker-tls"},{3000,"http-dev"},{3128,"squid"},
    {3306,"mysql"},{3389,"rdp"},{3690,"svn"},{4443,"https-alt"},{5000,"http-dev"},
    {5060,"sip"},{5432,"postgres"},{5672,"amqp"},{5900,"vnc"},{5985,"winrm"},
    {5986,"winrm-ssl"},{6379,"redis"},{6443,"k8s-api"},{6667,"irc"},
    {7001,"weblogic"},{8000,"http-alt"},{8008,"http-alt"},{8080,"http-proxy"},
    {8081,"http-alt"},{8443,"https-alt"},{8888,"http-alt"},{9000,"http-alt"},
    {9090,"http-alt"},{9092,"kafka"},{9100,"jetdirect"},{9200,"elasticsearch"},
    {9418,"git"},{10000,"webmin"},{11211,"memcached"},{25565,"minecraft"},
    {27017,"mongodb"},{0,NULL}
};

static const char *service_name(int port) {
    for (int i = 0; SERVICES[i].name; i++)
        if (SERVICES[i].port == port) return SERVICES[i].name;
    return "";
}

static int is_http_port(int p) {
    static const int H[] = {80,81,3000,5000,8000,8008,8080,8081,8888,9000,9090,9200,0};
    for (int i = 0; H[i]; i++) if (H[i] == p) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Small platform helpers                                             */
/* ------------------------------------------------------------------ */
static double now_ms(void) {
#ifdef _WIN32
    static LARGE_INTEGER f; LARGE_INTEGER c;
    if (!f.QuadPart) QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart * 1000.0 / (double)f.QuadPart;
#else
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
#endif
}

static void sleep_ms(int ms) {
    if (ms <= 0) return;
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
#endif
}

static int set_nonblocking(sock_t s) {
#ifdef _WIN32
    u_long m = 1; return ioctlsocket(s, FIONBIO, &m);
#else
    int f = fcntl(s, F_GETFL, 0); return fcntl(s, F_SETFL, f | O_NONBLOCK);
#endif
}

static unsigned long long rng_state;
static unsigned long long rng(void) {           /* xorshift64 */
    rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17;
    return rng_state;
}

/* ------------------------------------------------------------------ */
/* State                                                              */
/* ------------------------------------------------------------------ */
enum { R_NONE = 0, R_OPEN, R_CLOSED, R_FILTERED };
enum { S_FREE = 0, S_CONNECT, S_BANNER };

typedef struct {
    sock_t s;
    int    port;
    int    state;
    int    ready;
    double t0;
} slot_t;

static struct sockaddr_storage g_addr;
static socklen_t g_alen;
static int g_family;

static unsigned char g_res[65536];
static char *g_banner[65536];
static int  g_grab = 0;
static int  g_timeout = 1000, g_btimeout = 1500;
static size_t g_done = 0, g_open = 0, g_closed = 0, g_filtered = 0;

/* ------------------------------------------------------------------ */
/* Port list parsing: "22,80,1000-2000", "top", "all"                 */
/* ------------------------------------------------------------------ */
static int add_port(int p, int *out, int n, unsigned char *seen) {
    if (p < 1 || p > 65535 || seen[p]) return n;
    seen[p] = 1; out[n++] = p; return n;
}

static int parse_ports(const char *spec, int *out) {
    static unsigned char seen[65536];
    int n = 0;
    if (!strcmp(spec, "all") || !strcmp(spec, "-")) {
        for (int p = 1; p <= 65535; p++) n = add_port(p, out, n, seen);
        return n;
    }
    const char *p = spec;
    while (*p) {
        char tok[32]; int k = 0;
        while (*p && *p != ',' && k < (int)sizeof(tok) - 1) tok[k++] = *p++;
        tok[k] = 0;
        while (*p && *p != ',') p++;
        if (*p == ',') p++;
        if (!k) continue;
        if (!strcmp(tok, "top")) {
            for (int i = 0; SERVICES[i].name; i++) n = add_port(SERVICES[i].port, out, n, seen);
            continue;
        }
        char *dash = strchr(tok, '-');
        if (dash) {
            int a = atoi(tok), b = atoi(dash + 1);
            if (a < 1) a = 1;
            if (b > 65535 || b == 0) b = 65535;
            for (int q = a; q <= b; q++) n = add_port(q, out, n, seen);
        } else {
            n = add_port(atoi(tok), out, n, seen);
        }
    }
    return n;
}


/* ------------------------------------------------------------------ */
/* Banner cleanup: first line, plus Server: header for HTTP           */
/* ------------------------------------------------------------------ */
static char *clean_banner(const char *buf, int len) {
    char line[200]; int j = 0;
    for (int i = 0; i < len && j < (int)sizeof(line) - 1; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c == '\r' || c == '\n') break;
        line[j++] = isprint(c) ? (char)c : '.';
    }
    line[j] = 0;
    if (!strncmp(buf, "HTTP/", 5)) {
        const char *sv = NULL;
        for (int i = 0; i + 8 < len; i++)
            if ((buf[i] == '\n') && !strncmp(buf + i + 1, "Server:", 7) ) { sv = buf + i + 8; break; }
            else if ((buf[i] == '\n') && !strncmp(buf + i + 1, "server:", 7)) { sv = buf + i + 8; break; }
        if (sv) {
            while (*sv == ' ') sv++;
            int k = j;
            const char *tag = " | Server: ";
            for (const char *t = tag; *t && k < (int)sizeof(line) - 1; t++) line[k++] = *t;
            while (sv < buf + len && *sv != '\r' && *sv != '\n' && k < (int)sizeof(line) - 1)
                line[k++] = isprint((unsigned char)*sv) ? *sv : '.', sv++;
            line[k] = 0;
        }
    }
    return line[0] ? strdup(line) : NULL;
}

/* ------------------------------------------------------------------ */
/* Connection lifecycle                                               */
/* ------------------------------------------------------------------ */
static void finish(slot_t *sl, int result) {
    g_res[sl->port] = (unsigned char)result;
    if (result == R_OPEN) g_open++;
    else if (result == R_CLOSED) g_closed++;
    else g_filtered++;
    CLOSESOCK(sl->s);          /* SO_LINGER=0 -> RST, no FIN/TIME_WAIT */
    sl->state = S_FREE;
    g_done++;
}

static void on_open(slot_t *sl, double now) {
    if (!g_grab) { finish(sl, R_OPEN); return; }
    if (is_http_port(sl->port)) {
        static const char probe[] = "HEAD / HTTP/1.0\r\n\r\n";
        send(sl->s, probe, (int)sizeof(probe) - 1, 0);
    }
    sl->state = S_BANNER;
    sl->t0 = now;
}

static int is_resource_error(int e) {
#ifdef _WIN32
    return e == WSAENOBUFS || e == WSAEMFILE || e == WSAEADDRINUSE;
#else
    return e == EMFILE || e == ENFILE || e == ENOBUFS || e == EADDRNOTAVAIL || e == EAGAIN;
#endif
}

/* returns: 0 pending, 1 open now, 2 closed, 3 filtered, -1 out of resources */
static int start_connect(slot_t *sl, int port, double now) {
    sock_t s = socket(g_family, SOCK_STREAM, IPPROTO_TCP);
    if (s == BAD_SOCK) return -1;
    set_nonblocking(s);

    struct linger lg; lg.l_onoff = 1; lg.l_linger = 0;
    setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);

    struct sockaddr_storage a;
    memcpy(&a, &g_addr, g_alen);
    if (g_family == AF_INET) ((struct sockaddr_in  *)&a)->sin_port  = htons((unsigned short)port);
    else                     ((struct sockaddr_in6 *)&a)->sin6_port = htons((unsigned short)port);

    sl->s = s; sl->port = port; sl->t0 = now; sl->ready = 0;

    if (connect(s, (struct sockaddr *)&a, g_alen) == 0) return 1;
    int e = SOCKERR();
#ifdef _WIN32
    if (e == WSAEWOULDBLOCK) { sl->state = S_CONNECT; return 0; }
    if (e == WSAECONNREFUSED) { CLOSESOCK(s); return 2; }
#else
    if (e == EINPROGRESS) { sl->state = S_CONNECT; return 0; }
    if (e == ECONNREFUSED) { CLOSESOCK(s); return 2; }
#endif
    CLOSESOCK(s);
    return is_resource_error(e) ? -1 : 3;
}

static int connect_result(sock_t s) {
    int err = 0; socklen_t len = sizeof err;
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
    if (err == 0) return R_OPEN;
#ifdef _WIN32
    if (err == WSAECONNREFUSED) return R_CLOSED;
#else
    if (err == ECONNREFUSED) return R_CLOSED;
#endif
    return R_FILTERED;      /* unreachable, reset by middlebox, etc. */
}

/* ------------------------------------------------------------------ */
/* Event wait: select() on Windows, poll() elsewhere                  */
/* ------------------------------------------------------------------ */
#ifdef _WIN32
static void wait_events(slot_t *sl, int n, int timeout) {
    static fd_set r, w, e;
    FD_ZERO(&r); FD_ZERO(&w); FD_ZERO(&e);
    int count = 0;
    for (int i = 0; i < n; i++) {
        sl[i].ready = 0;
        if (sl[i].state == S_CONNECT) { FD_SET(sl[i].s, &w); FD_SET(sl[i].s, &e); count++; }
        else if (sl[i].state == S_BANNER) { FD_SET(sl[i].s, &r); count++; }
    }
    if (!count) { sleep_ms(timeout); return; }
    struct timeval tv = { 0, timeout * 1000 };
    if (select(0, &r, &w, &e, &tv) <= 0) return;
    for (int i = 0; i < n; i++) {
        if (sl[i].state == S_CONNECT)
            sl[i].ready = FD_ISSET(sl[i].s, &w) || FD_ISSET(sl[i].s, &e); /* Windows reports failed connects in exceptfds */
        else if (sl[i].state == S_BANNER)
            sl[i].ready = FD_ISSET(sl[i].s, &r);
    }
}
#else
static void wait_events(slot_t *sl, int n, int timeout) {
    static struct pollfd *pf = NULL; static int *map = NULL; static int cap = 0;
    if (cap < n) { pf = realloc(pf, n * sizeof *pf); map = realloc(map, n * sizeof *map); cap = n; }
    int count = 0;
    for (int i = 0; i < n; i++) {
        sl[i].ready = 0;
        if (sl[i].state == S_FREE) continue;
        pf[count].fd = sl[i].s;
        pf[count].events = sl[i].state == S_CONNECT ? POLLOUT : POLLIN;
        pf[count].revents = 0;
        map[count++] = i;
    }
    if (!count) { sleep_ms(timeout); return; }
    if (poll(pf, count, timeout) <= 0) return;
    for (int k = 0; k < count; k++)
        if (pf[k].revents) sl[map[k]].ready = 1;
}
#endif

/* ------------------------------------------------------------------ */
static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s <host> [options]\n"
        "  -p <ports>  22,80,1000-2000 | top (default) | all\n"
        "  -c <n>      concurrent connections (default 500, max %d)\n"
        "  -t <ms>     connect timeout (default 1000)\n"
        "  -b          grab service banners\n"
        "  -B <ms>     banner read timeout (default 1500)\n"
        "  -r <n>      max new connections per second (default: unlimited)\n"
        "  -j <ms>     random extra delay 0..ms between connections\n"
        "  -s          scan ports in sequential order (default: randomized)\n"
        "  -a          also list closed/filtered ports\n"
        "  -q          no progress line\n"
        "\nexamples:\n"
        "  %s 192.168.1.10                 top ports, fast\n"
        "  %s scanme.local -p all -c 1000  full range\n"
        "  %s 10.0.0.5 -p 1-1024 -r 20 -j 200 -c 10   slow, low-noise\n",
        argv0, MAX_CONC, argv0, argv0, argv0);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 1; }

    const char *host = NULL, *portspec = "top";
    int conc = 500, rate = 0, jitter = 0, sequential = 0, show_all = 0, quiet = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (i + 1 < argc ? argv[++i] : (usage(argv[0]), exit(1), ""))
        if      (!strcmp(a, "-p")) portspec = NEXT();
        else if (!strcmp(a, "-c")) conc = atoi(NEXT());
        else if (!strcmp(a, "-t")) g_timeout = atoi(NEXT());
        else if (!strcmp(a, "-B")) g_btimeout = atoi(NEXT());
        else if (!strcmp(a, "-r")) rate = atoi(NEXT());
        else if (!strcmp(a, "-j")) jitter = atoi(NEXT());
        else if (!strcmp(a, "-b")) g_grab = 1;
        else if (!strcmp(a, "-s")) sequential = 1;
        else if (!strcmp(a, "-a")) show_all = 1;
        else if (!strcmp(a, "-q")) quiet = 1;
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else if (a[0] == '-') { fprintf(stderr, "unknown option %s\n", a); return 1; }
        else host = a;
    }
    if (!host) { usage(argv[0]); return 1; }
    if (conc < 1) conc = 1;
    if (conc > MAX_CONC) conc = MAX_CONC;
    if (g_timeout < 50) g_timeout = 50;

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa)) { fprintf(stderr, "WSAStartup failed\n"); return 1; }
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    /* Resolve target */
    struct addrinfo hints, *ai = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &ai) || !ai) {
        fprintf(stderr, "cannot resolve %s\n", host); return 1;
    }
    memcpy(&g_addr, ai->ai_addr, ai->ai_addrlen);
    g_alen = (socklen_t)ai->ai_addrlen;
    g_family = ai->ai_family;
    char ipstr[INET6_ADDRSTRLEN] = "?";
    getnameinfo(ai->ai_addr, (socklen_t)ai->ai_addrlen, ipstr, sizeof ipstr, NULL, 0, NI_NUMERICHOST);
    freeaddrinfo(ai);

    /* Build port list */
    int *ports = malloc(65536 * sizeof(int));
    int nports = parse_ports(portspec, ports);
    if (nports == 0) { fprintf(stderr, "no valid ports in '%s'\n", portspec); return 1; }
    if (conc > nports) conc = nports;

    rng_state = (unsigned long long)time(NULL) ^ ((unsigned long long)(size_t)&ports << 16) ^ 0x9E3779B97F4A7C15ULL;
    if (!sequential)
        for (int i = nports - 1; i > 0; i--) {
            int j = (int)(rng() % (unsigned long long)(i + 1));
            int t = ports[i]; ports[i] = ports[j]; ports[j] = t;
        }

    printf("scanning %s (%s): %d ports, %d concurrent, timeout %dms%s\n",
           host, ipstr, nports, conc, g_timeout, g_grab ? ", banners on" : "");

    slot_t *slots = calloc((size_t)conc, sizeof *slots);
    double interval = rate > 0 ? 1000.0 / rate : 0.0;
    double next_send = 0, start = now_ms(), last_prog = 0;
    int next = 0;

    while (g_done < (size_t)nports) {
        double now = now_ms();

        /* launch new connections into free slots */
        for (int i = 0; i < conc && next < nports; i++) {
            if (slots[i].state != S_FREE) continue;
            if ((rate > 0 || jitter > 0) && now < next_send) break;

            int r = start_connect(&slots[i], ports[next], now);
            if (r == -1) break;                 /* out of sockets: retry next round */
            next++;
            if (r == 1) on_open(&slots[i], now);
            else if (r == 2) { g_res[slots[i].port] = R_CLOSED; g_closed++; g_done++; }
            else if (r == 3) { g_res[slots[i].port] = R_FILTERED; g_filtered++; g_done++; }

            if (rate > 0 || jitter > 0) {
                next_send = now + interval + (jitter > 0 ? (double)(rng() % (unsigned)(jitter + 1)) : 0);
                break;                          /* one at a time when pacing */
            }
        }

        int wait = 20;
        if ((rate > 0 || jitter > 0) && next < nports) {
            int until = (int)(next_send - now);
            if (until < wait) wait = until < 1 ? 1 : until;
        }
        wait_events(slots, conc, wait);
        now = now_ms();

        /* process ready sockets and timeouts */
        for (int i = 0; i < conc; i++) {
            slot_t *sl = &slots[i];
            if (sl->state == S_CONNECT) {
                if (sl->ready) {
                    int res = connect_result(sl->s);
                    if (res == R_OPEN) on_open(sl, now);
                    else finish(sl, res);
                } else if (now - sl->t0 >= g_timeout) {
                    finish(sl, R_FILTERED);     /* no answer: dropped by firewall */
                }
            } else if (sl->state == S_BANNER) {
                if (sl->ready) {
                    char buf[1024];
                    int got = (int)recv(sl->s, buf, sizeof buf, 0);
                    if (got > 0) g_banner[sl->port] = clean_banner(buf, got);
                    finish(sl, R_OPEN);
                } else if (now - sl->t0 >= g_btimeout) {
                    finish(sl, R_OPEN);
                }
            }
        }

        if (!quiet && now - last_prog > 250) {
            last_prog = now;
            fprintf(stderr, "\r  %zu/%d (%d%%)  open: %zu   ", g_done, nports,
                    (int)(g_done * 100 / (size_t)nports), g_open);
            fflush(stderr);
        }
    }
    if (!quiet) fprintf(stderr, "\r%60s\r", "");

    double secs = (now_ms() - start) / 1000.0;

    /* Results, sorted by port */
    printf("\nPORT       STATE     SERVICE         %s\n", g_grab ? "BANNER" : "");
    for (int p = 1; p <= 65535; p++) {
        int r = g_res[p];
        if (r == R_NONE) continue;
        if (r != R_OPEN && !show_all) continue;
        char pbuf[16]; snprintf(pbuf, sizeof pbuf, "%d/tcp", p);
        printf("%-10s %-9s %-15s %s\n", pbuf,
               r == R_OPEN ? "open" : r == R_CLOSED ? "closed" : "filtered",
               service_name(p), g_banner[p] ? g_banner[p] : "");
    }
    printf("\n%zu open, %zu closed, %zu filtered  |  %d ports in %.2fs (%.0f ports/s)\n",
           g_open, g_closed, g_filtered, nports, secs, secs > 0 ? nports / secs : 0.0);

    free(slots); free(ports);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
