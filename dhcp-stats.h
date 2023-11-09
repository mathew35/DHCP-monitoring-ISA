/**
 * ISA
 * @file dhcp-stasts.h
 * @authors Matus Vrablik (xvrab05)
 * @brief DHCP monitoring
 */
#define UDP_HDR_LEN sizeof(struct udphdr)
#define dhcp_map std::map<std::string, dhcp_monitor>
#define p_map std::map<std::string, std::tuple<uint32_t, dhcp_map>>
useconds_t *U_SLEEP = nullptr;
bool STEP = false;
timeval time_now = {0, 0};

struct dhcp {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    in_addr ciaddr;
    in_addr yiaddr;
    in_addr siaddr;
    in_addr giaddr;
    char chadddr[16];
    char sname[64];
    char file[128];
    char magic_cookie[4];
    char options[312];
};
struct dhcp_monitor {
    time_t lease_time;
    timeval time;
    in_addr ip_addr;
    bool rm;
};

void update_win();

int start_ncurses();

void exit_prog(int exit_code, std::string msg);

void exit_handler(int status);

int argparse(int argc, char **argv);

void handle_pcap(u_char *user, const pcap_pkthdr *h,
                 const u_char *bytes);

p_map *global_map();

void update_global_map(dhcp_monitor mon);

void check_lease_time();
