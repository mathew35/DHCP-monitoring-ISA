/**
 * ISA
 * @file dhcp-stasts.h
 * @authors Matus Vrablik (xvrab05)
 * @brief DHCP monitoring
 */
#define UDP_HDR_LEN 8
#define v_map std::map<std::string, std::string>
#define p_map std::map<std::tuple<std::string, int>, v_map>

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
    char options[308];
};

int update_win(p_map stats);

int start_ncurses();

int argparse(int argc, char **argv);

void handle_pcap(u_char *user, const pcap_pkthdr *h,
                 const u_char *bytes);
