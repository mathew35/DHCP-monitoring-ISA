/**
 * ISA
 * @file dhcp-stasts.cpp
 * @authors Matus Vrablik (xvrab05)
 * @brief DHCP monitoring
 */

#include <iostream>
#include <unistd.h>
// #include <string>
#include <array>
#include <cmath>
#include <map>
#include <regex>

#include <arpa/inet.h>
#include <ncurses.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <syslog.h>
/* posible includes
#include "arg_parser.h"
#include <cstdlib>
*/
#include "dhcp-stats.h"

int main(int argc, char **argv) {
    bool read_from_file = false;
    std::string filename = "";
    bool read_from_interface = false;
    std::string interface = "";
    int option_char;
    while ((option_char = getopt(argc, argv, "r:i:")) != EOF) {
        switch (option_char) {
            case 'r':
                read_from_file = true;
                filename = optarg;
                break;

            case 'i':
                read_from_interface = true;
                interface = optarg;
                break;

            default:
                std::cerr << "Unsuported option: " << option_char << std::endl;
                return 1;
        }
    };
    if ((read_from_file and read_from_interface) or (not read_from_file and not read_from_interface)) {
        std::cerr << "Unsuported ussage of '-r' with '-i', choose only one of them.\nFor more info see 'man -l dhcp-stats.1'" << std::endl;
        exit(1);
    }
    pcap_t *handle;
    if (read_from_file) {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_offline(filename.c_str(), errbuf);
    } else {
        // TODO read from interface
    }
    p_map print_map = {};
    for (int i = optind; i < argc; i++) {
        // Verify ip-prefix
        std::regex pattern(R"(\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([12][0-9]|3[0-2]|[0-9])\b)");
        if (!std::regex_search(argv[i], pattern)) {
            std::cerr << "Wrong Format of ip-prefix: " << argv[i] << std::endl;
            exit(1);
        }

        std::string str = argv[i];
        // get max_hosts
        uint32_t prefix = std::stoi(str.substr(str.find('/') + 1));
        uint32_t max_hosts = std::pow(2, (32 - prefix)) - 2;
        // create placeholder
        dhcp_map d_map = {};
        global_map()->emplace(str, std::tuple(max_hosts, d_map));
    }
    // print map example
    // for (const auto &pair : print_map) {
    // std::cout << "Key: " << std::get<0>(pair.first) << "\nMax hosts: " << std::get<1>(pair.first) << std::endl;
    // }
    start_ncurses();
    update_win();
    getch();
    // getch(); // read from stdin - see output , TODO redo
    pcap_loop(handle, -1, handle_pcap, nullptr);
    //  map[(prefix,max_hosts),map['ip?yiaddr?',lease time]]
    // Ncurses
    // p_map print_map = {};
    // v_map value_map = {{"max_hosts", "2987"}, {"allocated", "300"}, {"utilization", "47%%"}};
    // print_map.insert({{"192.123.152.234/10"}, value_map});
    // getch();  // read from stdin - see output , TODO redo
    // getch();  // read from stdin - see output , TODO redo
    endwin(); // end ncurses
    return 0;
}

void handle_pcap(u_char *user, const pcap_pkthdr *header, const u_char *packet) {
    // TODO work with time
    //  std::cout << "TimeVal: " << header->ts.tv_usec << std::endl;
    static int line = 0;
    line++;
    ether_header *eth = (ether_header *)packet;
    // TODO check ethertype?
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        std::cout << "WARNING skipping packet" << std::endl;
        // std::cerr << "Wrong eth type: " << std::hex << ntohs(eth->ether_type) << std::endl;
    }

    ip *ip_hdr = (ip *)(packet + ETHER_HDR_LEN);
    // *4 => count of 4 byte words
    // 20 => minimal length of IP header
    if (ip_hdr->ip_hl * 4 < 20) {
        std::cerr << "Invalid IP header of size: " << ip_hdr->ip_hl * 4 << std::endl;
        exit(1);
    }
    // skip non UDP packets -> dhcp uses udp
    if (ip_hdr->ip_p != (uint8_t)IPPROTO_UDP) {
        return;
    }
    udphdr *udp_hdr = (udphdr *)(packet + ETHER_HDR_LEN + ip_hdr->ip_hl * 4);
    int sport = ntohs(udp_hdr->uh_sport);
    int dport = ntohs(udp_hdr->uh_dport);
    // skip non dhcp packets
    if (sport == dport || 67 > sport || sport > 68 || 67 > dport || dport > 68) return;

    dhcp *dhcp_packet = (dhcp *)(packet + ETHER_HDR_LEN + ip_hdr->ip_hl * 4 + UDP_HDR_LEN);
    int i = 0;
    bool server_id = false;
    time_t lease_time = 0;
    bool vendor_id = false;
    std::string dhcp_msg = "";
    while (i < 308 and (uint8_t) dhcp_packet->options[i] != 255) {
        int op_no = dhcp_packet->options[i];
        int length = dhcp_packet->options[i + 1];
        uint8_t value = 0;

        switch (op_no) {
            // skip pad
            case 0:
                i++;
                continue;
            // skip packets with request IP value
            case 50:
                return;
            case 51:
                for (int j = 0; j < dhcp_packet->options[i + 1]; j++) {
                    lease_time = (lease_time << 8) | static_cast<unsigned int>(dhcp_packet->options[i + 2 + j]);
                }
                break;
            case 53:
                value = dhcp_packet->options[i + 2];
                if (value == 5) {
                    dhcp_msg = "DHCPACK";
                } else if (value == 7) {
                    dhcp_msg = "DHCPRELEASE";
                } else {
                    i += 2 + length;
                    return;
                }
                break;
            case 54:
                server_id = true;
                break;
            default:
                break;
        }
        // 2 for op_no and length
        i += 2 + (uint8_t)length;
    }
    // check valid ack/release packet RFC2131
    if (!server_id) return;
    if (dhcp_msg == "DHCPRELEASE" and (lease_time or vendor_id))
        return;
    else if (dhcp_msg == "DHCPACK" and !lease_time)
        return;
    else if (dhcp_msg != "DHCPACK" and dhcp_msg != "DHCPRELEASE")
        return;

    dhcp_monitor dhcp_mon;
    if (dhcp_msg == "DHCPACK") {
        dhcp_mon.rm = false;
        dhcp_mon.ip_addr = dhcp_packet->yiaddr;
    } else if (dhcp_msg == "DHCPRELEASE") {
        dhcp_mon.rm = true;
        dhcp_mon.ip_addr = dhcp_packet->ciaddr;
    }
    dhcp_mon.time = header->ts;
    dhcp_mon.lease_time = lease_time;
    update_global_map(dhcp_mon);
    update_win();
    getch();
}

int start_ncurses() {
    setlocale(LC_ALL, ""); // Initialization needed for ncurses
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    resize_term(10, 100);
    return 0;
}
void update_win() {
    int pos[] = {0, 19, 30, 41};
    mvprintw(0, pos[0], "IP-Prefix");
    mvprintw(0, pos[1], "Max-hosts");
    mvprintw(0, pos[2], "Allocated");
    mvprintw(0, pos[3], "Utilization");
    p_map *stats = global_map();
    if (stats->empty()) {
        return;
    }
    p_map::iterator stats_iter = stats->begin();
    int i = 1;
    std::string ip_prefix = "";
    int max_hosts = 0;
    int allocation = 0;
    float utilization = 0;
    for (stats_iter; stats_iter != stats->end(); stats_iter++) {
        ip_prefix = stats_iter->first;
        max_hosts = std::get<0>(stats_iter->second);
        allocation = std::get<1>(stats_iter->second).size();
        utilization = (float)allocation / max_hosts * 100;
        if (utilization >= 50) {
            std::string log_str = "prefix " + ip_prefix + " exceeded 50%% of allocations";
            syslog(LOG_INFO, log_str.c_str());
        }
        char buffer[6] = "";
        sprintf(buffer, "%6.2f", utilization);
        std::string util = std::string(buffer).append("%%");
        mvprintw(i, 0, (char *)(ip_prefix.c_str()));
        mvprintw(i, pos[1], (char *)std::to_string(max_hosts).c_str());
        mvprintw(i, pos[2], (char *)std::to_string(allocation).c_str());
        mvprintw(i, pos[3], (char *)util.c_str());
        i++;
    }
    refresh();
}
p_map *global_map() {
    static p_map map = {};
    return &map;
}

void update_global_map(dhcp_monitor mon) {
    static std::map<std::string, std::array<uint32_t, 2>> mask_map = {};
    p_map *g_map = global_map();
    p_map::iterator map_iter = g_map->begin();
    // Prepare mask_map for use
    if (mask_map.empty()) {
        for (map_iter = g_map->begin(); map_iter != g_map->end(); map_iter++) {
            int slash_pos = map_iter->first.find('/');
            std::string prefix_ip = map_iter->first.substr(0, slash_pos);
            std::string prefix_mask_bits = map_iter->first.substr(slash_pos + 1);
            uint32_t ip;
            if (inet_pton(AF_INET, prefix_ip.c_str(), &ip) != 1) {
                std::cerr << "Error converting ip from prefix to binary network format" << std::endl;
                exit(1);
            }
            uint32_t mask = (0xFFFFFFFFu >> (32 - std::stoi(prefix_mask_bits)));
            mask_map.emplace(map_iter->first, std::array<uint32_t, 2>{ip, mask});
        }
    }
    for (map_iter = g_map->begin(); map_iter != g_map->end(); map_iter++) {
        uint32_t mask = mask_map[map_iter->first][1];
        uint32_t prefix_ip = mask_map[map_iter->first][0];
        if (((uint32_t)mon.ip_addr.s_addr & mask) == (prefix_ip & mask)) {
            dhcp_map *d_map = &std::get<1>(map_iter->second);
            // DHCPRELEASE
            if (mon.rm) {
                if (d_map->find(inet_ntoa(mon.ip_addr)) != d_map->end()) {
                    d_map->erase(inet_ntoa(mon.ip_addr));
                }
                continue;
            }
            // DHCPACK
            if (d_map->find(inet_ntoa(mon.ip_addr)) != d_map->end()) {
                dhcp_map::iterator d_map_iter = d_map->find(inet_ntoa(mon.ip_addr));
                d_map_iter->second.lease_time = mon.lease_time;
                d_map_iter->second.time = mon.time;
            } else {
                d_map->emplace(inet_ntoa(mon.ip_addr), mon);
            }
        }
    }
}
