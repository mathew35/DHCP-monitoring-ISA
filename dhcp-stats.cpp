/**
 * ISA
 * @file dhcp-stasts.cpp
 * @authors Matus Vrablik (xvrab05)
 * @brief DHCP monitoring
 */

// standard libs
#include <array>
#include <cmath>
#include <iostream>
#include <map>
#include <regex>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
// network libs
#include <arpa/inet.h>
#include <ncurses.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
// header files
#include "dhcp-stats.h"

int main(int argc, char **argv) {
    useconds_t sleep = 400000;
    // register ctrl+c handler
    if (signal(SIGINT, exit_handler) == SIG_ERR) {
        exit_prog(1, "Error setting up SIGINT handler\n");
    }
    // parse arguments
    bool read_from_file = false;
    std::string filename = "";
    bool read_from_interface = false;
    std::string interface = "";
    int option_char;
    std::string tmp;
    while ((option_char = getopt(argc, argv, "r:i:st:")) != EOF) {
        switch (option_char) {
            case 'r':
                read_from_file = true;
                filename = optarg;
                break;
            case 'i':
                sleep = 0;
                read_from_interface = true;
                interface = optarg;
                break;
            case 's':
                sleep = 0;
                STEP = true;
                break;
            case 't':
                tmp = optarg;
                if(tmp.empty() or !std::all_of(tmp.begin(), tmp.end(), [](unsigned char c) { return std::isdigit(c); })){
                    exit_prog(1,"Invalid value <useconds> for '-t', use number.\n");
                }
                sleep = std::stoi(tmp);
                break;
            default:
                return 1;
        }
    };
    if ((read_from_file and read_from_interface) or (not read_from_file and not read_from_interface)) {
        std::stringstream msg;
        msg << "Unsuported ussage of '-r' with '-i', choose only one of them.\nFor more info see 'man -l dhcp-stats.1'" << std::endl;
        exit_prog(1, msg.str());
    }
    if (STEP and sleep != 0) {
        std::stringstream msg;
        msg << "Unsupported ussage of '-s' and '-t', choose only one of them.\nFor more info see 'man -l dhcp-stats.1'" << std::endl;
        exit_prog(1, msg.str());
    }
    // set pcap stream
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (read_from_file) {
        // read from file
        handle = pcap_open_offline(filename.c_str(), errbuf);
        if (handle == nullptr) {
            std::stringstream msg;
            msg << "Couldn't open file " << filename << ":" << errbuf << std::endl;
            exit_prog(1, msg.str());
        }
    } else {
        // read from inteface
        handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            std::stringstream msg;
            msg << "Couldn't open device " << interface << ":" << errbuf << std::endl;
            exit_prog(1, msg.str());
        }
    }
    U_SLEEP = &sleep;
    // initialize statistics map
    bool got_prefix = false;
    for (int i = optind; i < argc; i++) {
        // Verify ip-prefix
        std::string ip_prefix = argv[i];
        std::regex pattern(R"(\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([12][0-9]|30|[0-9])\b)");
        if (!std::regex_search(argv[i], pattern)) {
            std::stringstream msg;
            msg << "Wrong Format of ip-prefix: " << argv[i] << std::endl;
            exit_prog(1, msg.str());
        }
        // get max_hosts
        uint32_t prefix = std::stoi(ip_prefix.substr(ip_prefix.find('/') + 1));
        uint32_t max_hosts = std::pow(2, (32 - prefix)) - 2;
        // create dummy value with computed max_hosts
        dhcp_map d_map = {};
        global_map()->emplace(ip_prefix, std::tuple<uint32_t, dhcp_map>(max_hosts, d_map));
        got_prefix = true;
    }
    if (!got_prefix) {
        std::stringstream msg;
        msg << "Missing <ip-prefix>!" << std::endl;
        pcap_close(handle);
        exit_prog(1, msg.str());
    }
    start_ncurses();
    // show table before 1st packet
    update_win();
    // stepping mechanism to see what's happening
    usleep(*U_SLEEP);
    if (STEP) getch();
    // process packets
    pcap_loop(handle, -1, handle_pcap, nullptr);
    // last step to see final result
    usleep(*U_SLEEP);
    if (STEP) getch();
    // gracefuly end ncurses
    pcap_close(handle);
    endwin();
    return 0;
}

void handle_pcap(u_char *user, const pcap_pkthdr *header, const u_char *packet) {
    // skip all but IPv4 packets
    ether_header *eth = (ether_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return;
    }

    ip *ip_hdr = (ip *)(packet + ETHER_HDR_LEN);
    // *4 => count of 4 byte words
    // 20 => minimal length of IP header
    if (ip_hdr->ip_hl * 4 < 20) {
        std::stringstream msg;
        msg << "Invalid IP header of size: " << ip_hdr->ip_hl * 4 << std::endl;
        exit_prog(1, msg.str());
    }
    // skip non UDP packets -> dhcp uses udp
    if (ip_hdr->ip_p != (uint8_t)IPPROTO_UDP) {
        return;
    }
    udphdr *udp_hdr = (udphdr *)(packet + ETHER_HDR_LEN + ip_hdr->ip_hl * 4);
    int sport = ntohs(udp_hdr->source);
    int dport = ntohs(udp_hdr->dest);
    // skip non dhcp packets
    if (sport == dport || 67 > sport || sport > 68 || 67 > dport || dport > 68) return;

    dhcp *dhcp_packet = (dhcp *)(packet + ETHER_HDR_LEN + ip_hdr->ip_hl * 4 + UDP_HDR_LEN);
    int i = 0;
    bool server_id = false;
    time_t lease_time = 0;
    bool vendor_id = false;
    std::string dhcp_msg = "";
    while (i < sizeof(dhcp_packet->options) and (uint8_t) dhcp_packet->options[i] != 255) {
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
    // update time_now;
    if (time_now.tv_sec == 0) {
        time_now = header->ts;
    }
    time_now = header->ts;
    check_lease_time();
    update_global_map(dhcp_mon);
    update_win();
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

void exit_prog(int exit_code, std::string msg) {
    endwin();
    std::cerr << msg;
    exit(exit_code);
}

void exit_handler(int status) {
    exit_prog(0, "");
}
void update_win() {
    int pos[] = {0, 19, 30, 41, 50};
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
    uint32_t max_hosts = 0;
    int allocation = 0;
    float utilization = 0;
    for (; stats_iter != stats->end(); stats_iter++) {
        ip_prefix = stats_iter->first;
        max_hosts = std::get<0>(stats_iter->second);
        allocation = std::get<1>(stats_iter->second).size();
        utilization = (float)allocation / max_hosts * 100;
        char buffer[6] = "";
        sprintf(buffer, "%5.2f", utilization);
        std::string util = std::string(buffer).append("%%");
        mvprintw(i, 0, (char *)(ip_prefix.c_str()));
        mvprintw(i, pos[1], (char *)std::to_string(max_hosts).c_str());
        mvprintw(i, pos[2], (char *)std::to_string(allocation).c_str());
        mvprintw(i, pos[3], (char *)util.c_str());
        if (utilization > 50) {
            mvprintw(i, pos[4], "!!! over 50%% !!!");
        }
        i++;
    }
    refresh();
    usleep(*U_SLEEP);
    if (STEP) getch();
}
p_map *global_map() {
    static p_map map = {};
    return &map;
}

void update_global_map(dhcp_monitor mon) {
    // map for prefix masks
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
                std::stringstream msg;
                msg << "Error converting ip from prefix to binary network format: " << prefix_ip << std::endl;
                exit_prog(1, msg.str());
            }
            // split bit shifting due to undefined behaviour
            uint32_t mask = (0xFFFFFFFFu << (30 - std::stoi(prefix_mask_bits)) << 2);
            ip = ntohl(ip);
            mask_map.emplace(map_iter->first, std::array<uint32_t, 2>{ip, mask});
        }
    }
    // update global map
    for (map_iter = g_map->begin(); map_iter != g_map->end(); map_iter++) {
        uint32_t mask = mask_map[map_iter->first][1];
        uint32_t prefix_ip = mask_map[map_iter->first][0];
        // process DHCP release/ack

        if ((ntohl(mon.ip_addr.s_addr) & mask) == (prefix_ip & mask)) {
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
                float utilization_before, utilization_now;
                utilization_before = (float)d_map->size() / std::get<0>(map_iter->second) * 100;
                d_map->emplace(inet_ntoa(mon.ip_addr), mon);
                utilization_now = (float)d_map->size() / std::get<0>(map_iter->second) * 100;
                if (utilization_now >= 50 and utilization_before < utilization_now) {
                    std::string log_str = "prefix " + map_iter->first + " exceeded 50%% of allocations" + std::to_string(utilization_now) + "," + std::to_string(utilization_before) + ",time: " + std::to_string(time_now.tv_sec) + "." + std::to_string(time_now.tv_usec) + "," + std::to_string(mon.time.tv_sec) + "." + std::to_string(mon.time.tv_usec) + " addr: " + inet_ntoa(mon.ip_addr);
                    syslog(LOG_INFO, log_str.c_str());
                }
            }
        }
    }
}

void check_lease_time() {
    p_map *g_map = global_map();
    bool update = false;
    for (p_map::iterator map_iter = g_map->begin(); map_iter != g_map->end(); map_iter++) {
        dhcp_map *d_map = &std::get<1>(map_iter->second);
        dhcp_map::iterator d_map_iter = d_map->begin();
        while (d_map_iter != d_map->end()) {
            timeval dhcp_time = d_map_iter->second.time;
            time_t lease_time = d_map_iter->second.lease_time;
            if (time_now.tv_sec - dhcp_time.tv_sec >= lease_time) {
                d_map_iter = d_map->erase(d_map_iter);
                update = true;
                continue;
            }
            d_map_iter++;
        }
    }
    if (update) update_win();
}
