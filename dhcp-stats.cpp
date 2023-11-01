/**
 * ISA
 * @file dhcp-stasts.cpp
 * @authors Matus Vrablik (xvrab05)
 * @brief DHCP monitoring
 */

#include <iostream>
#include <unistd.h>
// #include <string>
#include <cmath>
#include <map>
#include <regex>

#include <arpa/inet.h>
#include <ncurses.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
// #include <syslog.h>
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
    pcap *handle;
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
        uint32_t max_hosts = std::pow(2, prefix);
        // create placeholder
        v_map empty_map = {};
        print_map.emplace(std::tuple(str, max_hosts), empty_map);
    }
    // print map example
    // for (const auto &pair : print_map) {
    // std::cout << "Key: " << std::get<0>(pair.first) << "\nMax hosts: " << std::get<1>(pair.first) << std::endl;
    // }
    pcap_loop(handle, -1, handle_pcap, nullptr);
    //  map[(prefix,max_hosts),map['ip?yiaddr?',lease time]]
    // Ncurses
    // p_map print_map = {};
    // v_map value_map = {{"max_hosts", "2987"}, {"allocated", "300"}, {"utilization", "47%%"}};
    // print_map.insert({{"192.123.152.234/10"}, value_map});
    //  start_ncurses();
    //  update_win(print_map);
    //  getch();  // read from stdin - see output , TODO redo
    //  endwin(); // end ncurses
    return 0;
}

void handle_pcap(u_char *user, const pcap_pkthdr *header, const u_char *packet) {
    static int line = 0;
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
    if (sport == dport || 66 > sport || sport > 69 || 66 > dport || dport > 69) return;

    dhcp *dhcp_packet = (dhcp *)(packet + ETHER_HDR_LEN + ip_hdr->ip_hl * 4 + UDP_HDR_LEN);
    int i = 0;
    bool server_id = false;
    bool lease_time = false;
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
                line++;
                return;
            case 51:
                lease_time = true;
                break;
            case 53:
                value = dhcp_packet->options[i + 2];
                // std::cout << "DHCP msg: " << value << std::endl;
                if (value == 5)
                    dhcp_msg = "DHCPACK";
                else if (value == 7)
                    dhcp_msg = "DHCPRELEASE";
                else {
                    i += 2 + length;
                    line++;
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
        // std::cout << "'i' before: [" << i;
        i += 2 + (uint8_t)length;
        // std::cout << "] and after: [" << i << "]" << std::endl;
    }
    // check valid ack/release packet RFC2131
    if (!server_id) return;
    if (dhcp_msg == "DHCPRELEASE" and (lease_time or vendor_id))
        return;
    else if (dhcp_msg == "DHCPACK" and !lease_time)
        return;
    else if (dhcp_msg != "DHCPACK" and dhcp_msg != "DHCPRELEASE")
        return;

    std::string sip = inet_ntoa(ip_hdr->ip_src);
    std::string dip = inet_ntoa(ip_hdr->ip_dst);
    line++;
    std::cout << line << "\tsource ip: " << sip << "\n\tdestin ip: " << dip << "\n\tDHCP msg: " << dhcp_msg << std::endl;
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
int update_win(p_map stats) {
    // int x, y;
    // int pos[] = {0, 19, 30, 41};
    // getmaxyx(stdscr, y, x);
    // mvprintw(0, pos[0], "IP-Prefix");
    // mvprintw(0, pos[1], "Max-hosts");
    // mvprintw(0, pos[2], "Allocated");
    // mvprintw(0, pos[3], "Utilization");

    // if (stats.empty()) {
    //     return 0;
    // }
    // p_map::iterator stats_iter = stats.begin();
    // int i = 1;
    // for (stats_iter; stats_iter != stats.end(); stats_iter++) {
    //     mvprintw(1, 0, (char *)(stats_iter->first.c_str()));
    //     int j = 1;
    //     for (v_map::iterator vals_iter = stats_iter->second.begin(); vals_iter != stats_iter->second.end(); vals_iter++) {
    //         mvprintw(i, pos[j], (char *)(vals_iter->second.c_str()));
    //         j++;
    //     }
    //     i++;
    // }
    // refresh();
    return 0;
}
