

#include <iostream>
// #include <string>
#include <map>

#include <ncurses.h>
// #include <syslog.h>
/* posible includes
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <cstdlib>
#include "dhcp_monitor.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include "arg_parser.h"
*/

#define v_map std::map<std::string,std::string>
#define p_map std::map<std::string,v_map>
int update_win(p_map stats);
int start_ncurses();

int main(int argc, char** argv){
    //TODO get input from file or interface



    // map['prefix',[map['max_hosts',int]]]
    p_map print_map = {};
    v_map value_map = {{"max_hosts","2987"},{"allocated","300"},{"utilization","47%%"}};
    print_map.insert({{"192.123.152.234/10"},value_map});
    start_ncurses();
    update_win(print_map);
    getch();//read from stdin - see output , TODO redo
    endwin();//end ncurses
    return 0;
}

int start_ncurses(){
    setlocale(LC_ALL,""); //Initialization needed for ncurses
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    resize_term(10,100);
    return 0;
}
int update_win(p_map stats){
    int x,y;
    int pos[]={0,19,30,41};
    getmaxyx(stdscr,y,x);
    mvprintw(0,pos[0],"IP-Prefix");
    mvprintw(0,pos[1],"Max-hosts");
    mvprintw(0,pos[2],"Allocated");
    mvprintw(0,pos[3],"Utilization");
    
    if (stats.empty()){return 0;}
    p_map::iterator stats_iter = stats.begin();
    int i = 1;
    for(stats_iter; stats_iter!=stats.end();stats_iter++){
        mvprintw(1,0,(char*)(stats_iter->first.c_str()));
        int j = 1;
        for(v_map::iterator vals_iter = stats_iter->second.begin(); vals_iter != stats_iter->second.end();vals_iter++){
            mvprintw(i,pos[j],(char*)(vals_iter->second.c_str()));
            j++;
        }
        i++;
    }
    refresh();
    return 0;
}
