# ISA-project-repete
DHCP monitoring
# DETAIL ZADÁNÍ
###  Předmět:
ISA - Síťové aplikace a správa sítí
### Ak. rok:
2023/2024
### Název:
Monitorování DHCP komunikace (Matěj Grégr)
### Vedoucí:
Ing. Matěj Grégr, Ph.D.
### Literatura:
http://liw.fi/manpages/\
RFC 2131 - DHCP protocol, https://datatracker.ietf.org/doc/html/rfc2131\
NCURSES HOWTO: https://tldp.org/HOWTO/NCURSES-Programming-HOWTO/
## Popis:
Vaším úkolem je vytvořit program, který umožní získat statistiku o vytížení síťového prefixu z pohledu množství alokovaných IP adres. Při zaplnění prefixu z více jako 50%, nástroj informuje administrátora na standardní výstup a zalogováním skrz syslog server.

Tento problém se v praxi řeší typicky pomocí parsingu přidělených adres z logu DHCP serveru, případně tuto informaci může někdy poskytnout přímo DHCP server. Cílem projektu je vyřešit situaci, kdy DHCP server tuto možnost nepodporuje a pro získání daných statistik je možné monitorovat DHCP provoz.

## Příklad spuštění:
./dhcp-stats [-r \<filename>] [-i \<interface-name>] \<ip-prefix> [ \<ip-prefix> [ ... ] ]

-r \<filename> - statistika bude vytvořena z pcap souborů\
-i \<interface> - rozhraní, na kterém může program naslouchat

\<ip-prefix> - rozsah sítě pro které se bude generovat statistika

Např.
./dhcp-stats -i eth0 192.168.1.0/24 192.168.0.0/22 172.16.32.0/24

## Princip fungování:

Program po spuštění začne monitorovat DHCP provoz na zvoleném rozhraní, případně zpracuje pcap soubor, a generovat si statistiku vytížení síťového prefixu, který mu byl zadán v příkazové řádce.

Prefixů může být více a mohou se překrývat - důvodem možného překryvu je zjištění, jak by vypadalo vytížení sítě, kdyby byl prefix větší. Tedy pokud je program spuštěn podobně jak v předcházejícím příkladě a DHCP server přidělil klientovi adresu 192.168.1.12, tato adresa bude započítána do statistik prefixu 192.168.1.0/24 i 192.168.0.0/22. Adresa 192.168.3.1 bude započítána pouze do prefixu 192.168.0.0/22 atp.

V případě, že počet alokovaných adres v prefixu překročí 50%, program tuto informaci zaloguje skrz standardní syslog mechanismus do logu. 

## Příklad výstupu:

./dhcp-stats -i eth0 192.168.1.0/24 172.16.32.0/24 192.168.0.0/22\
IP-Prefix Max-hosts Allocated addresses Utilization\
192.168.0.0/22 1022 123 12.04%\
192.168.1.0/24 254 123 48.43%\
172.16.32.0/24 254 15 5.9%

Program by při spuštění na síťovém rozhraní měl fungovat jako konzolová aplikace. Tedy měly by se aktualizovat pouze řádky s prefixy. Pro tyto účely lze využít např. knihovnu ncurses.

## Příklad logu

Při překročení 50% se do logu zapíše následující hláška:

prefix x.x.x.x/y exceeded 50% of allocations .

## Poznámky k implementaci

Programovací jazyk může být C/C++\
Pro syslog použijte standardní logovací rutinu syslog (man 3 syslog, nebo příklad zde)\
Lze využít knihovnu libpcap\
Pro práci s terminálem lze využít např. knihovny ncurses při programování v jazyce C\
Lze předpokládat, že pcap/síťové rozhraní bude mít k dispozici kompletní DHCP komunikaci, tj. jako kdyby byl nástroj spuštěn přímo na DHCP serveru.
## Odevzdání:

### Odevzdaný projekt musí obsahovat:

* soubor se zdrojovým kódem
* funkční Makefile pro překlad zdrojového souboru
* dokumentaci (soubor manual.pdf), která bude obsahovat uvedení do problematiky, návrhu aplikace, popis implementace, základní informace o programu, návod na použití. V dokumentaci se očekává následující: titulní strana, obsah, logické strukturování textu, přehled nastudovaných informací z literatury, popis zajímavějších pasáží implementace, použití vytvořených programů a literatura
* soubor dhcp-stats.1 ve formátu a syntaxi manuálové stránky - viz https://liw.fi/manpages/
* Vypracovaný projekt uložený v archívu .tar a se jménem xlogin00.tar odevzdejte elektronicky přes IS. Soubor nekomprimujte.
 
