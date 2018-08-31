#include <pcap.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <time.h>

#define CAP_PACKETS 1000000
static volatile int keepRunning = 1;
static char my_ip6[INET6_ADDRSTRLEN];

void intHandler (int dummy) {
  keepRunning = 0;
}

char * get_mac_addr( char* name)
{
	struct ifreq ifr;
	int sd, merr;
	sd = socket ( PF_INET, SOCK_STREAM, 0 );
	if ( sd < 0 )	{
	    printf("if_up: socket error: %s ", strerror ( errno ) );
	}
	memset ( &ifr, 0, sizeof ( ifr ) );
	sprintf ( ifr.ifr_name, "%s", name );
	merr=ioctl ( sd, SIOCGIFHWADDR, &ifr );
	if ( merr < 0 )	{
	    close ( sd );
	}
	close ( sd );
	char buff[4000];
	sprintf(buff,"%02x:%02x:%02x:%02x:%02x:%02x\n",
		(int) ((unsigned char *) &ifr.ifr_hwaddr.sa_data)[0],   (int) ((unsigned char *) &ifr.ifr_hwaddr.sa_data)[1],
      (int) ((unsigned char *) &ifr.ifr_hwaddr.sa_data)[2],   (int) ((unsigned char *) &ifr.ifr_hwaddr.sa_data)[3],
      (int) ((unsigned char *) &ifr.ifr_hwaddr.sa_data)[4],   (int) ((unsigned char *) &ifr.ifr_hwaddr.sa_data)[5]);
  char *mac = malloc (sizeof (char) * ETHER_ADDR_LEN);
  mac = buff;
  return mac;
}

void removeSpaces(char str[]) {
    int i, j;
    for (i = 0; str[i] != 0; i ++){
        while (isspace(str[i])){
            for(j = i; str[j] != 0; j ++){
                str[j] = str[j + 1];
            }
        }
    }
}

char * getAddr (char *device)  {
  int fd;
  struct ifreq ifr;
  char *my_ip = malloc (sizeof (char) * INET_ADDRSTRLEN);
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, device, IFNAMSIZ-1);
  ioctl(fd, SIOCGIFADDR, &ifr);
  close(fd);
  my_ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
  return my_ip;
}

void getAddr6(char *device) {
  struct ifaddrs *ifa, *ifa_tmp;
  if (getifaddrs(&ifa) == -1) {
      perror("getifaddrs failed");
      exit(1);
  }
  ifa_tmp = ifa;
  while (ifa_tmp) {
      if ((ifa_tmp->ifa_addr) && (ifa_tmp->ifa_addr->sa_family == AF_INET6) && (strcmp(device, ifa_tmp->ifa_name)==0)) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
        inet_ntop(AF_INET6, &in6->sin6_addr, my_ip6, sizeof(my_ip6));
      }
      ifa_tmp = ifa_tmp->ifa_next;
  }
  freeifaddrs(ifa);
}

int main(int argc, char *argv[]) {
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevsp, *devsp;
  pcap_t *handle;
  struct pcap_pkthdr hdr;
  const u_char *packet;
  struct ether_header *eptr;
  struct ethhdr *ehdr;
  struct ip *ipptr;
  struct ip6_hdr *ip6ptr;
  struct tcphdr *tcpptr;
  struct tcphdr *tcp6ptr;
  u_char *ptr;
  struct bpf_program fp;
	char filter_exp[1024] = "tcp";
	bpf_u_int32 mask;
	bpf_u_int32 net;
  int n, len, full_len = 0;
  int my_mac_src = 0, my_mac_dst = 0, ssh = 0, telnet = 0, smtp = 0, http = 0, https = 0, others = 0;
  char ip6_src[INET6_ADDRSTRLEN];
  char ip6_dst[INET6_ADDRSTRLEN];
  struct timeval t1, t2;
  double elapsedTime;
  //Wybor interfejsu
  if(argv[1] == NULL)  {
    if(pcap_findalldevs(&alldevsp, errbuf) == -1)  {
      printf("Blad! Nie znaleziono urzadzen! %s", errbuf);
      exit(1);
    } else {
      printf("Dostepne interfejsy: \n \n");
      devsp = alldevsp;
      while(devsp != NULL)  {
        printf("%s : %s \n", devsp->name, devsp->description);
        devsp = devsp->next;
      }
      pcap_freealldevs(alldevsp);
    }
    printf("\nWybierz interfejs do nasluchiwania otwierajac program za pomoca komendy ./mytcpsniffer <nazwa_interfejsu>\n");
    exit(1);
  }
  //zwracanie sieci i maski naszego urzadzenia
  dev = argv[1];
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Nie udalo sie uzyskac informacji o sieci w urzadzeniu %s\n", dev);
    net = 0;
    mask = 0;
  }
  //Sprawdz czy dany interfejs istnieje
  printf("Wybrany do analizy interfejs: %s\n", dev);
  handle = pcap_open_live(dev , 100 , 1 , 0 , errbuf);
  //pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *errbuf)
  if (handle == NULL)  {
    fprintf(stderr, "Blad przy otwieraniu interfejsu %s : %s\n" , dev , errbuf);
    exit(1);
  }
  const char *my_ip = getAddr(dev);
  getAddr6(dev);
  char *my_mac;
  char macSrc[18], macDst[18];
  my_mac = get_mac_addr(dev);
  removeSpaces(my_mac);
  printf("Adres MAC interfejsu: %s\n", my_mac);
  printf("Adres IP interfejsu: %s\n", my_ip);
  printf("Adres IPv6 interfejsu: %s\n", my_ip6);
  printf("Adres sieci wybranego do analizy interfejsu: %s\n", inet_ntop(AF_INET, &net, ip6_src, sizeof(ip6_src)));
  printf("Maska wybranego do analizy interfejsu: %s\n", inet_ntop(AF_INET, &mask, ip6_dst, sizeof(ip6_dst)));
  //Filtrowanie, ustalanie reguly
  //int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask);
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Nieprawidlowy filtr %s: %s\n", filter_exp, pcap_geterr(handle));
    exit(1);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Nie udalo sie ustawic filtru %s: %s\n", filter_exp, pcap_geterr(handle));
    exit(1);
   }
  gettimeofday(&t1, NULL);

  // Lapanie pakietow
  for(n=0; n<CAP_PACKETS; n++) {
    packet = pcap_next(handle, &hdr);
    ehdr = (struct ethhdr *) packet;
    ipptr = (struct ip *)(packet+sizeof(struct ethhdr));
    ip6ptr = (struct ip6_hdr *)(packet+sizeof(struct ethhdr));
    tcpptr = (struct tcphdr *)(packet+sizeof(struct ethhdr)+sizeof(struct ip));
    tcp6ptr = (struct tcphdr *)(packet+sizeof(struct ethhdr)+sizeof(struct ip6_hdr));

    printf("\n---Zlapano pakiet %d ---\n", n+1);
    printf("\nDługość: %d\n", hdr.len);
    len = hdr.len;
    full_len += len;
    printf("EtherType: 0x%x\n", ntohs(ehdr->h_proto));
    snprintf(macSrc, sizeof(macSrc), "%02x:%02x:%02x:%02x:%02x:%02x",
      (int) ehdr->h_source[0], (int) ehdr->h_source[1], (int) ehdr->h_source[2],
      (int) ehdr->h_source[3], (int) ehdr->h_source[4],(int) ehdr->h_source[5] );
    printf("Zrodlowy adres MAC: %s\n", macSrc);
    snprintf(macDst, sizeof(macDst), "%02x:%02x:%02x:%02x:%02x:%02x",
      (int) ehdr->h_dest[0], (int) ehdr->h_dest[1], (int) ehdr->h_dest[2],
      (int) ehdr->h_dest[3], (int) ehdr->h_dest[4],(int) ehdr->h_dest[5] );
    printf("Docelowy adres MAC: %s\n", macDst);
    if(strcmp(macSrc, my_mac)==0) {
      ++my_mac_src;
    } else if (strcmp(macDst, my_mac)==0)  {
      ++my_mac_dst;
    }
    if(ntohs(ehdr->h_proto) == ETHERTYPE_IP)  {
      printf("Zrodlowy adres IP: %s\n", inet_ntoa(ipptr->ip_src));
      printf("Docelowy adres IP: %s\n", inet_ntoa(ipptr->ip_dst));
      printf("Wersja IP: %d\n", (ipptr->ip_v));
      printf("Zrodlowy port: %u\n", ntohs(tcpptr->th_sport));
      printf("Docelowy port: %u\n", ntohs(tcpptr->th_dport));
      switch(ntohs(tcpptr->th_sport))  {
        case 22:
            ++ssh;
            break;
        case 23:
            ++telnet;
            break;
        case 25:
            ++smtp;
            break;
        case 80:
            ++http;
            break;
        case 443:
            ++https;
            break;
        default:
            ++others;
            break;
      }
      switch(ntohs(tcpptr->th_dport))  {
        case 22:
            ++ssh;
            break;
        case 23:
            ++telnet;
            break;
        case 25:
            ++smtp;
            break;
        case 80:
            ++http;
            break;
        case 443:
            ++https;
            break;
        default:
            ++others;
            break;
      }
      printf("Numer sekwencyjny: %u\n",ntohl(tcpptr->seq));
      printf("Numer potwierdzenia: %u\n",ntohl(tcpptr->ack_seq));
      printf("Flagi: URG: %d, ACK: %d, PSH: %d, RST: %d, SYN: %d, FIN: %d\n",(unsigned int)tcpptr->urg, (unsigned int)tcpptr->ack, (unsigned int)tcpptr->psh, (unsigned int)tcpptr->rst, (unsigned int)tcpptr->syn, (unsigned int)tcpptr->fin);
      printf("Szerokosc okna: %d\n",ntohs(tcpptr->window));
      printf("Suma kontrolna: %d\n",ntohs(tcpptr->check));
      printf("Wskaznik priorytetu: %d\n",tcpptr->urg_ptr);
    } else if(ntohs(ehdr->h_proto) == ETHERTYPE_IPV6) {
      printf("\nZrodlowy adres IP: %s\n", inet_ntop(AF_INET6, &ip6ptr->ip6_src, ip6_src, sizeof(ip6_src)));
      printf("Docelowy adres IP: %s\n", inet_ntop(AF_INET6, &ip6ptr->ip6_dst, ip6_dst, sizeof(ip6_dst)));
      printf("Zrodlowy port: %u\n", ntohs(tcp6ptr->th_sport));
      printf("Docelowy port: %u\n", ntohs(tcp6ptr->th_dport));
      switch(ntohs(tcp6ptr->th_sport))  {
        case 22:
            ++ssh;
            break;
        case 23:
            ++telnet;
            break;
        case 25:
            ++smtp;
            break;
        case 80:
            ++http;
            break;
        case 443:
            ++https;
            break;
        default:
            ++others;
            break;
      }
      switch(ntohs(tcp6ptr->th_dport))  {
        case 22:
            ++ssh;
            break;
        case 23:
            ++telnet;
            break;
        case 25:
            ++smtp;
            break;
        case 80:
            ++http;
            break;
        case 443:
            ++https;
            break;
        default:
            ++others;
            break;
      }
      printf("Numer sekwencyjny: %u\n",ntohl(tcp6ptr->seq));
      printf("Numer potwierdzenia: %u\n",ntohl(tcp6ptr->ack_seq));
      printf("Flagi: URG: %d, ACK: %d, PSH: %d, RST: %d, SYN: %d, FIN: %d\n",(unsigned int)tcp6ptr->urg, (unsigned int)tcp6ptr->ack, (unsigned int)tcp6ptr->psh, (unsigned int)tcp6ptr->rst, (unsigned int)tcp6ptr->syn, (unsigned int)tcp6ptr->fin);
      printf("Szerokosc okna: %d\n",ntohs(tcp6ptr->window));
      printf("Suma kontrolna: %d\n",ntohs(tcp6ptr->check));
      printf("Wskaznik priorytetu: %d\n",tcp6ptr->urg_ptr);
    } else  {
      printf("Pakiet inny niż IP\n");
      ++others;
    }
    signal(SIGINT, intHandler);
    fflush(stdout); //fflush - wypróżnienie buforów strumienia
    //reakcja na ctrl+c, zliczanie pakietow
    if(n == CAP_PACKETS - 1 || keepRunning == 0)  {
      break;
    }
  }
  gettimeofday(&t2, NULL);
  elapsedTime = (t2.tv_sec - t1.tv_sec);
  double bps = full_len/elapsedTime;
  printf("\n------PODSUMOWANIE------\n");
  printf("Liczba pakietow: %d\n", n+1);
  printf("Liczba pakietow wyslanych: %d\n", my_mac_src);
  printf("Liczba pakietow odebranych: %d\n", my_mac_dst);
  printf("Liczba uzyc aplikacji: SSH %d Telnet %d SMTP %d HTTP %d HTTPS %d Inne %d\n", ssh, telnet, smtp, http, https, others);
  printf("Liczba bajtow: %d\n", full_len);
  printf("Przyblizony czas przechwytywania: %lf\n", elapsedTime);
  printf("Przyblizona szybkosc przechwytywania: %lf bps\n", bps);
  pcap_close(handle);
}
