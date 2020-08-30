#include <iostream>

#include <cstring>

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <pcap.h>

pcap_t* g_handle_1 = nullptr;
pcap_t* g_handle_2 = nullptr;

void forward_onto_1(u_char* frame, unsigned frame_len)
{
    if ( pcap_inject(g_handle_1, frame, frame_len) == -1 )
    {
        pcap_perror(g_handle_1, 0);
        pcap_close(g_handle_1);
        exit(7);
    }
}

void get_new_frame_2(u_char* dummy, const struct pcap_pkthdr* frame_hdr, u_char* frame)
{
    unsigned int frame_len = frame_hdr->len;
    unsigned int caplen = frame_hdr->caplen;

    const ether_header* ethr_frame = (const ether_header*)frame;
    uint16_t eth_type = ethr_frame->ether_type;
    if ( ntohs(eth_type) == ETHERTYPE_IP )
    {
        const ip* ip_pkt = (const ip*)(frame + ETHER_HDR_LEN);
        const char* str_ip = inet_ntoa(ip_pkt->ip_src);
        if ( !strcmp(str_ip, "192.168.1.5") )
            return;

        std::cout << "HNDL_2:src IP:" << str_ip << std::endl;
    }
    
    forward_onto_1(frame, frame_len);
}

void forward_onto_2(u_char* frame, unsigned frame_len)
{
    if ( pcap_inject(g_handle_2, frame, frame_len) == -1 )
    {
        pcap_perror(g_handle_2, 0);
        pcap_close(g_handle_2);
        exit(7);
    }
}

void get_new_frame_1(u_char* dummy, const struct pcap_pkthdr* frame_hdr, u_char* frame)
{
    unsigned int frame_len = frame_hdr->len;
    unsigned int caplen = frame_hdr->caplen;

    const ether_header* ethr_frame = (const ether_header*)frame;
    uint16_t eth_type = ethr_frame->ether_type;
    if ( ntohs(eth_type) == ETHERTYPE_IP )
    {
        const ip* ip_pkt = (const ip*)(frame + ETHER_HDR_LEN);
        const char* str_ip = inet_ntoa(ip_pkt->ip_src);
        if ( !strcmp(str_ip, "192.168.1.5") )
            return;

        std::cout << "HNDL_2:src IP:" << str_ip << std::endl;
    }
    
    forward_onto_2(frame, frame_len);   
}

void init_bridge(const char* dev_1, const char* dev_2)
{
    char err_buf_1[PCAP_ERRBUF_SIZE];
    char err_buf_2[PCAP_ERRBUF_SIZE];

    g_handle_1 = pcap_open_live(dev_1, BUFSIZ, 1, 1, err_buf_1);
    g_handle_2 = pcap_open_live(dev_2, BUFSIZ, 1, 1, err_buf_2);

    if ( pcap_setnonblock(g_handle_1, 1, err_buf_1) == -1 )
    {
        std::cout << "error setting handle_1: " << err_buf_1 << std::endl;
        exit(1);
    }

    if ( pcap_setnonblock(g_handle_2, 1, err_buf_2) == -1 )
    {
        std::cout << "error setting handle_2: " << err_buf_2 << std::endl;
        exit(1);
    }

    if ( pcap_setdirection(g_handle_1, PCAP_D_IN) == -1 )
    {
        std::cout << "error setting direction for handle_1: " << err_buf_1 << std::endl;
        exit(1);
    }

    if ( pcap_setdirection(g_handle_2, PCAP_D_IN) == -1 )
    {
        std::cout << "error setting direction for handle_2: " << err_buf_2 << std::endl;
        exit(1);
    }

    std::cout << "bridge successfully installed" << std::endl;
}

void run_bridge()
{
    while ( true )
    {
        if ( pcap_dispatch(g_handle_1, 1, (pcap_handler) get_new_frame_1, (u_char *) NULL) < 0 )
        {
            pcap_perror(g_handle_1, 0);
            pcap_close(g_handle_1);
            exit(8);
        }
        
        if ( pcap_dispatch(g_handle_2, 1, (pcap_handler) get_new_frame_2, (u_char *) NULL) < 0 )
        {
            pcap_perror(g_handle_2, 0);
            pcap_close(g_handle_2);
            exit(8);
        }
    }
}

int main(int argc, char* argv[])
{
    init_bridge(argv[1], argv[2]);

    run_bridge();

    return 0;
}

