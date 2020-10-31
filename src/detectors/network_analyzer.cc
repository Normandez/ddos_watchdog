//------------------------------------------------------------------------------------
// MIT License
//
// Copyright (c) 2020 Alexandr Sergienko
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//------------------------------------------------------------------------------------
// network_analyzer.cc author Oleksandr Serhiienko <sergienko.9711@gmail.com>

#include "network_analyzer.h"

#include <iomanip>
#include <sstream>
#include <string>

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "core/logger.h"
#include "core/net_defines.h"

static void print_arp(const ether_arp* pkt, const std::string& prefix_log)
{
    const unsigned short int proto_type = ntohs(pkt->arp_pro);
    const unsigned short int operation_code = ntohs(pkt->arp_op);
    const uint8_t* sha = pkt->arp_sha;
    const uint8_t* spa = pkt->arp_spa;
    const uint8_t* tha = pkt->arp_tha;
    const uint8_t* tpa = pkt->arp_tpa;

    std::stringstream ss;
    std::string pkt_line = prefix_log + ": ";
    pkt_line += ether_ntoa((ether_addr*)sha);
    pkt_line += " → ";
    pkt_line += ether_ntoa((ether_addr*)tha);
    pkt_line += " ARP";
    ss << "0x" << std::setfill('0') << std::setw(4)
        << std::hex << proto_type;
    pkt_line += " PTYPE " + ss.str();

    if ( operation_code == ARPOP_REQUEST )
    {
        pkt_line += " Who has " + std::to_string(tpa[0]);
        pkt_line += "." + std::to_string(tpa[1]);
        pkt_line += "." + std::to_string(tpa[2]);
        pkt_line += "." + std::to_string(tpa[3]);
        pkt_line += "? ";

        pkt_line += "Tell " + std::to_string(spa[0]);
        pkt_line += "." + std::to_string(spa[1]);
        pkt_line += "." + std::to_string(spa[2]);
        pkt_line += "." + std::to_string(spa[3]);
    }
    else if ( operation_code == ARPOP_REPLY )
    {
        pkt_line += " " + std::to_string(spa[0]);
        pkt_line += "." + std::to_string(spa[1]);
        pkt_line += "." + std::to_string(spa[2]);
        pkt_line += "." + std::to_string(spa[3]);
        pkt_line += " is at ";
        pkt_line += ether_ntoa((ether_addr*)sha);
    }
    else
        pkt_line += " OPER " + std::to_string(operation_code);

    Logger::msg("%s", pkt_line.c_str());
}

static void print_icmp(const icmphdr* hdr, const uint8_t ttl, const std::string& prefix_log)
{
    std::string pkt_line = prefix_log + " ICMP Echo (ping)";
    uint8_t type = hdr->type;
    uint8_t code = hdr->code;
    uint16_t id = ntohs(hdr->un.echo.id);
    uint16_t seq = ntohs(hdr->un.echo.sequence);

    std::stringstream ss;
    ss << "0x" << std::setfill('0') << std::setw(4) << std::hex;
    if ( type == ICMP_ECHO and code == 0 )
    {
        ss << id;
        pkt_line += " request id=" + ss.str();
        pkt_line += ", seq=" + std::to_string(seq);
        pkt_line += ", ttl=" + std::to_string(ttl);
    }
    else if ( type == ICMP_ECHOREPLY and code == 0 )
    {
        ss << id;
        pkt_line += " reply   id=" + ss.str();
        pkt_line += ", seq=" + std::to_string(seq);
        pkt_line += ", ttl=" + std::to_string(ttl);
    }

    Logger::msg("%s", pkt_line.c_str());
}

static void print_tcp(const tcphdr* hdr, const uint16_t pkt_len, const std::string& prefix_log)
{
    std::string pkt_line = prefix_log + " TCP";

    const uint16_t src_port = ntohs(hdr->source);
    const uint16_t dst_port = ntohs(hdr->dest);
    const uint16_t syn = ntohs(hdr->syn);
    const uint16_t ack = ntohs(hdr->ack);
    const uint16_t fin = ntohs(hdr->fin);
    const uint32_t seq = ntohl(hdr->seq);
    const uint32_t ack_seq = ntohl(hdr->ack_seq);
    const uint16_t win_size = ntohs(hdr->window);
    const uint16_t len = pkt_len - (hdr->doff * BYTES_IN_OCTET);

    pkt_line += " " + std::to_string(src_port);
    pkt_line += " →";
    pkt_line += " " + std::to_string(dst_port);

    pkt_line += " [";
    if ( syn and ack )
        pkt_line += "SYN, ACK";
    else if ( fin and ack )
        pkt_line += "FIN, ACK";
    else if ( ack )
        pkt_line += "ACK";
    else if ( syn )
        pkt_line += "SYN";
    pkt_line += "]";

    pkt_line += " Seq=" + std::to_string(seq);
    pkt_line += " Ack=" + std::to_string(ack_seq);
    pkt_line += " Win=" + std::to_string(win_size);
    pkt_line += " Len=" + std::to_string(len);

    Logger::msg("%s", pkt_line.c_str());
}

static void print_udp(const udphdr* hdr, const std::string& prefix_log)
{
    std::string pkt_line = prefix_log + " UDP";

    const uint16_t src_port = ntohs(hdr->source);
    const uint16_t dst_port = ntohs(hdr->dest);
    const uint16_t len = ntohs(hdr->len) - UDP_HDRLEN;

    pkt_line += " " + std::to_string(src_port);
    pkt_line += " →";
    pkt_line += " " + std::to_string(dst_port);
    pkt_line += " Len=" + std::to_string(len);

    Logger::msg("%s", pkt_line.c_str());
}

static inline bool is_first_ip_fragment(const uint16_t frag_off)
{ return ( frag_off & IP_DF ) or !( frag_off & IP_MF ); }

static void print_ip(const ip* pkt, const std::string& prefix_log)
{
    std::string ip_pkt_line = prefix_log + ": ";

    ip_pkt_line += inet_ntoa(pkt->ip_src);
    ip_pkt_line += " → ";
    ip_pkt_line += inet_ntoa(pkt->ip_dst);

    const uint16_t id = ntohs(pkt->ip_id);
    const uint16_t frag_off = ntohs(pkt->ip_off);
    const uint8_t ttl = pkt->ip_ttl;
    const uint16_t next_pkt_len = ntohs(pkt->ip_len) - (uint16_t)pkt->ip_hl * BYTES_IN_OCTET;

    const u_char* raw_ip_pkt = (const u_char*)pkt;
    ip_pkt_line += " ID=" + std::to_string(id);
    switch ( pkt->ip_p )
    {
    case IPPROTO_ICMP:
    {
        const icmphdr* icmp_pkt_hdr =
            (const icmphdr*)(raw_ip_pkt + (pkt->ip_hl * BYTES_IN_OCTET));

        print_icmp(icmp_pkt_hdr, ttl, ip_pkt_line);
        break;
    }
    case IPPROTO_TCP:
    {
        if ( is_first_ip_fragment(frag_off) )
        {
            const tcphdr* tcp_pkt_hdr = (const tcphdr*)(raw_ip_pkt + (pkt->ip_hl * BYTES_IN_OCTET));
            print_tcp(tcp_pkt_hdr, next_pkt_len, ip_pkt_line);
        }
        else
        {
            const uint16_t fragmented_bits = frag_off & IP_OFFMASK;
            ip_pkt_line += " fragmented TCP, Offset=" + std::to_string(fragmented_bits);
            ip_pkt_line += ", Len=" + std::to_string(next_pkt_len);
            Logger::msg("%s", ip_pkt_line.c_str());
        }
        break;
    }
    case IPPROTO_UDP:
    {
        if ( is_first_ip_fragment(frag_off) )
        {
            const udphdr* udp_pkt_hdr = (const udphdr*)(raw_ip_pkt + (pkt->ip_hl * BYTES_IN_OCTET));
            print_udp(udp_pkt_hdr, ip_pkt_line);
        }
        else
        {
            const uint16_t fragmented_bits = frag_off & IP_OFFMASK;
            ip_pkt_line += " fragmented UDP, Offset=" + std::to_string(fragmented_bits);
            ip_pkt_line += ", Len=" + std::to_string(next_pkt_len);
            Logger::msg("%s", ip_pkt_line.c_str());
        }
        break;
    }
    }
}

bool NetworkAnalyzer::analyze(const u_char* pkt, const unsigned int,
    const unsigned long long pkt_num)
{
    std::string prefix_log = "bridge #" + std::to_string(bridge_id);
    prefix_log += ( dir == EXT_TO_INT ) ? "(ext)" : "(int)";
    prefix_log += ": pkt " + std::to_string(pkt_num);

    const ether_header* ethr_frame = (const ether_header*)pkt;
    uint16_t eth_type = ntohs(ethr_frame->ether_type);

    switch ( eth_type )
    {
    case ETHERTYPE_ARP:
    {
        const ether_arp* arp_pkt = (const ether_arp*)(pkt + ETHER_HDR_LEN);
        print_arp(arp_pkt, prefix_log);
        break;
    }
    case ETHERTYPE_IP:
    {
        const ip* ip_pkt = (const ip*)(pkt + ETHER_HDR_LEN);
        print_ip(ip_pkt, prefix_log);
        break;
    }
    }

    return true;
}

