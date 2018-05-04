#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include "psy_header.h"

#include <libnetfilter_queue/libnetfilter_queue.h>



void dump(unsigned char *pkt, int len)
{
    printf("\n");
    for(int i=0; i<len; i++)
    {
        printf("%02X ",pkt[i]);
    }
    printf("\n");
}

static int callback(struct nfq_q_handle *qhandle, struct nfgenmsg *nfmsg,
                    struct nfq_data *nf_data, void *data)
{
    u_int32_t id=0;
    unsigned char *pkt;
    struct nfqnl_msg_packet_hdr *ph;
//    struct ip_header *ih;
    struct ip_header * ih;
    struct tcp_header *th;

    if((ph = nfq_get_msg_packet_hdr(nf_data)))
        id = ntohl(ph->packet_id);

    nfq_get_payload(nf_data,&pkt);

    ih = (ip_header *)pkt;
    th = (tcp_header *)(pkt+sizeof(ip_header));

    if( ih->ip_version == 4 && (ntohs(th->des_port) == 80 || ntohs(th->src_port) == 80))
    {
        printf("==================Port 80 Blocking================\n");
        printf("IPv%d - DstPort : %d\n",ih->ip_version,ntohs(th->des_port));
        return nfq_set_verdict(qhandle,id,NF_DROP,0,NULL);
    }

    return nfq_set_verdict(qhandle,id,NF_ACCEPT,0,NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *handle;
    struct nfq_q_handle *qhandle;
    int fd;
    int rv;
    char pkt[4096];

    printf("Library handle OPEN!\n");
    if(!(handle = nfq_open()))
    {
        fprintf(stderr,"nfq_open ERROR\n");
        exit(1);
    }

    if(nfq_unbind_pf(handle,AF_INET) < 0)
    {
        fprintf(stderr,"nfq_unbind_pf ERROR\n");
        exit(1);
    }

    if(nfq_bind_pf(handle,AF_INET) < 0)
    {
        fprintf(stderr,"nfq_bind_pf ERROR\n");
        exit(1);
    }

    if(!(qhandle = nfq_create_queue(handle,0,&callback,NULL)))
    {
        fprintf(stderr,"nfq_create_queue ERROR\n");
        exit(1);
    }

    if(nfq_set_mode(qhandle, NFQNL_COPY_PACKET, 0xffff) <0)
    {
        fprintf(stderr,"can't set packet copy mode");
        exit(1);
    }

    fd = nfq_fd(handle);

    while(true)
    {
        if((rv = recv(fd,pkt,sizeof(pkt),0))>= 0)
        {
            nfq_handle_packet(handle,pkt,rv);
            continue;
        }

        if(rv < 0 && errno == ENOBUFS)
        {
            printf("losing packet!\n");
            continue;
        }

        perror("recv failed!\n");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qhandle);

    printf("closing library handle!\n");
    nfq_close(handle);

}
