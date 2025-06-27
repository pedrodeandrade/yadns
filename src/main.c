#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_ether.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_pcapng.h>
#include <rte_errno.h>
#include <cryptopANT.h>
#include <netinet/in.h>

#include "batch_queue_message.h"

#define NB_MBUFS 8191
#define RX_RING_SIZE 1024
#define BURST_SIZE 64
#define MBUF_CACHE_SIZE (BURST_SIZE * 4)
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1
#define TOTAL_RX_QUEUES 1
#define IPV4_PROTO 2048
#define IPV6_PROTO 34525
#  define SSIZE_MAX	LONG_MAX

static volatile bool force_quit;
static struct rte_mempool* mbuf_pool_persist;
static int closing_pcap = 0;
rte_pcapng_t* pcapng;

void gracefully_shutdown(int signal)
{
    if (signal != SIGINT && signal != SIGTERM)
        return;

    if (pcapng != NULL)
    {
        closing_pcap = 1;
        RTE_LOG(INFO,APP,"\n ---- CLOSING PCAPNG ----");
        rte_pcapng_close(pcapng);
    }
}


static int init_port(u_int16_t port,struct rte_mempool* mbuf_pool){
    struct rte_ether_addr addr;
    
    rte_eth_macaddr_get(port, &addr);
    RTE_LOG(INFO, APP, "Port %u default MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            port,
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);

    struct rte_eth_dev_info dev_info = {};
    rte_eth_dev_info_get(port, &dev_info);

    RTE_LOG(INFO, APP, "Number RX queues available = %d", dev_info.nb_rx_queues);

    // configure the ethernet device
    struct rte_eth_conf port_conf = { };
    int ret = rte_eth_dev_configure(port,
                                    TOTAL_RX_QUEUES,
                                0,
                                &port_conf);
    if (ret != 0)
        return ret;

    return rte_eth_rx_queue_setup(port,0,RX_RING_SIZE,
                           rte_eth_dev_socket_id(port),
                           NULL, mbuf_pool);
}

static int check_link_status(int port_id)
{
    struct rte_eth_link link;

    rte_eth_link_get(port_id,&link);

    if(link.link_status == RTE_ETH_LINK_DOWN){
        RTE_LOG(INFO,APP,"Port: %u Link DOWN\n",port_id);
        return -1;
    }

    RTE_LOG(INFO,APP,"Port: %u Link UP Speed %u\n",
            port_id,link.link_speed);
    
    return 0;
}

static u_int16_t get_l3_type(char *pointer)
{
    u_int8_t slb= 0;
    u_int8_t lb= 0;
    slb= *(pointer - 2);// second last byte of ETH layer
    lb= *(pointer - 1);// last byte of ETH layer
    return (slb* 256) +lb;
}

static int batch_seq_number = 0;
static struct rte_ring* batches_queue;

static int lcore_main(__rte_unused void *arg)
{
    unsigned int lcore_id = rte_lcore_id();
    RTE_LOG(INFO, APP, "[lcore_main] - Core %d is RUNNING\n", lcore_id);
    
    while(!force_quit)
    {
        struct rte_mbuf** pckt_buffer = (struct rte_mbuf**)rte_malloc(NULL, sizeof(struct rte_mbuf*) * BURST_SIZE, 0);
        u_int16_t nb_rx = rte_eth_rx_burst(0, 0, pckt_buffer, BURST_SIZE);

        if (nb_rx <= 0){
            rte_free(pckt_buffer);
            continue;
        }
        
        RTE_LOG(INFO, APP, "[lcore_main] - Packets receive in burst %d: %d\n", batch_seq_number, nb_rx);

        RTE_LOG(DEBUG, APP, "[lcore_main] - Allocating message\n");
        struct batch_queue_message* message = (struct batch_queue_message*)rte_malloc(NULL, sizeof(struct batch_queue_message), 0);
        RTE_LOG(DEBUG, APP, "[lcore_main] - Message allocated\n");
        
        message->batch_number = batch_seq_number;
        message->batch_size = nb_rx;
        message->batch = pckt_buffer;

        RTE_LOG(INFO, APP, "[lcore_main] - Enqueuing batch\n");
        rte_ring_enqueue(batches_queue, message);
        RTE_LOG(INFO, APP, "[lcore_main] - Batch enqueued\n");

        batch_seq_number++;
    }

    RTE_LOG(INFO, APP, "lcore main finished\n");
    
    return 0;
}

static int lcore_packet_processing(__rte_unused void* arg)
{
    RTE_LOG(INFO, APP, "[lcore_packet_processing] - Packet processing starting\n");
    
    while (1)
    {
        void* message;
        
        int dequeue = rte_ring_dequeue(batches_queue, &message);
        if (dequeue != 0)
            continue;

        RTE_LOG(INFO, APP, "[lcore_packet_processing] - Batch dequeue successfully\n");

        struct batch_queue_message* batch_message = (struct batch_queue_message*) message;
        
        RTE_LOG(INFO, APP, "[lcore_packet_processing] - Batch %d dequeued from ring with %d packets\n", batch_message->batch_number, batch_message->batch_size);

        for (int i = 0; i < batch_message->batch_size; i++) {
            struct rte_mbuf* pkt_buffer = batch_message->batch[i];

            // TODO Calculate timestamp
            
            struct rte_ether_hdr* ethernet_header = rte_pktmbuf_mtod(pkt_buffer, struct rte_ether_hdr *);

            void* next_proto_pointer = (void*) ((unsigned char*) ethernet_header + sizeof (struct rte_ether_hdr));
            u_int16_t next_proto = get_l3_type(next_proto_pointer); // holds last two byte value of ETH Layer
            
            if (next_proto == IPV4_PROTO){
                RTE_LOG(INFO, APP, "[lcore_packet_processing] - IPV4 PACKET ARRIVED\n");
                
                struct rte_ipv4_hdr* ipv4_header = rte_pktmbuf_mtod_offset(pkt_buffer, struct rte_ipv4_hdr*, sizeof (struct rte_ether_hdr));

                // BIG-ENDIAN TO LITTLE-ENDIAN (network to host byte order)
                u_int32_t ip_src = rte_bswap32(ipv4_header->src_addr);
                u_int32_t ip_dst = rte_bswap32(ipv4_header->dst_addr);
                
                ipv4_header->src_addr = scramble_ip4(ip_src, 0);
                ipv4_header->dst_addr = scramble_ip4(ip_dst, 0);
            }
            else if (next_proto == IPV6_PROTO){
                RTE_LOG(INFO, APP, "[lcore_packet_processing] - IPV6 PACKET ARRIVED\n");
                
                struct rte_ipv6_hdr* ipv6_header = rte_pktmbuf_mtod_offset(pkt_buffer, struct rte_ipv6_hdr*, sizeof (struct rte_ether_hdr));

                struct in6_addr ip_src = {};
                struct in6_addr ip_dst = {};
                rte_memcpy(ip_src.s6_addr, ipv6_header->src_addr, 16);
                rte_memcpy(ip_dst.s6_addr, ipv6_header->dst_addr, 16);

                scramble_ip6(&ip_src, 0);
                scramble_ip6(&ip_dst, 0);

                rte_memcpy(ipv6_header->src_addr, ip_src.s6_addr, 16);
                rte_memcpy(ipv6_header->dst_addr, ip_dst.s6_addr, 16);
            }
        }
        
        // TODO PUT THE MESSAGE IN THE STORAGE RING
    }
}


static int lcore_packet_persist(__rte_unused void* args){
    RTE_LOG(INFO, APP, "[lcore_packet_processing] - Packet storage starting\n");

    while (1)
    {
        void* message;

        // TODO Retrieve the packets from the appropriate queue
        int dequeue = rte_ring_dequeue(batches_queue, &message);
        if (dequeue != 0)
            continue;

        RTE_LOG(INFO, APP, "[lcore_packet_processing] - Storage dequeue successfully\n");

        struct batch_queue_message* batch_message = (struct batch_queue_message*)message;

        RTE_LOG(INFO, APP, "[lcore_packet_processing] - Batch %d dequeued from ring with %d packets\n", batch_message->batch_number, batch_message->batch_size);

        struct rte_mbuf* mbufs_persist[batch_message->batch_size];

        for (int i = 0; i < batch_message->batch_size; i++){
            mbufs_persist[i] = rte_pcapng_copy(
                    0,
                    0,
                    batch_message->batch[i],
                    mbuf_pool_persist,
                    UINT32_MAX,
                    RTE_PCAPNG_DIRECTION_IN,
                    NULL
            );

            if (mbufs_persist[i] == NULL){
                RTE_LOG(ERR, APP, "[lcore_packet_processing] - Error copying packet %d from batch %d", i, batch_message->batch_number);
                rte_exit(1, "fodas4");
            }

            rte_pktmbuf_free(batch_message->batch[i]);
        }

        if (closing_pcap == 1)
            return 0;

        ssize_t packets_persisted = rte_pcapng_write_packets(pcapng, mbufs_persist, batch_message->batch_size);
        if (packets_persisted == -1)
            RTE_LOG(ERR, APP, "[lcore_packet_processing] - Error persistin packets to pcapng file ERRNO %s", rte_strerror(rte_errno));
    }
}

int main(int argc, char **argv)
{
    force_quit = false;
    int return_status;

    /* The EAL arguments are passed when calling the program */
    int parsed_eal_args = rte_eal_init(argc, argv);
    if (parsed_eal_args < 0)
        rte_exit(EXIT_FAILURE,"EAL Init failed\n");

    argc -= parsed_eal_args;
    argv += parsed_eal_args;

    uint16_t ports_number = rte_eth_dev_count_avail();
    if(ports_number < 1)
        rte_exit(EXIT_FAILURE,"No ports available in the NIC\n");

    RTE_LOG(INFO, APP, "Number of ports:%u\n", ports_number);

    /* Create a new mbuf mempool */
    struct rte_mempool* mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
        NB_MBUFS,
        MBUF_CACHE_SIZE,
        0, 
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());

    int port_id = 0;
    
    struct rte_eth_dev_info dev_info = {};
    if (rte_eth_dev_info_get(port_id, &dev_info) != 0) {
        rte_exit(EXIT_FAILURE, "Failed to get device info for port %u\n", port_id);
    }
    
    mbuf_pool_persist = rte_pktmbuf_pool_create("MBUF_POOL_PERSIST",
        NB_MBUFS,
        MBUF_CACHE_SIZE,
        0,
        RTE_MBUF_DEFAULT_BUF_SIZE + 28, // TODO DECLARE 28 AS A MACRO, IT'S THE EXTRA SIZE REQUIRED BY THE PCAPNG FORMAT
        rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE,"mbuff_pool create failed\n");
    
    if(init_port(port_id, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE,"port init failed\n");

    // start the ethernet port
    return_status = rte_eth_dev_start(port_id);
    if (return_status < 0)
        return return_status;

    // Enable RX in promiscuous mode for the Ethernet device
    rte_eth_promiscuous_enable(port_id);

    if (check_link_status(port_id) < 0)
        RTE_LOG(ERR,APP,"Some ports are down\n");

    RTE_LOG(INFO, APP, "%d lcore available\n", rte_lcore_count());
    
    // TODO Get the file name from the app parameters
    FILE* output = fopen("dump/teste.pcapng", "w");
    if (output == NULL)
        rte_exit(EXIT_FAILURE, "error creating file to persist packets");

    int fd = fileno(output);
    pcapng = rte_pcapng_fdopen(fd, NULL, NULL, NULL, NULL);
    if (pcapng == NULL)
        rte_exit(EXIT_FAILURE, "error opening the file to persist packets");

    if (rte_pcapng_add_interface(pcapng, port_id, NULL, NULL, NULL) < 0)
        rte_exit(EXIT_FAILURE, "error adding interface");

    RTE_LOG(INFO, APP, "FD NUMBER %d\n", fd);

    batches_queue = rte_ring_create("BATCHES_RING", 32, rte_socket_id(), RING_F_SP_ENQ | RING_F_MC_HTS_DEQ);
    int key_created = scramble_init_from_file("config/anom.key", SCRAMBLE_BLOWFISH, SCRAMBLE_BLOWFISH, 0);
    if (key_created < 0)
        rte_exit(EXIT_FAILURE, "ERROR CREATING cryptopANT key");
    

    signal(SIGTERM, gracefully_shutdown);

    rte_eal_remote_launch(lcore_main, NULL, 1);
    rte_eal_remote_launch(lcore_packet_processing, NULL, 2);

    rte_eal_mp_wait_lcore();
    
    rte_eal_cleanup();

    return 0;
}
