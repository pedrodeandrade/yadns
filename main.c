#include <stdlib.h>
#include <time.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_ether.h>
#include <rte_cycles.h>


#define NB_MBUFS 8191
#define RX_RING_SIZE 1024
#define BURST_SIZE 64
#define MBUF_CACHE_SIZE (BURST_SIZE * 1.5)
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1
#define TOTAL_RX_QUEUES 1

static volatile bool force_quit;

static int init_port(u_int16_t port,struct rte_mempool *mbuf_pool){
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

int burst = 0;
static int lcore_main(__rte_unused void *arg)
{
    unsigned int lcore_id = rte_lcore_id();
    RTE_LOG(INFO, APP, "Core %d is RUNNING\n", lcore_id);
    
    struct rte_mbuf* pckt_buffer[BURST_SIZE];
    int pckt_count = 0;
    
    while(!force_quit)
    {
        u_int16_t nb_rx = rte_eth_rx_burst(0, 0, pckt_buffer, BURST_SIZE);

        if (unlikely(nb_rx <= 0))
            continue;
        
        RTE_LOG(INFO, APP, "Packets receive in burst %d: %d\n", burst, nb_rx);
        for (int i = 0; i < nb_rx; i++)
        {
            rte_pktmbuf_free(pckt_buffer[i]);
        }

        burst++;

        pckt_count++;
    }

    RTE_LOG(INFO, APP, "lcore main finished\n");
    
    return 0;
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
    struct rte_mempool * mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
        NB_MBUFS,
        MBUF_CACHE_SIZE,
        0, 
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE,"mbuff_pool create failed\n");

    int port_id = 0;
    
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

    unsigned int lcore_id;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_remote_launch(lcore_main, NULL, lcore_id);
    }

    rte_eal_mp_wait_lcore();

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}
