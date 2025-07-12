//
// Created by pedro-andrade on 6/8/25.
//

#ifndef SNIFFER_BATCH_QUEUE_MESSAGE_H
#define SNIFFER_BATCH_QUEUE_MESSAGE_H

#include <rte_mbuf.h>

struct batch_queue_message{
    int batch_number;
    int batch_size;
    uint64_t* packets_timestamps;
    uint64_t timestamp_nsec;
    struct rte_mbuf** batch;
};

#endif //SNIFFER_BATCH_QUEUE_MESSAGE_H
