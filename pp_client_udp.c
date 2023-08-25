#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#define SERVER_IP "192.168.56.102"
#define SERVER_PORT 1234

/**
 * Packet structure:
 * ,------------------------------------------------,
 * | ethhdr | iphdr | udphdr | id | ts1 | ts2 | ts3 |
 * '------------------------------------------------'
 * id = 0 -> PING
 * id = 1 -> PONG
*/
struct pp_payload {
    uint64_t round;
    uint8_t id;
    uint64_t ts1;
    uint64_t ts2;
    uint64_t ts3; 
};


int main() {
    int clientSocket;
    struct sockaddr_in serverAddr;
    socklen_t addrSize = sizeof(serverAddr);
    struct pp_payload payload;    
    struct timespec ts1_timespec;

    // Create UDP socket
    clientSocket = socket(PF_INET, SOCK_DGRAM, 0);
    if (clientSocket == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);


    memset(&payload, 0, sizeof(struct pp_payload));
    payload.round = 3;
    payload.id = 0; // PING

    clock_gettime(CLOCK_MONOTONIC, &ts1_timespec);

    payload.ts1 = ts1_timespec.tv_sec * 1000000000LL + ts1_timespec.tv_nsec;
    
    printf("ts1:%lu\n", payload.ts1);

    int bytesSent = sendto(clientSocket, &payload, sizeof(payload), 0, (struct sockaddr*)&serverAddr, addrSize);
    if (bytesSent == -1) {
        perror("Sending data failed");
        exit(EXIT_FAILURE);
    }

    // Close the socket
    close(clientSocket);

    return 0;
}
