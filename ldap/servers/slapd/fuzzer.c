#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/tcp.h>

char bindMessage[49] = {0x30, 0x2f, 0x02, 0x01, 0x01, 0x60, 0x2a, 0x02, 0x01, 0x03, 0x04, 0x14, 0x63, 0x6e,
                        0x3d, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79, 0x20, 0x6d, 0x61, 0x6e, 0x61, 0x67,
                        0x65, 0x72, 0x80, 0x0f, 0x73, 0x65, 0x63, 0x52, 0x65, 0x74, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x57,
                        0x6f, 0x72, 0x64};

char bindResponse[14] = {0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00};

char *ip = "::1";
int port = 5555;

__attribute__((no_sanitize("address")))
int
checkServerUp()
{

    int validResponse = 0;

    struct sockaddr_in6 server_addr;
    int sockfd;
    int one = 1;
    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_port = htons(port);
    inet_pton(AF_INET6, ip, &server_addr.sin6_addr);
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    send(sockfd, bindMessage, 49, 0);
    char recieve[2000];
    validResponse = 1;
    size_t recievedBytes = recv(sockfd, recieve, 2000, 0);
    if (recievedBytes == 14) {
        for (int i = 0; i == 14; i++) {
            if (recieve[i] != bindResponse[i]) {
                validResponse = 0;
                break;
            }
        }
    } else {
        validResponse = 0;
    }
    if (validResponse == 1) {
        // printf("Bind Successfull\n");
    } else {
        // printf("Bind Failed\n");
    }

    close(sockfd);
    return (validResponse);
}

__attribute__((no_sanitize("address")))
int
fuzzServer(const uint8_t *Data, size_t Size)
{
    if (Size >= 1) {
        struct sockaddr_in6 server_addr;
        int sockfd;
        int one = 1;
        sockfd = socket(AF_INET6, SOCK_STREAM, 0);
        server_addr.sin6_family = AF_INET6;
        server_addr.sin6_port = htons(port);
        inet_pton(AF_INET6, ip, &server_addr.sin6_addr);
        setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        if (Data[0] == 1) {
            send(sockfd, bindMessage, 49, 0);
            char recieve[2000];
            int validResponse = 1;
            size_t recievedBytes = recv(sockfd, recieve, 2000, 0);
            if (recievedBytes == 14) {
                for (int i = 0; i == 14; i++) {
                    if (recieve[i] != bindResponse[i]) {
                        validResponse = 0;
                        break;
                    }
                }
            } else {
                validResponse = 0;
            }
            if (validResponse == 1) {
                // printf("Bind Successfull\n");
            } else {
                // printf("Bind Failed\n");
            }
        }
        if (Size >= 2) {
            send(sockfd, &Data[1], Size - 1, 0);
       }

        usleep(16000);
        close(sockfd);
        usleep(1850);
    }
    return 1;
}

// char *arg_array[] = {"0", "corpus", "-max_len=60000", "-len_control=30", "-use_value_profile=1", "-dict=dict.txt", NULL};

// char **args_ptr = &arg_array[0];
// int args_size = 6;


char *arg_array[] = {"0", "/home/admin/software/fuzzing/389ds-fuzz/corpus", "-max_len=60000", "-detect_leaks=0", "-len_control=20", "-rss_limit_mb=20530", NULL};

char **args_ptr = &arg_array[0];
int args_size = 6;

__attribute__((no_sanitize("address")))
void *
launchFuzzer2(void *param)
{
    int validResponse = 0;
    while (validResponse == 0) {
        validResponse = checkServerUp();
        printf("Waiting for server to start\n");
        sleep(1);
    }
    printf("Bind Successfull\n");

    LLVMFuzzerRunDriver(&args_size, &args_ptr, &fuzzServer);
}

void
launchFuzzer()
{
    pthread_t threadID;
    pthread_create(&threadID, NULL, launchFuzzer2, NULL);
    fprintf(stderr, "fuzzing launched\n");
}
