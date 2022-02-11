#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int fuzzServer(const uint8_t *Data, size_t Size) {
  char *ip = "::1";
  int port = 5555;
  struct sockaddr_in6 server_addr;
  int sockfd;
  sockfd = socket(AF_INET6, SOCK_STREAM, 0);
  server_addr.sin6_family = AF_INET6;
  server_addr.sin6_port = htons(port);
  inet_pton(AF_INET6, ip, &server_addr.sin6_addr);
  connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
  send(sockfd, Data, Size, 0);
  usleep(1000);
  close(sockfd);
  return 1;
}

// char *arg_array[] = {"0", "corpus", "-max_len=60000", "-len_control=30", "-use_value_profile=1", "-dict=dict.txt", NULL};

// char **args_ptr = &arg_array[0];
// int args_size = 6;


char *arg_array[] = {"0", "corpus", "-max_len=60000", "-detect_leaks=0", "-len_control=20", NULL};

char **args_ptr = &arg_array[0];
int args_size = 5;

void *launchFuzzer2(void *param) {
  usleep(15000);
  LLVMFuzzerRunDriver(&args_size, &args_ptr, &fuzzServer);
}

void launchFuzzer() {
  pthread_t threadID;
  pthread_create(&threadID, NULL, launchFuzzer2, NULL);
  fprintf(stderr, "fuzzing launched\n");
}
