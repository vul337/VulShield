#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define THREAD_ITER     10000
#define POOL_SIZE       7
#define GET_THREADS     7
#define NUM_ROUNDS      400
#define WRITE_DELAY_US  3
#define READ_DELAY_US   1

int socks[POOL_SIZE];
volatile int running = 1;
pthread_mutex_t pool_lock = PTHREAD_MUTEX_INITIALIZER;

int create_nl_socket() {
    int s = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (s < 0) {
        perror("socket");
        exit(1);
    }
    return s;
}

void* thread_sendmsg(void* arg) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    char dummy_data[4] = {0xde, 0xad, 0xbe, 0xef};
    struct iovec iov = {
        .iov_base = dummy_data,
        .iov_len = sizeof(dummy_data),
    };
    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    int index = 0;
    while (running) {
        int s = create_nl_socket();

        pthread_mutex_lock(&pool_lock);
        if (socks[index] != -1)
            close(socks[index]);
        socks[index] = s;
        pthread_mutex_unlock(&pool_lock);

        for (int i = 0; i < THREAD_ITER; i++) {
            if (sendmsg(s, &msg, 0) < 0) {
                if (errno != ENOBUFS && errno != ENODATA && errno != EAGAIN)
                    perror("sendmsg");
            }
            usleep(WRITE_DELAY_US);
        }

        usleep(10); // Ensure socket release time
        index = (index + 1) % POOL_SIZE;
    }
    return NULL;
}

void* thread_getsockname(void* arg) {
    int core = *(int*)arg;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    int index = core - 1; // CPU1读socket[0], ..., CPU7读socket[6]
    struct sockaddr_nl addr;
    socklen_t len = sizeof(addr);

    while (running) {
        for (int i = 0; i < THREAD_ITER; i++) {
            pthread_mutex_lock(&pool_lock);
            int s = socks[index];
            pthread_mutex_unlock(&pool_lock);
            if (s != -1) {
                getsockname(s, (struct sockaddr*)&addr, &len);
            }
            usleep(READ_DELAY_US);
        }
    }
    return NULL;
}

void run_rounds() {
    pthread_t writer, readers[GET_THREADS];
    int cpu_ids[GET_THREADS];
    time_t start = time(NULL);

    for (int i = 0; i < POOL_SIZE; i++)
        socks[i] = -1;

    pthread_create(&writer, NULL, thread_sendmsg, NULL);

    for (int i = 0; i < GET_THREADS; i++) {
        cpu_ids[i] = i + 1; // CPUs 1-7
        pthread_create(&readers[i], NULL, thread_getsockname, &cpu_ids[i]);
    }

    for (int round = 0; round < NUM_ROUNDS; round++) {
        printf("[+] Round %d/%d\n", round + 1, NUM_ROUNDS);
        fflush(stdout);
        sleep(1);
        system("dmesg | tail -n 20 | grep -i kcsan");
    }

    running = 0;
    // pthread_join(writer, NULL);
    // for (int i = 0; i < GET_THREADS; i++)
    //     pthread_join(readers[i], NULL);

    time_t end = time(NULL);
    printf("[+] Done. Ran for %ld seconds.\n", end - start);

    for (int i = 0; i < POOL_SIZE; i++) {
        if (socks[i] != -1)
            close(socks[i]);
    }
    exit(0);
}

int main() {
    srand(time(NULL));
    printf("[+] Starting aggressive KCSAN PoC with fine-grained CPU affinity...\n");
    run_rounds();
    return 0;
}