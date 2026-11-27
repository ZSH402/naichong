// 验证：PDEATHSIG 传给子进程后，子进程再 fork 出的孙进程有没有继承
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <signal.h>

int main(void) {
    pid_t pid = fork();
    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);   // 只有这一层设了
        execlp("sh", "sh", "-c", "sleep 30 & sleep 30 & wait", (char *)NULL);
        _exit(127);
    }
    printf("子进程 %d 设了 PDEATHSIG，它会 fork 两个孙进程\n", pid);
    usleep(300000);
    printf("父进程退出\n");
    fflush(stdout);
    _exit(0);
}
