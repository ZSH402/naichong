// 验证 PR_SET_PDEATHSIG 在 exec 之后是否还有效
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <signal.h>

int main(void) {
    pid_t pid = fork();
    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        // exec 一个长命令
        execlp("sleep", "sleep", "30", (char *)NULL);
        _exit(127);
    }
    printf("child pid = %d\n", pid);
    usleep(300000);
    printf("父进程退出（child 应设了 PDEATHSIG=SIGKILL）\n");
    fflush(stdout);
    _exit(0);          // 父直接退出，不 wait
}
