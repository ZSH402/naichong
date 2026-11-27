// 复现事故形态：主进程直接 fork 7 个子进程，每个吃掉 150MB，然后主进程退出
#include <stdio.h>
#include <unistd.h>

int main(void) {
    for (int i = 0; i < 7; i++) {
        if (fork() == 0) {
            execlp("python3", "python3", "-c",
                   "import time; b=bytearray(150*1024*1024); time.sleep(300)", NULL);
            _exit(1);
        }
    }
    printf("主进程 %d 派出 7 个子进程，每个占 150MB\n", getpid());
    sleep(1);
    printf("主进程退出（没做任何清理）\n");
    return 0;
}
