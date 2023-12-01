#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>


pid_t Fork(void)
{
    pid_t pid = fork();
    if (pid < 0)
    {
        perror("Error, while calling fork\n");
        exit(EXIT_FAILURE);
    }
    return pid;
}

pid_t Wait(int *status)
{
    pid_t ret_pid = wait(status);
    if (ret_pid < 0)
    {
        perror("Error, while calling wait: ");
        exit(EXIT_FAILURE);
    }
    return ret_pid;
}
int main(int argc, char *argv[])
{
    pid_t child_pid, ret_pid;
    int status;

    if ( (child_pid =  Fork()) == 0)
    {
        printf("Running in child process with PID: %d\n", getpid());
        exit(EXIT_SUCCESS);
    }

    printf("Waiting for the child to terminate in Parent with PID %d\n", getpid());
    ret_pid = Wait(&status);

    printf("Child with PID %d exited\n", ret_pid);
    return 0;
}
