#include <sys/sdt.h>
#include <sys/time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	struct timeval tv;
	while(1) {
		gettimeofday(&tv, NULL);
		DTRACE_PROBE1(test-app, test-probe, tv.tv_sec);
		sleep(1);
	}
	return 0;
}
