/* NOTE:  if you just want to insert your own code at the time of checkpoint
 *  and restart, there are two simpler additional mechanisms:
 *  dmtcpaware, and the MTCP special hook functions:
 *    mtcpHookPreCheckpoint, mtcpHookPostCheckpoint, mtcpHookRestart
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <signal.h>

#include "dmtcp.h"

#define MAX 5

int fd[] = {-1, -1, -1, -1, -1, -1, -1, -1};
struct perf_event_attr *pe[8];
int long long count = 0;

void read_perf_ctr_val(int i, char *name){

	assert(fd[i] > 0);
	count = 0;
        read(fd[i], &count, sizeof(long long));
        printf("Used %lld %s: \n", count, name);
	ioctl(fd[i], PERF_EVENT_IOC_DISABLE, 0);
        close(fd[i]);
}

void alarm_handler(int a){

	read_perf_ctr_val(0, "PAGE_FAULTS");
        read_perf_ctr_val(1, "CONTEXT_SWITCHES");
        read_perf_ctr_val(2, "CPU_MIGRATIONS");
        read_perf_ctr_val(3, "CPU_CYCLES");
        read_perf_ctr_val(4, "INSTRUCTIONS");
        read_perf_ctr_val(5, "CACHE_REFERENCES");
        read_perf_ctr_val(6, "CACHE_MISSES");
        read_perf_ctr_val(7, "BRANCH_INSTRUCTIONS");

        exit(0);
}

static long perf_event_open1(struct perf_event_attr *hw_event, pid_t pid,
                       int cpu, int group_fd, unsigned long flags){

           int ret;
           ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
                          group_fd, flags);
           return ret;
}

void initialize_and_start_perf_attr(int i, __u32 type, __u64 config){

	pe[i] = (struct perf_event_attr*)malloc(sizeof(struct perf_event_attr));
	memset(pe[i], 0, sizeof(struct perf_event_attr));
        pe[i]->type = type;
        pe[i]->size = sizeof(struct perf_event_attr);
        pe[i]->config = config;
        pe[i]->disabled = 1;
        pe[i]->exclude_kernel = 1;
        pe[i]->exclude_hv = 1;
        fd[i] = perf_event_open1(pe[i], 0, -1, -1, 0);
	ioctl(fd[i], PERF_EVENT_IOC_RESET, 0);
        ioctl(fd[i], PERF_EVENT_IOC_ENABLE, 0);

        if (fd[i] == -1) {
            fprintf(stderr, "Error opening leader %llx\n", pe[i]->config);
            ioctl(fd[i], PERF_EVENT_IOC_DISABLE, 0);
            exit(EXIT_FAILURE);
        }
}

void invoke_ctr(){


	initialize_and_start_perf_attr(0, PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS);
	initialize_and_start_perf_attr(1, PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES);
	initialize_and_start_perf_attr(2, PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS);
	initialize_and_start_perf_attr(3, PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES);
	initialize_and_start_perf_attr(4, PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS);
        initialize_and_start_perf_attr(5, PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES);
        initialize_and_start_perf_attr(6, PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES);
        initialize_and_start_perf_attr(7, PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS);
}

void setup_perf_ctr()
{
        invoke_ctr();
	alarm(MAX);
}

void dmtcp_event_hook(DmtcpEvent_t event, DmtcpEventData_t *data)
{
  /* NOTE:  See warning in plugin/README about calls to printf here. */
  switch (event) {

  case DMTCP_EVENT_WRITE_CKPT:
      break;
  case DMTCP_EVENT_RESUME_USER_THREAD:
  {
      if (data->resumeInfo.isRestart) {
        printf("Setting the signal handler.\n");
        signal(SIGALRM, alarm_handler);
	setup_perf_ctr();
      } else {
        printf("Resuming user threads.\n");
      }
      printf("in resume user thread\n");
      break;
  }
  default:
    break;
  }

  DMTCP_NEXT_EVENT_HOOK(event, data);

}
