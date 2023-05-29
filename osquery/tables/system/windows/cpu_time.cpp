/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

/*
 *  Inspired from the psutil per_cpu_times function -
 *  https://github.com/giampaolo/psutil/blob/ec1d35e41c288248818388830f0e4f98536b93e4/psutil/_psutil_osx.c#L739
 */

#include <windows.h>
#include <psapi.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

static inline long int ticks_to_usecs(int ticks) {
  return static_cast<long int>(
      (static_cast<double>(ticks) / CLOCKS_PER_SEC * 1000000));
}

/**
 * TODO:
 * https://stackoverflow.com/questions/38384658/get-cpu-usage-for-each-core-using-the-windows-command-line
 * https://www.codeproject.com/Articles/10539/Making-WMI-Queries-In-C
 * https://learn.microsoft.com/en-us/windows/win32/wmisdk/example--getting-wmi-data-from-the-local-computer
 * https://stackoverflow.com/questions/19756454/calculating-process-cpu-usage-from-process-totalprocessortime
 * https://wutils.com/wmi/root/cimv2/win32_perfformatteddata_perfos_processor/
 * https://www.philosophicalgeek.com/2009/01/03/determine-cpu-usage-of-current-process-c-and-c/
 * prev refs:
 * https://www.linuxhowtos.org/System/procstat.htm
 * https://man7.org/linux/man-pages/man5/proc.5.html
 * https://stackoverflow.com/questions/17432502/how-can-i-measure-cpu-time-and-wall-clock-time-on-both-linux-windows
 * https://learn.microsoft.com/en-us/windows/win32/psapi/enumerating-all-processes
 * https://superuser.com/questions/914782/how-do-you-list-all-processes-on-the-command-line-in-windows
 * https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes?redirectedfrom=MSDN
 * https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
 * https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryidleprocessorcycletime
 * https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryinterrupttime
 * https://stackoverflow.com/questions/23143693/retrieving-cpu-load-percent-total-in-windows-with-c
*/
QueryData genCpuTime(QueryContext& context) {
  QueryData results;

  // Get the list of process identifiers.
  DWORD aProcesses[1024], cbNeeded, cProcesses;
  unsigned int i;

  // Calculate how many process identifiers were returned.
  cProcesses = cbNeeded / sizeof(DWORD);

  // Iterate through all processes.
  for ( i = 0; i < cProcesses; i++ )
  {
    if( aProcesses[i] != 0 )
    {
      // Get a handle to the process.
      HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i] );
      // get cpu time
      FILETIME a,b,c,d;
      if (GetProcessTimes(GetCurrentProcess(),&a,&b,&c,&d) != 0){
        // kernal mode (system mode)
        r["system"] = BIGINT((long int)(c.dwLowDateTime |
            ((unsigned long long)c.dwHighDateTime << 32)) * 0.0000001);
        // user mode
        r["user"] = BIGINT((long int)(d.dwLowDateTime |
            ((unsigned long long)d.dwHighDateTime << 32)) * 0.0000001);
      }else{
        //  Handle error
        r["system"] = "0";
        r["user"] = "0";
      }
    }
  }

  // kern_return_t ret =
  //     host_processor_info(host,
  //                         PROCESSOR_CPU_LOAD_INFO,
  //                         &processor_count,
  //                         reinterpret_cast<processor_info_t*>(&processor_times),
  //                         &processor_msg_count);

  // if (ret == KERN_SUCCESS) {
  //   // Loop through the cores and add rows for each core.
  //   for (unsigned int core = 0; core < processor_count; core++) {
  //     Row r;
  //     r["core"] = INTEGER(core);
  //     r["user"] = BIGINT(
  //         ticks_to_usecs(processor_times[core].cpu_ticks[CPU_STATE_USER]));
  //     r["idle"] = BIGINT(
  //         ticks_to_usecs(processor_times[core].cpu_ticks[CPU_STATE_IDLE]));
  //     r["system"] = BIGINT(
  //         ticks_to_usecs(processor_times[core].cpu_ticks[CPU_STATE_SYSTEM]));
  //     r["nice"] = BIGINT(
  //         ticks_to_usecs(processor_times[core].cpu_ticks[CPU_STATE_NICE]));

  //     results.push_back(r);
  //   }
  //   vm_deallocate(
  //       mach_task_self(),
  //       reinterpret_cast<vm_address_t>(processor_times),
  //       static_cast<vm_size_t>(processor_count * sizeof(*processor_times)));
  // }
  return results;
}
} // namespace tables
} // namespace osquery
