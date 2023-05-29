/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/tryto.h>
#include "osquery/core/windows/wmi.h"

#include <unordered_map>

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
 * https://wutils.com/wmi/root/cimv2/win32_perfformatteddata_counters_processorinformation
 * https://wutils.com/wmi/root/cimv2/win32_perfformatteddata_perfproc_process/ <= this one
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

  const Expected<WmiRequest, WmiError> wmiSystemReq_uptime =
      WmiRequest::CreateWmiRequest("select ElapsedTime, Name from Win32_PerfFormattedData_PerfProc_Process");
  if (!wmiSystemReq_uptime || wmiSystemReq_uptime->results().empty()) {
    LOG(WARNING) << "Error retrieving information from WMI.";
    return results;
  }

  const std::vector<WmiResultItem>& uptimeData = wmiSystemReq_uptime->results();
  std::unordered_map<std::string, long long> uptimeMap;
  for (const auto& data : uptimeData) {
    std::string name;
    data.GetString("Name", name);
    long long temp = 0;
    data.GetLongLong("ElapsedTime", temp);
    uptimeMap[name] = temp;
  }

  const Expected<WmiRequest, WmiError> wmiSystemReq =
      WmiRequest::CreateWmiRequest("select Name, PercentUserTime, PercentPrivilegedTime, PercentIdleTime, PercentInterruptTime, PercentPriorityTime from Win32_PerfFormattedData_Counters_ProcessorInformation");
  if (!wmiSystemReq || wmiSystemReq->results().empty()) {
    LOG(WARNING) << "Error retrieving information from WMI.";
    return results;
  }

  const std::vector<WmiResultItem>& wmiResults = wmiSystemReq->results();
  for (const auto& data : wmiResults) {
    std::string name;
    data.GetString("Name", name);
    r["core"] = name;
    long long uptime = uptimeMap[name];
    long percent = 0;
    data.GetLongLong("PercentUserTime", percent);
    r["user"] = BIGINT(percent / 100 * uptime);
    data.GetLongLong("PercentPrivilegedTime", percent);
    r["system"] = BIGINT(percent / 100 * uptime);
    data.GetLongLong("PercentIdleTime", percent);
    r["idle"] = BIGINT(percent / 100 * uptime);
    long idle = percent;
    data.GetLongLong("PercentInterruptTime", percent);
    r["irq"] = BIGINT(percent / 100 * uptime);
    data.GetLongLong("PercentPriorityTime", percent]);  // nice = 100 - priority - idle?
    r["nice"] = BIGINT((100 - percent - idle) / 100 * uptime);
    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
