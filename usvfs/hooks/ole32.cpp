#include "ole32.h"
#include "cogetserverpid.h"
#include "../loghelpers.h"
#include "../hookcallcontext.h"
#include "../hookcontext.h"
#include <inject.h>
#include <winapi.h>
#include <future>


HRESULT WINAPI usvfs::hooks::CoCreateInstance(const IID &rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext,
                                              const IID &riid, LPVOID *ppv)
{
  HRESULT res = REGDB_E_CLASSNOTREG;

  HOOK_START_GROUP(MutExHookGroup::CREATE_PROCESS)

  FILETIME now;
  {
    SYSTEMTIME nowSys;
    GetSystemTime(&nowSys);
    SystemTimeToFileTime(&nowSys, &now);
  }


  PRE_REALCALL
  res = ::CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
  POST_REALCALL

  DWORD pid = 0UL;
  std::string processName;

  if (dwClsContext & CLSCTX_LOCAL_SERVER) {
    HRESULT prodIdRes = CoGetServerPID(reinterpret_cast<IUnknown*>(*ppv), &pid);

    if (SUCCEEDED(prodIdRes) && (pid != 0UL)) {
      HookCallContext createProcessCtx(MutExHookGroup::ALL_GROUPS);
      spdlog::get("hooks")->debug("COM started process, trying to inject to {}", pid);

      /*
      HANDLE token;
      OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token);
      LUID lookupId;
      LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &lookupId);

      TOKEN_PRIVILEGES privileges;
      privileges.PrivilegeCount = 1;
      privileges.Privileges[0].Luid = lookupId;
      privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
      AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
      */

      HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
      if (processHandle != INVALID_HANDLE_VALUE) {
        FILETIME creationTime, exitTime, kernelTime, userTime;
        if (GetProcessTimes(processHandle, &creationTime, &exitTime, &kernelTime, &userTime) == 0) {
          spdlog::get("hooks")->info("failed to get process time: {}", ::GetLastError());
          pid = 0;
        } else if (CompareFileTime(&creationTime, &now) == -1) {
          // the process was created before our call to CoCreateInstance so it can't have been created by that.
          pid = 0;
        } else {
          // process created after our call to CoCreateInstance. It's unlikely (though of course not impossible)
          // that the process wasn't started by our call
          try {
            processName = winapi::ansi::getModuleFileName(nullptr, processHandle);
          } catch (const std::exception &ex) {
            spdlog::get("hooks")->warn("failed to retrieve module name ({1}): {0}", ex.what(), processHandle);
          }

          HookContext::Ptr context = WRITE_CONTEXT();
          // register this process early because when it registers itself may be too late
          context->registerProcess(pid);

          context->registerDelayed(std::move(std::async(std::launch::async, [processHandle]() -> int {
            // TODO: ugly hack from hell. hooking here doesn't work if we inject immediately, no clue why.
            // doing it later means we must potentially delay this process so this async thread runs
            Sleep(100);
#pragma message("the remote process seems to resume the hook-thread only after a not-yet-known event")
#pragma message("update CoCreateInstanceEx once this works")
            HookContext::ConstPtr context = READ_CONTEXT();
            injectProcess(context->dllPath()
                          , context->callParameters()
                          , processHandle
                          , INVALID_HANDLE_VALUE);

            CloseHandle(processHandle);
            return 0;
          })));

          // CloseHandle(token);
        }
      } else {
        spdlog::get("hooks")->warn("failed to open process with pid {0}", pid);
      }
    }
  }

  if (pid != 0) {
    LOG_CALL().PARAMHEX(dwClsContext).PARAM(pid).PARAM(processName).PARAM(res);
  }

  HOOK_END

  return res;
}

HRESULT WINAPI usvfs::hooks::CoCreateInstanceEx(const IID &rclsid, IUnknown *punkOuter, DWORD dwClsCtx,
                                                COSERVERINFO *pServerInfo, DWORD dwCount, MULTI_QI *pResults)
{
  HRESULT res = REGDB_E_CLASSNOTREG;

  HOOK_START_GROUP(MutExHookGroup::CREATE_PROCESS)

  PRE_REALCALL
  res = ::CoCreateInstanceEx(rclsid, punkOuter, dwClsCtx, pServerInfo, dwCount, pResults);
  POST_REALCALL

  DWORD pid = 0UL;
  std::string processName;

  if (dwClsCtx & CLSCTX_LOCAL_SERVER) {
    HookCallContext createProcessCtx(MutExHookGroup::ALL_GROUPS);
    HRESULT procIdRes = CoGetServerPID(pResults[0].pItf, &pid);

    if (SUCCEEDED(procIdRes) && (pid != 0UL)) {
      spdlog::get("hooks")->debug("COM started process (ex), trying to inject to {}", pid);

      HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);

      if (processHandle != INVALID_HANDLE_VALUE) {
        HookContext::ConstPtr context = READ_CONTEXT();
        injectProcess(context->dllPath()
                             , context->callParameters()
                             , processHandle
                             , INVALID_HANDLE_VALUE);
        try {
          processName = winapi::ansi::getModuleFileName(nullptr, processHandle);
        } catch (const std::exception &ex) {
          spdlog::get("hooks")->warn("failed to retrieve module name ({1}): {0}", ex.what(), processHandle);
        }
        CloseHandle(processHandle);
      } else {
        spdlog::get("hooks")->warn("can't open process {0}: {1:x}", pid, static_cast<unsigned long>(procIdRes));
      }
    }
  }

  if (pid != 0) {
    LOG_CALL().PARAMHEX(dwClsCtx).PARAM(pid).PARAM(processName).PARAM(dwCount).PARAM(res);
  }

  HOOK_END

  return res;
}
