#pragma once

#include <dllimport.h>
#include <windows_sane.h>
#include <Unknwn.h>

namespace usvfs {

DLLEXPORT HRESULT WINAPI hook_CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext,
                                          REFIID riid, LPVOID *ppv);

DLLEXPORT HRESULT WINAPI hook_CoCreateInstanceEx(REFCLSID rclsid, IUnknown *punkOuter, DWORD dwClsCtx,
                                            COSERVERINFO *pServerInfo, DWORD dwCount, MULTI_QI *pResults);

}
