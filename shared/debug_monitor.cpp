/*
Userspace Virtual Filesystem

Copyright (C) 2015 Sebastian Herbord. All rights reserved.

This file is part of usvfs.

usvfs is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

usvfs is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with usvfs. If not, see <http://www.gnu.org/licenses/>.
*/
#include "debug_monitor.h"
#include <stdexcept>


DebugMonitor::DebugMonitor(const DebugCallback &callback)
  : m_Callback(callback), m_ProcessFilter(NO_FILTER), m_DebugBuffer(nullptr)
{
  initialize();
}


DebugMonitor::~DebugMonitor()
{
  stop();
}

DWORD DebugMonitor::errorState() const
{
  return m_InitError;
}

void DebugMonitor::setProcessFilter(DWORD processId)
{
  m_ProcessFilter = processId;
}

void DebugMonitor::initialize()
{
  printf("initialize\n");
  LPCTSTR dbBufferReady  = TEXT("DBWIN_BUFFER_READY");
  LPCTSTR dbDataReady    = TEXT("DBWIN_DATA_READY");

  m_InitError = NO_ERROR;

  // init events
  if ((m_EventBufferReady = openOrCreateEvent(dbBufferReady, EVENT_ALL_ACCESS, FALSE)) == nullptr) {
    return;
  }

  if ((m_EventDataReady = openOrCreateEvent(dbDataReady, SYNCHRONIZE, FALSE)) == nullptr) {
    return;
  }

  if (!openSHM(TEXT("DBWIN_BUFFER"))) {
    return;
  }

  startMonitorThread();
}


void DebugMonitor::clearHandle(HANDLE &handle)
{
  if (handle != nullptr) {
    CloseHandle(handle);
    handle = nullptr;
  }
}


bool DebugMonitor::stop()
{
  m_StopMonitorThread = TRUE;

  bool threadStopped = FALSE;

  if (m_MonitorThread != nullptr) {
    if (WaitForSingleObject(m_MonitorThread, 500) != WAIT_OBJECT_0) {
      threadStopped = TRUE;
    }
  }

  clearHandle(m_BufferMapping);
  clearHandle(m_EventBufferReady);
  clearHandle(m_EventDataReady);

  if (m_DebugBuffer != nullptr) {
    UnmapViewOfFile(m_DebugBuffer);
    m_DebugBuffer = nullptr;
  }

  return threadStopped;
}


void DebugMonitor::startMonitorThread()
{
  m_StopMonitorThread = false;
  m_MonitorThread = CreateThread(nullptr, 0, monitorThreadLoop, this, 0, nullptr);
  if (m_MonitorThread != 0) {
    // set very high priority for the monitor thread so t doesn't slow down calls to OutputDebugString

    BOOL success = SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
    if (!success) {
      printf("failed to change priority class: %lu\n", GetLastError());
    }

    success = SetThreadPriority(m_MonitorThread, THREAD_PRIORITY_TIME_CRITICAL);
    if (!success) {
      printf("failed to change thread priority: %lu\n", GetLastError());
    }
  }
}


void DebugMonitor::processDebugEvent()
{
  SetEvent(m_EventBufferReady);
  DWORD ret = WaitForSingleObject(m_EventDataReady, 100);
  ResetEvent(m_EventBufferReady);

  if (ret == WAIT_OBJECT_0) {
    if ((m_DebugBuffer->processId == NO_FILTER) ||
        (m_DebugBuffer->processId == m_ProcessFilter)) {
      fprintf(stdout, "%lu : %s\n", m_DebugBuffer->processId, m_DebugBuffer->data);
      fflush(stdout);
//      m_Callback(m_DebugBuffer->data);
    }
  } // TODO: error handling?
}

DWORD WINAPI DebugMonitor::monitorThreadLoop(LPVOID data)
{
  DebugMonitor *self = reinterpret_cast<DebugMonitor*>(data);

  if (self != nullptr) {
    while (!self->m_StopMonitorThread) {
      self->processDebugEvent();
    }
  }

  return 0;
}

/*
HANDLE DebugMonitor::openOrCreateEvent(LPCTSTR name, DWORD desiredAccess, BOOL initialState)
{
  HANDLE result = ::OpenEvent(desiredAccess, FALSE, name);
  if (result == nullptr) {
    printf("create event %ls\n", name);
    result = ::CreateEvent(nullptr, FALSE, initialState, name);
    if (result == nullptr) {
      m_InitError = ::GetLastError();
    }
  } else {
    printf("event %ls exists\n", name);
  }
  return result;
}
*/

HANDLE DebugMonitor::openOrCreateEvent(LPCTSTR name, DWORD, BOOL initialState)
{
  HANDLE result = ::CreateEvent(nullptr, FALSE, initialState, name);
  if ((result == nullptr) || (GetLastError() == ERROR_ALREADY_EXISTS)) {
    printf("failed to create event %ls\n", name);
    m_InitError = GetLastError();

    if (result != nullptr) {
      ::CloseHandle(result);
      result = nullptr;
    }
  }
  return result;
}


bool DebugMonitor::openSHM(LPCTSTR name)
{
  m_BufferMapping = ::OpenFileMapping(FILE_MAP_READ, FALSE, name);

  if (m_BufferMapping == nullptr) {
    m_BufferMapping = ::CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(DebugBuffer), name);

    if ((m_BufferMapping == nullptr) || (GetLastError() == ERROR_ALREADY_EXISTS)) {
      printf("failed to create mapping to debug buffer\n");
      m_InitError = GetLastError();
      return false;
    }
  }

  m_DebugBuffer = static_cast<DebugBuffer*>(MapViewOfFile(m_BufferMapping, SECTION_MAP_READ, 0, 0, 0));

  if (m_DebugBuffer == nullptr) {
    printf("failed to map view of debug buffer\n");
    m_InitError = GetLastError();
    return false;
  }
  return true;
}
