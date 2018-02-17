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
#include "windows_sane.h"
#include <functional>

class DebugMonitor {

public:

  typedef std::function<void(char*)> DebugCallback;
  static const DWORD NO_FILTER = static_cast<DWORD>(-1);

public:

  explicit DebugMonitor(const DebugCallback &callback);
  ~DebugMonitor();

  ///
  /// \brief stop monitoring debug log. This can take a moment (~200ms)
  /// \return returns false in the very unlikely event the monitor thread can't be stopped, true otherwise.
  ///         the most likely reason the thread fails to stop is if it's already "crashed" so either way
  ///         logging is stopped
  ///
  bool stop();

  ///
  /// test the error state from initialisation. if this is different from NO_ERROR
  /// the monitor will not work. This is usually caused by another debugger listening
  /// \return windows error code from initialisation
  ///
  DWORD errorState() const;

  ///
  /// \brief set the process to monitor. Only messsages from that process are printed
  /// \param processId id of the process to filter. NO_FILTER to display messages from all processes
  ///
  void setProcessFilter(DWORD processId);

private:

  void initialize();

  void startMonitorThread();
  HANDLE openOrCreateEvent(LPCTSTR name, DWORD desiredAccess, BOOL initialState);
  void clearHandle(HANDLE &handle);
  bool openSHM(LPCTSTR name);

  void processDebugEvent();
  static DWORD WINAPI monitorThreadLoop(LPVOID data);

private:

  DebugCallback m_Callback;

  DWORD m_ProcessFilter;

  DWORD m_InitError;

  HANDLE m_BufferMapping;
  HANDLE m_EventBufferReady;
  HANDLE m_EventDataReady;

  struct DebugBuffer {
      DWORD processId;
      char data[4096 - sizeof(DWORD)];
  } *m_DebugBuffer;

  HANDLE m_MonitorThread;
  BOOL m_StopMonitorThread;

};
