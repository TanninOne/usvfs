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
#include "hookcontext.h"
#include "exceptionex.h"
#include "usvfs.h"
#include "hookcallcontext.h"
#include <winapi.h>
#include <usvfsparameters.h>
#include <shared_memory.h>
#include "loghelpers.h"


namespace bi = boost::interprocess;
using usvfs::shared::SharedMemoryT;
using usvfs::shared::VoidAllocatorT;

using namespace usvfs;

HookContext *HookContext::s_Instance = nullptr;


void printBuffer(const char *buffer, size_t size)
{
  static const int bufferSize = 16 * 3;
  char temp[bufferSize + 1];
  temp[bufferSize] = '\0';

  for (size_t i = 0; i < size; ++i) {
    size_t offset = i % 16;
    _snprintf(&temp[offset * 3], 3, "%02x ", (unsigned char)buffer[i]);
    if (offset == 15) {
      spdlog::get("hooks")->info("{0:x} - {1}", i - offset, temp);
    }
  }

  spdlog::get("hooks")->info(temp);
}


USVFSParameters SharedParameters::makeLocal() const
{
  USVFSParameters result;
  USVFSInitParametersInt(&result, instanceName.c_str(),
                         currentSHMName.c_str(),
                         currentInverseSHMName.c_str(),
                         debugMode, logLevel, crashDumpsType,
                         crashDumpsPath.c_str());
  return result;
}


void usvfs::USVFSInitParametersInt(USVFSParameters *parameters,
                                   const char *instanceName,
                                   const char *currentSHMName,
                                   const char *currentInverseSHMName,
                                   bool debugMode,
                                   LogLevel logLevel,
                                   CrashDumpsType crashDumpsType,
                                   const char *crashDumpsPath)
{
  parameters->debugMode = debugMode;
  parameters->logLevel = logLevel;
  parameters->crashDumpsType = crashDumpsType;
  strncpy_s(parameters->instanceName, instanceName, _TRUNCATE);
  strncpy_s(parameters->currentSHMName, currentSHMName, _TRUNCATE);
  strncpy_s(parameters->currentInverseSHMName, currentInverseSHMName, _TRUNCATE);
  strncpy_s(parameters->crashDumpsPath, crashDumpsPath, _TRUNCATE);
}


HookContext::HookContext(const USVFSParameters &params, HMODULE module)
  : m_ConfigurationSHM(bi::open_or_create, params.instanceName, 8192)
  , m_Parameters(retrieveParameters(params))
  , m_Tree(m_Parameters->currentSHMName.c_str(), 65536)
  , m_InverseTree(m_Parameters->currentInverseSHMName.c_str(), 65536)
  , m_DebugMode(params.debugMode)
  , m_DLLModule(module)
{
  if (s_Instance != nullptr) {
    throw std::runtime_error("singleton duplicate instantiation (HookContext)");
  }

  ++m_Parameters->userCount;

  spdlog::get("usvfs")->debug("context current shm: {0} (now {1} connections)",
                              m_Parameters->currentSHMName.c_str(),
                              m_Parameters->userCount);

  s_Instance = this;

  if (m_Tree.get() == nullptr) {
    USVFS_THROW_EXCEPTION(usage_error() << ex_msg("shm not found")
                                        << ex_msg(params.instanceName));
  }
}

void HookContext::remove(const char *instanceName)
{
  bi::shared_memory_object::remove(instanceName);
}

HookContext::~HookContext()
{
  spdlog::get("usvfs")->info("releasing hook context");
  s_Instance = nullptr;

  if (--m_Parameters->userCount == 0) {
    spdlog::get("usvfs")
        ->info("removing tree {}", m_Parameters->instanceName.c_str());
    bi::shared_memory_object::remove(m_Parameters->instanceName.c_str());
  } else {
    spdlog::get("usvfs")->info("{} users left", m_Parameters->userCount);
  }
}

SharedParameters *HookContext::retrieveParameters(const USVFSParameters &params)
{
  std::pair<SharedParameters *, SharedMemoryT::size_type> res
      = m_ConfigurationSHM.find<SharedParameters>("parameters");
  if (res.first == nullptr) {
    // not configured yet
    spdlog::get("usvfs")->info("create config in {}", ::GetCurrentProcessId());
    res.first = m_ConfigurationSHM.construct<SharedParameters>("parameters")(
        params, VoidAllocatorT(m_ConfigurationSHM.get_segment_manager()));
    if (res.first == nullptr) {
      USVFS_THROW_EXCEPTION(bi::bad_alloc());
    }
  } else {
    spdlog::get("usvfs")
        ->info("access existing config in {}", ::GetCurrentProcessId());
  }
  spdlog::get("usvfs")->info("{} processes - {}", res.first->processList.size(), (int)res.first->logLevel);
  return res.first;
}

HookContext::ConstPtr HookContext::readAccess(const char*)
{
  BOOST_ASSERT(s_Instance != nullptr);

  // TODO: this should be a shared mutex!
  s_Instance->m_Mutex.wait(200);
  return ConstPtr(s_Instance, unlockShared);
}

HookContext::Ptr HookContext::writeAccess(const char*)
{
  BOOST_ASSERT(s_Instance != nullptr);

  s_Instance->m_Mutex.wait(200);
  return Ptr(s_Instance, unlock);
}

void HookContext::setLogLevel(LogLevel level)
{
  m_Parameters->logLevel = level;
}

void HookContext::setCrashDumpsType(CrashDumpsType type)
{
  m_Parameters->crashDumpsType = type;
}

void HookContext::updateParameters() const
{
  m_Parameters->currentSHMName = m_Tree.shmName().c_str();
  m_Parameters->currentInverseSHMName = m_InverseTree.shmName().c_str();
}

USVFSParameters HookContext::callParameters() const
{
  updateParameters();
  return m_Parameters->makeLocal();
}

std::wstring HookContext::dllPath() const
{
  std::wstring path = winapi::wide::getModuleFileName(m_DLLModule);
  return boost::filesystem::path(path).parent_path().make_preferred().wstring();
}

void HookContext::registerProcess(DWORD pid)
{
  m_Parameters->processList.insert(pid);
}

void HookContext::blacklistExecutable(const std::wstring &executableName)
{
  m_Parameters->processBlacklist.insert(shared::StringT(
      shared::string_cast<std::string>(executableName, shared::CodePage::UTF8)
          .c_str(),
      m_Parameters->processBlacklist.get_allocator()));
}

void HookContext::unregisterCurrentProcess()
{
  auto iter = m_Parameters->processList.find(::GetCurrentProcessId());
  m_Parameters->processList.erase(iter);
}

std::vector<DWORD> HookContext::registeredProcesses() const
{
  std::vector<DWORD> result;
  for (DWORD procId : m_Parameters->processList) {
    result.push_back(procId);
  }
  return result;
}

void HookContext::registerDelayed(std::future<int> delayed)
{
  m_Futures.push_back(std::move(delayed));
}

std::vector<std::future<int>> &HookContext::delayed()
{
  return m_Futures;
}

void HookContext::unlock(HookContext *instance)
{
  instance->m_Mutex.signal();
}

void HookContext::unlockShared(const HookContext *instance)
{
  instance->m_Mutex.signal();
}

extern "C" DLLEXPORT HookContext *__cdecl CreateHookContext(const USVFSParameters &params, HMODULE module)
{
  return new HookContext(params, module);
}
