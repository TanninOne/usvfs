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

namespace bi = boost::interprocess;
using usvfs::shared::SharedMemoryT;
using usvfs::shared::VoidAllocatorT;

using namespace usvfs;

HookContext *HookContext::s_Instance = nullptr;

HookContext::HookContext(const Parameters &params, HMODULE module)
  : m_ConfigurationSHM(bi::open_or_create, params.instanceName, 8192)
  , m_Parameters(retrieveParameters(params))
  , m_Tree(m_Parameters->currentSHMName.c_str(), 4096)
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

SharedParameters *HookContext::retrieveParameters(const Parameters &params)
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
  spdlog::get("usvfs")->info("{} processes", res.first->processList.size());
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

void HookContext::updateParameters() const
{
  m_Parameters->currentSHMName = m_Tree.shmName().c_str();
}

Parameters HookContext::callParameters() const
{
  updateParameters();
  return static_cast<Parameters>(*m_Parameters);
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
  m_Parameters->processBlacklist.insert(
      shared::StringT(shared::string_cast<std::string>(executableName).c_str(),
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

HookContext *__cdecl CreateHookContext(const Parameters &params, HMODULE module)
{
  return new HookContext(params, module);
}
