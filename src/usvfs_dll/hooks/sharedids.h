#pragma once

#include "../hookcontext.h"

/*
template <typename KeyT, typename ValueT>
class SharedMap {
public:

  typedef std::map<KeyT, ValueT> MapT;
  typedef std::shared_ptr<MapT> Ptr;

public:

  Ptr access() {
    m_Mutex.lock();
    return Ptr(&m_Map, [] () {
      m_Mutex.unlock();
    });
  }

private:

  MapT m_Map;
  std::recursive_timed_mutex m_Mutex;

};
*/

typedef std::map<HANDLE, std::wstring> SearchHandleMap;


// maps handles opened for searching to the original search path, which is
// necessary if the handle creation was rerouted
DATA_ID(SearchHandles);
DATA_ID(ActualCWD);
