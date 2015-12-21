/*******************************************************************************
Copyright (c) 2012, Kim Gräsman
All rights reserved.

Released under the Modified BSD license. For details, please see LICENSE file.

*******************************************************************************/
#ifndef INCLUDED_COGETSERVERPID_H__
#define INCLUDED_COGETSERVERPID_H__

#include <objbase.h>
#include <stdio.h>
#include <logging.h>

/* This structure represents the OBJREF up to the PID at offset 52 bytes.
   1-byte structure packing to make sure offsets are deterministic. */
#pragma pack(push, 1)
typedef struct tagCOGETSERVERPID_OBJREFHDR
{
  DWORD  signature;  /* Should be 'MEOW'. */
  BYTE  padding[48];
  USHORT  pid;
} COGETSERVERPID_OBJREFHDR;
#pragma pack(pop)

inline HRESULT CoGetServerPID(IUnknown* punk, DWORD* pdwPID)
{
  HRESULT hr;
  IUnknown* pProxyManager = nullptr;
  IStream* pMarshalStream = nullptr;
  HGLOBAL hg = nullptr;
  COGETSERVERPID_OBJREFHDR *pObjRefHdr = nullptr;
  LARGE_INTEGER zero = {0};

  if(pdwPID == nullptr) return E_POINTER;
  if(punk == nullptr) return E_INVALIDARG;

  /* Make sure this is a standard proxy, otherwise we can't make any
     assumptions about OBJREF wire format. */
  hr = punk->QueryInterface(IID_IProxyManager, (void**)&pProxyManager);
  if(FAILED(hr)) return hr;

  pProxyManager->Release();

  /* Marshal the interface to get a new OBJREF. */
  hr = CreateStreamOnHGlobal(nullptr, TRUE, &pMarshalStream);
  if(SUCCEEDED(hr))
  {
    hr = CoMarshalInterface(pMarshalStream, IID_IUnknown, punk, 
      MSHCTX_INPROC, nullptr, MSHLFLAGS_NORMAL);
    if(SUCCEEDED(hr))
    {
      /* We just created the stream so it's safe to go back to a raw pointer. */
      hr = GetHGlobalFromStream(pMarshalStream, &hg);
      if(SUCCEEDED(hr))
      {
        /* Start out pessimistic. */
        hr = RPC_E_INVALID_OBJREF;

        pObjRefHdr = (COGETSERVERPID_OBJREFHDR*)GlobalLock(hg);
        if(pObjRefHdr != nullptr)
        {
          /* Verify that the signature is MEOW. */
          if(pObjRefHdr->signature == 0x574f454d)
          {
            /* We got the remote PID! */
            *pdwPID = pObjRefHdr->pid;
            hr = S_OK;
          }

          GlobalUnlock(hg);
        }
      }

      /* Rewind stream and release marshal data to keep refcount in order. */
      pMarshalStream->Seek(zero, SEEK_SET, nullptr);
      CoReleaseMarshalData(pMarshalStream);
    }

    pMarshalStream->Release();
  }

  return hr;
}

#endif // INCLUDED_COGETSERVERPID_H__
