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
#pragma once

#include "windows_sane.h"

#pragma warning(push)
#pragma warning(disable : 4201)

typedef LONG NTSTATUS;

typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID Pointer;
  } DUMMYUNIONNAME;

  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _FILE_DIRECTORY_INFORMATION {
  ULONG NextEntryOffset;
  ULONG FileIndex;
  LARGE_INTEGER CreationTime;
  LARGE_INTEGER LastAccessTime;
  LARGE_INTEGER LastWriteTime;
  LARGE_INTEGER ChangeTime;
  LARGE_INTEGER EndOfFile;
  LARGE_INTEGER AllocationSize;
  ULONG FileAttributes;
  ULONG FileNameLength;
  WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_FULL_DIR_INFORMATION {
  ULONG NextEntryOffset;
  ULONG FileIndex;
  LARGE_INTEGER CreationTime;
  LARGE_INTEGER LastAccessTime;
  LARGE_INTEGER LastWriteTime;
  LARGE_INTEGER ChangeTime;
  LARGE_INTEGER EndOfFile;
  LARGE_INTEGER AllocationSize;
  ULONG FileAttributes;
  ULONG FileNameLength;
  ULONG EaSize;
  WCHAR FileName[1];
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_ID_FULL_DIR_INFORMATION {
  ULONG NextEntryOffset;
  ULONG FileIndex;
  LARGE_INTEGER CreationTime;
  LARGE_INTEGER LastAccessTime;
  LARGE_INTEGER LastWriteTime;
  LARGE_INTEGER ChangeTime;
  LARGE_INTEGER EndOfFile;
  LARGE_INTEGER AllocationSize;
  ULONG FileAttributes;
  ULONG FileNameLength;
  ULONG EaSize;
  LARGE_INTEGER FileId;
  WCHAR FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION {
  ULONG NextEntryOffset;
  ULONG FileIndex;
  LARGE_INTEGER CreationTime;
  LARGE_INTEGER LastAccessTime;
  LARGE_INTEGER LastWriteTime;
  LARGE_INTEGER ChangeTime;
  LARGE_INTEGER EndOfFile;
  LARGE_INTEGER AllocationSize;
  ULONG FileAttributes;
  ULONG FileNameLength;
  ULONG EaSize;
  CCHAR ShortNameLength;
  WCHAR ShortName[12];
  WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
  ULONG NextEntryOffset;
  ULONG FileIndex;
  LARGE_INTEGER CreationTime;
  LARGE_INTEGER LastAccessTime;
  LARGE_INTEGER LastWriteTime;
  LARGE_INTEGER ChangeTime;
  LARGE_INTEGER EndOfFile;
  LARGE_INTEGER AllocationSize;
  ULONG FileAttributes;
  ULONG FileNameLength;
  ULONG EaSize;
  CCHAR ShortNameLength;
  WCHAR ShortName[12];
  LARGE_INTEGER FileId;
  WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct _FILE_NAMES_INFORMATION {
  ULONG NextEntryOffset;
  ULONG FileIndex;
  ULONG FileNameLength;
  WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

typedef struct _FILE_OBJECTID_INFORMATION {
  LONGLONG FileReference;
  UCHAR ObjectId[16];
  union {
    struct {
      UCHAR BirthVolumeId[16];
      UCHAR BirthObjectId[16];
      UCHAR DomainId[16];
    };
    UCHAR ExtendedInfo[48];
  };
} FILE_OBJECTID_INFORMATION, *PFILE_OBJECTID_INFORMATION;

typedef struct _FILE_REPARSE_POINT_INFORMATION {
  LONGLONG FileReference;
  ULONG Tag;
} FILE_REPARSE_POINT_INFORMATION, *PFILE_REPARSE_POINT_INFORMATION;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#define STATUS_NO_MORE_FILES ((NTSTATUS)0x80000006L)
#define STATUS_NO_SUCH_FILE ((NTSTATUS)0xC000000FL)

typedef enum _FILE_INFORMATION_CLASS {
  FileDirectoryInformation       = 1,
  FileFullDirectoryInformation   = 2,
  FileBothDirectoryInformation   = 3,
  FileNamesInformation           = 12,
  FileObjectIdInformation        = 29,
  FileReparsePointInformation    = 33,
  FileIdBothDirectoryInformation = 37,
  FileIdFullDirectoryInformation = 38
} FILE_INFORMATION_CLASS,
    *PFILE_INFORMATION_CLASS;

typedef enum _MODE { KernelMode, UserMode, MaximumMode } MODE;

typedef struct _IO_STATUS_BLOCK IO_STATUS_BLOCK;

typedef struct _IO_STATUS_BLOCK *PIO_STATUS_BLOCK;
// typedef VOID (NTAPI *PIO_APC_ROUTINE )(__in PVOID ApcContext, __in
// PIO_STATUS_BLOCK IoStatusBlock, __in ULONG Reserved);
typedef VOID(NTAPI *PIO_APC_ROUTINE)(PVOID ApcContext,
                                     PIO_STATUS_BLOCK IoStatusBlock,
                                     ULONG Reserved);
typedef enum _FILE_INFORMATION_CLASS FILE_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef enum _POOL_TYPE {
  NonPagedPool,
  NonPagedPoolExecute = NonPagedPool,
  PagedPool,
  NonPagedPoolMustSucceed = NonPagedPool + 2,
  DontUseThisType,
  NonPagedPoolCacheAligned = NonPagedPool + 4,
  PagedPoolCacheAligned,
  NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
  MaxPoolType,
  NonPagedPoolBase                     = 0,
  NonPagedPoolBaseMustSucceed          = NonPagedPoolBase + 2,
  NonPagedPoolBaseCacheAligned         = NonPagedPoolBase + 4,
  NonPagedPoolBaseCacheAlignedMustS    = NonPagedPoolBase + 6,
  NonPagedPoolSession                  = 32,
  PagedPoolSession                     = NonPagedPoolSession + 1,
  NonPagedPoolMustSucceedSession       = PagedPoolSession + 1,
  DontUseThisTypeSession               = NonPagedPoolMustSucceedSession + 1,
  NonPagedPoolCacheAlignedSession      = DontUseThisTypeSession + 1,
  PagedPoolCacheAlignedSession         = NonPagedPoolCacheAlignedSession + 1,
  NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
  NonPagedPoolNx                       = 512,
  NonPagedPoolNxCacheAligned           = NonPagedPoolNx + 4,
  NonPagedPoolSessionNx                = NonPagedPoolNx + 32
} POOL_TYPE;

typedef struct _OBJECT_TYPE_INITIALIZER {
  WORD Length;
  UCHAR ObjectTypeFlags;
  ULONG CaseInsensitive : 1;
  ULONG UnnamedObjectsOnly : 1;
  ULONG UseDefaultObject : 1;
  ULONG SecurityRequired : 1;
  ULONG MaintainHandleCount : 1;
  ULONG MaintainTypeList : 1;
  ULONG ObjectTypeCode;
  ULONG InvalidAttributes;
  GENERIC_MAPPING GenericMapping;
  ULONG ValidAccessMask;
  POOL_TYPE PoolType;
  ULONG DefaultPagedPoolCharge;
  ULONG DefaultNonPagedPoolCharge;
  PVOID DumpProcedure;
  LONG *OpenProcedure;
  PVOID CloseProcedure;
  PVOID DeleteProcedure;
  LONG *ParseProcedure;
  LONG *SecurityProcedure;
  LONG *QueryNameProcedure;
  UCHAR *OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;

typedef CCHAR KPROCESSOR_MODE;

typedef struct _OBJECT_HANDLE_INFORMATION {
  ULONG HandleAttributes;
  ACCESS_MASK GrantedAccess;
} OBJECT_HANDLE_INFORMATION, *POBJECT_HANDLE_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION {
  LARGE_INTEGER CreationTime;
  LARGE_INTEGER LastAccessTime;
  LARGE_INTEGER LastWriteTime;
  LARGE_INTEGER ChangeTime;
  LARGE_INTEGER AllocationSize;
  LARGE_INTEGER EndOfFile;
  ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef struct _FILE_BASIC_INFORMATION {
  LARGE_INTEGER CreationTime;
  LARGE_INTEGER LastAccessTime;
  LARGE_INTEGER LastWriteTime;
  LARGE_INTEGER ChangeTime;
  ULONG         FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

#define FILE_DIRECTORY_FILE         0x00000001
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000

typedef NTSTATUS(WINAPI *NtQueryDirectoryFile_type)(
    HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
    FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);

typedef NTSTATUS(WINAPI *NtQueryFullAttributesFile_type)(
    POBJECT_ATTRIBUTES, PFILE_NETWORK_OPEN_INFORMATION);

typedef NTSTATUS(WINAPI *NtQueryAttributesFile_type)(POBJECT_ATTRIBUTES,
                                                     PFILE_BASIC_INFORMATION);

typedef NTSTATUS(WINAPI *NtOpenFile_type)(PHANDLE, ACCESS_MASK,
                                          POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                          ULONG, ULONG);

typedef NTSTATUS(WINAPI *NtCreateFile_type)(PHANDLE, ACCESS_MASK,
                                            POBJECT_ATTRIBUTES,
                                            PIO_STATUS_BLOCK, PLARGE_INTEGER,
                                            ULONG, ULONG, ULONG, ULONG, PVOID,
                                            ULONG);

typedef NTSTATUS(WINAPI *NtClose_type)(HANDLE);

typedef NTSYSAPI BOOLEAN(NTAPI *RtlDoesFileExists_U_type)(PCWSTR);

typedef NTSTATUS (NTAPI *RtlGetVersion_type)(PRTL_OSVERSIONINFOW);

typedef NTSTATUS(WINAPI *NtTerminateProcess_type)(HANDLE ProcessHandle, NTSTATUS ExitStatus);

extern NtQueryDirectoryFile_type NtQueryDirectoryFile;
extern NtQueryFullAttributesFile_type NtQueryFullAttributesFile;
extern NtQueryAttributesFile_type NtQueryAttributesFile;
extern NtOpenFile_type NtOpenFile;
extern NtCreateFile_type NtCreateFile;
extern NtClose_type NtClose;
extern RtlDoesFileExists_U_type RtlDoesFileExists_U;
extern RtlGetVersion_type RtlGetVersion;
extern NtTerminateProcess_type NtTerminateProcess;

/*
extern ObReferenceObjectByHandle_type ObReferenceObjectByHandle;
extern ObQueryNameString_type ObQueryNameString;
extern ObDereferenceObject_type ObDereferenceObject;
extern RtlInitUnicodeString_type RtlInitUnicodeString;
*/

#pragma warning(pop)
