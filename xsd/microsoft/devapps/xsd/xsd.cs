/*+==========================================================================
  File:     XSD.cs

  Summary:  Utility to support XSD schema files; imports data types, creates
            new schemas, and converts the XDR format to the XSD format
  Notes:    

----------------------------------------------------------------------------

  Copyright (C) 2000 Microsoft Corporation.  All rights reserved.
==========================================================================+*/

namespace XsdTool {

    using System;
    using System.Reflection;
    using System.Xml.Serialization;
    using System.Xml.Serialization.Advanced;
    using System.Xml.Schema;
    using System.IO;
    using System.CodeDom.Compiler;
    using System.Collections;
    using System.Collections.Specialized;
    using System.Threading;
    using System.Xml;
    using System.Data;
    using System.Data.Design;
    using System.CodeDom;
    using System.Text;
    using Microsoft.DevApps.WebServices.XsdResources;
    using System.Globalization;// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.


//

#include "common.h"
#include "peimagelayout.h"
#include "peimagelayout.inl"

#if defined(TARGET_WINDOWS)
#include "amsi.h"
#endif

#if defined(CORECLR_EMBEDDED)
extern "C"
{
#include "pal_zlib.h"
}
#endif

static bool AllowR2RForImage(PEImage* pOwner)
{
    // Allow R2R for files
    if (pOwner->IsFile())
        return true;

    // Allow R2R for externally provided images
    INT64 size;
    if (pOwner->GetExternalData(&size) != NULL && size > 0)
        return true;

    return false;
}

#ifndef DACCESS_COMPILE
extern BOOL g_useDefaultBaseAddr;

PEImageLayout* PEImageLayout::CreateFromByteArray(PEImage* pOwner, const BYTE* array, COUNT_T size)
{
    STANDARD_VM_CONTRACT;
    return new FlatImageLayout(pOwner, array, size);
}

#ifndef TARGET_UNIX
PEImageLayout* PEImageLayout::CreateFromHMODULE(HMODULE hModule, PEImage* pOwner)
{
    CONTRACTL
    {
        THROWS;
        GC_TRIGGERS;
        MODE_ANY;
    }
    CONTRACTL_END;

    PEImageLayout* pLoadLayout;
    if (GetModuleHandle(NULL) == hModule)
    {
        return new LoadedImageLayout(pOwner, hModule);
    }
    else
    {
        HRESULT loadFailure = S_OK;
        pLoadLayout = new LoadedImageLayout(pOwner, &loadFailure);

        if (pLoadLayout == NULL)
        {
            loadFailure = FAILED(loadFailure) ? loadFailure : COR_E_BADIMAGEFORMAT;
            EEFileLoadException::Throw(pOwner->GetPathForErrorMessages(), loadFailure);
        }
    }

    return pLoadLayout;
}
#endif

PEImageLayout* PEImageLayout::LoadConverted(PEImage* pOwner, bool disableMapping)
{
    STANDARD_VM_CONTRACT;

    _ASSERTE(!pOwner->HasLoadedLayout());

    ReleaseHolder<FlatImageLayout> pFlat;
    if (pOwner->IsOpened())
    {
        pFlat = (FlatImageLayout*)pOwner->GetFlatLayout();
        pFlat->AddRef();
    }
    else if (AllowR2RForImage(pOwner))
    {
        // We only expect to be converting images that aren't already opened in the R2R composite case
        pFlat = new FlatImageLayout(pOwner);
        _ASSERTE(pFlat->HasReadyToRunHeader());
    }

    if (pFlat == NULL || !pFlat->CheckILOnlyFormat())
        EEFileLoadException::Throw(pOwner->GetPathForErrorMessages(), COR_E_BADIMAGEFORMAT);

// TODO: enable on OSX eventually
//       right now we have binaries that will trigger this in a singlefile bundle.
#ifdef TARGET_LINUX
    // we should not see R2R files here on Unix.
    // ConvertedImageLayout may be able to handle them, but the fact that we were unable to
    // load directly implies that MAPMapPEFile could not consume what crossgen produced.
    // that is suspicious, one or another might have a bug.
    _ASSERTE(!pOwner->IsFile() || !pFlat->HasReadyToRunHeader() || disableMapping);
#endif

    // If the image is R2R with native code (that is, not a component assembly of composite R2R) or has writeable sections,
    // we need to actually load/map it into virtual addresses
    if ((pFlat->HasReadyToRunHeader() && !pFlat->IsComponentAssembly() && AllowR2RForImage(pOwner))
        || pFlat->HasWriteableSections())
    {
        return new ConvertedImageLayout(pFlat, disableMapping);
    }

    // we can use flat layout for this
    return pFlat.Extract();
}

PEImageLayout* PEImageLayout::Load(PEImage* pOwner, HRESULT* loadFailure)
{
    STANDARD_VM_CONTRACT;

    bool disableMapping = CLRConfig::GetConfigValue(CLRConfig::INTERNAL_PELoader_DisableMapping);

    if (pOwner->IsFile())
    {
        if (!pOwner->IsInBundle()
#if defined(TARGET_UNIX)
            || !pOwner->IsCompressed()
#endif
            )
        {
#if defined(TARGET_UNIX)
            if (!disableMapping)
#endif
            {

                PEImageLayoutHolder pAlloc(new LoadedImageLayout(pOwner, loadFailure));
                if (pAlloc->GetBase() != NULL)
                    return pAlloc.Extract();

#if TARGET_WINDOWS
                // For regular PE files always use OS loader on Windows.
                // If a file cannot be loaded, do not try any further.
                // Even if we may be able to load it, we do not want to support such files.
                return NULL;
#endif
            }
        }
    }

    return PEImageLayout::LoadConverted(pOwner, disableMapping);
}

PEImageLayout* PEImageLayout::LoadFlat(PEImage* pOwner)
{
    STANDARD_VM_CONTRACT;
    return new FlatImageLayout(pOwner);
}

PEImageLayout *PEImageLayout::LoadNative(LPCWSTR fullPath)
{
    STANDARD_VM_CONTRACT;
    return new NativeImageLayout(fullPath);
}

#ifdef TARGET_UNIX
DWORD SectionCharacteristicsToPageProtection(UINT characteristics)
{
    _ASSERTE((characteristics & VAL32(IMAGE_SCN_MEM_READ)) != 0);
    DWORD pageProtection;

    if ((characteristics & VAL32(IMAGE_SCN_MEM_WRITE)) != 0)
    {
        if ((characteristics & VAL32(IMAGE_SCN_MEM_EXECUTE)) != 0)
        {
            pageProtection = PAGE_EXECUTE_READWRITE;
        }
        else
        {
            pageProtection = PAGE_READWRITE;
        }
    }
    else
    {
        if ((characteristics & VAL32(IMAGE_SCN_MEM_EXECUTE)) != 0)
        {
            pageProtection = PAGE_EXECUTE_READ;
        }
        else
        {
            pageProtection = PAGE_READONLY;
        }
    }

    return pageProtection;
}
#endif // TARGET_UNIX

// IMAGE_REL_BASED_PTR is architecture specific reloc of virtual address
#ifdef TARGET_64BIT
#define IMAGE_REL_BASED_PTR IMAGE_REL_BASED_DIR64
#else // !TARGET_64BIT
#define IMAGE_REL_BASED_PTR IMAGE_REL_BASED_HIGHLOW
#endif // !TARGET_64BIT

//To force base relocation on Vista (which uses ASLR), unmask IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
//(0x40) for OptionalHeader.DllCharacteristics
void PEImageLayout::ApplyBaseRelocations(bool relocationMustWriteCopy)
{
    STANDARD_VM_CONTRACT;

    SetRelocated();

    //
    // Note that this is not a univeral routine for applying relocations. It handles only the subset
    // required by NGen images. Also, it assumes that the image format is valid.
    //

    SSIZE_T delta = (SIZE_T) GetBase() - (SIZE_T) GetPreferredBase();

    // Nothing to do - image is loaded at preferred base
    if (delta == 0)
        return;

    LOG((LF_LOADER, LL_INFO100, "PEImage: Applying base relocations (preferred: %x, actual: %x)\n",
        GetPreferredBase(), GetBase()));

    COUNT_T dirSize;
    TADDR dir = GetDirectoryEntryData(IMAGE_DIRECTORY_ENTRY_BASERELOC, &dirSize);

    // Minimize number of calls to VirtualProtect by keeping a whole section unprotected at a time.
    BYTE * pWriteableRegion = NULL;
    SIZE_T cbWriteableRegion = 0;
    DWORD dwOldProtection = 0;

    BYTE * pFlushRegion = NULL;
    SIZE_T cbFlushRegion = 0;
    // The page size of PE file relocs is always 4096 bytes
    const SIZE_T cbPageSize = 4096;

    COUNT_T dirPos = 0;
    while (dirPos < dirSize)
    {
        PIMAGE_BASE_RELOCATION r = (PIMAGE_BASE_RELOCATION)(dir + dirPos);

        COUNT_T fixupsSize = VAL32(r->SizeOfBlock);

        USHORT *fixups = (USHORT *) (r + 1);

        _ASSERTE(fixupsSize > sizeof(IMAGE_BASE_RELOCATION));
        _ASSERTE((fixupsSize - sizeof(IMAGE_BASE_RELOCATION)) % 2 == 0);

        COUNT_T fixupsCount = (fixupsSize - sizeof(IMAGE_BASE_RELOCATION)) / 2;

        _ASSERTE((BYTE *)(fixups + fixupsCount) <= (BYTE *)(dir + dirSize));

        DWORD rva = VAL32(r->VirtualAddress);

        BYTE * pageAddress = (BYTE *)GetBase() + rva;

        // Check whether the page is outside the unprotected region
        if ((SIZE_T)(pageAddress - pWriteableRegion) >= cbWriteableRegion)
        {
            // Restore the protection
            if (dwOldProtection != 0)
            {
#if defined(__APPLE__) && defined(HOST_ARM64)
                BOOL bExecRegion = (dwOldProtection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

                // Disable writing on Apple Silicon
                if (bExecRegion)
                    PAL_JitWriteProtect(false);
#else
                if (!ClrVirtualProtect(pWriteableRegion, cbWriteableRegion,
                                       dwOldProtection, &dwOldProtection))
                    ThrowLastError();
#endif // __APPLE__ && HOST_ARM64
                dwOldProtection = 0;
            }

            USHORT fixup = VAL16(fixups[0]);

            IMAGE_SECTION_HEADER *pSection = RvaToSection(rva + (fixup & 0xfff));
            _ASSERTE(pSection != NULL);

            pWriteableRegion = (BYTE*)GetRvaData(VAL32(pSection->VirtualAddress));
            cbWriteableRegion = VAL32(pSection->SizeOfRawData);

            // Unprotect the section if it is not writable
            if (((pSection->Characteristics & VAL32(IMAGE_SCN_MEM_WRITE)) == 0))
            {
                DWORD dwNewProtection = relocationMustWriteCopy ? PAGE_WRITECOPY : PAGE_READWRITE;
#if defined(TARGET_UNIX)
                if (((pSection->Characteristics & VAL32(IMAGE_SCN_MEM_EXECUTE)) != 0))
                {
#if defined(__APPLE__) && defined(HOST_ARM64)
                    // Enable writing on Apple Silicon
                    PAL_JitWriteProtect(true);
#else
                    // On SELinux, we cannot change protection that doesn't have execute access rights
                    // to one that has it, so we need to set the protection to RWX instead of RW
                    dwNewProtection = PAGE_EXECUTE_READWRITE;
#endif
                }
#endif // TARGET_UNIX
#if !(defined(__APPLE__) && defined(HOST_ARM64))
                if (!ClrVirtualProtect(pWriteableRegion, cbWriteableRegion,
                                       dwNewProtection, &dwOldProtection))
                    ThrowLastError();
#endif // __APPLE__ && HOST_ARM64
#ifdef TARGET_UNIX
                dwOldProtection = SectionCharacteristicsToPageProtection(pSection->Characteristics);
#endif // TARGET_UNIX
            }
        }

        BYTE* pEndAddressToFlush = NULL;
        for (COUNT_T fixupIndex = 0; fixupIndex < fixupsCount; fixupIndex++)
        {
            USHORT fixup = VAL16(fixups[fixupIndex]);

            BYTE * address = pageAddress + (fixup & 0xfff);

            switch (fixup>>12)
            {
            case IMAGE_REL_BASED_PTR:
                *(TADDR *)address += delta;
                pEndAddressToFlush = max(pEndAddressToFlush, address + sizeof(TADDR));
                break;

#ifdef TARGET_ARM
            case IMAGE_REL_BASED_THUMB_MOV32:
                PutThumb2Mov32((UINT16 *)address, GetThumb2Mov32((UINT16 *)address) + (INT32)delta);
                pEndAddressToFlush = max(pEndAddressToFlush, address + 8);
                break;
#endif

            case IMAGE_REL_BASED_ABSOLUTE:
                //no adjustment
                break;

            default:
                _ASSERTE(!"Unhandled reloc type!");
            }
        }

        BOOL bExecRegion = (dwOldProtection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

        if (bExecRegion && pEndAddressToFlush != NULL)
        {
            // If the current page is not next to the pending region to flush, flush the current pending region and start a new one
            if (pageAddress >= pFlushRegion + cbFlushRegion + cbPageSize || pageAddress < pFlushRegion)
            {
                if (pFlushRegion != NULL)
                {
                    ClrFlushInstructionCache(pFlushRegion, cbFlushRegion);
                }
                pFlushRegion = pageAddress;
            }

            cbFlushRegion = pEndAddressToFlush - pFlushRegion;
        }

        dirPos += fixupsSize;
    }
    _ASSERTE(dirSize == dirPos);

    if (dwOldProtection != 0)
    {
#if defined(__APPLE__) && defined(HOST_ARM64)
        BOOL bExecRegion = (dwOldProtection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

        // Disable writing on Apple Silicon
        if (bExecRegion)
            PAL_JitWriteProtect(false);
#else
        // Restore the protection
        if (!ClrVirtualProtect(pWriteableRegion, cbWriteableRegion,
                               dwOldProtection, &dwOldProtection))
            ThrowLastError();
#endif // __APPLE__ && HOST_ARM64
    }
#ifdef TARGET_UNIX
    PAL_LOADMarkSectionAsNotNeeded((void*)dir);
#endif // TARGET_UNIX

    if (pFlushRegion != NULL)
    {
        ClrFlushInstructionCache(pFlushRegion, cbFlushRegion);
    }
}

static SIZE_T AllocatedPart(PVOID part)
{
    return (SIZE_T)part + 1;
}

static SIZE_T MappedPart(PVOID part)
{
    return (SIZE_T)part;
}

static PVOID PtrFromPart(SIZE_T part)
{
    return (PVOID)(part & ~1);
}

static SIZE_T IsAllocatedPart(SIZE_T part)
{
    return part & 1;
}

void ConvertedImageLayout::FreeImageParts()
{
    for (int i = 0; i < ConvertedImageLayout::MAX_PARTS; i++)
    {
        SIZE_T imagePart = this->m_imageParts[i];
        if (imagePart == 0)
            break;

        // memory projected into placeholders is page-aligned.
        // we are using "+1" to distinguish committed memory from mapped views, so that we know how to free them
        if (IsAllocatedPart(imagePart))
        {
            ClrVirtualFree(PtrFromPart(imagePart), 0, MEM_RELEASE);
        }
        else
        {
            CLRUnmapViewOfFile(PtrFromPart(imagePart));
        }

        this->m_imageParts[i] = 0;
    }
}

ConvertedImageLayout::ConvertedImageLayout(FlatImageLayout* source, bool disableMapping)
{
    CONTRACTL
    {
        CONSTRUCTOR_CHECK;
        STANDARD_VM_CHECK;
    }
    CONTRACTL_END;

    _ASSERTE(source->CheckILOnlyFormat());

    m_pOwner = source->m_pOwner;
    m_pExceptionDir = NULL;
    memset(m_imageParts, 0, sizeof(m_imageParts));

    bool relocationMustWriteCopy = false;
    void* loadedImage = NULL;

    LOG((LF_LOADER, LL_INFO100, "PEImage: Opening manually mapped stream\n"));

#ifdef TARGET_WINDOWS
    // LoadImageByMappingParts assumes the source has a file mapping handle created/managed by the runtime.
    // This is not the case for non-file images (for example, external data). Only try to load by mapping for files.
    if (!disableMapping && m_pOwner->IsFile())
    {
        loadedImage = source->LoadImageByMappingParts(this->m_imageParts);
        if (loadedImage == NULL)
        {
            FreeImageParts();
        }
        else
        {
            relocationMustWriteCopy = true;
        }
    }
#endif //TARGET_WINDOWS

    if (loadedImage == NULL)
    {
        loadedImage = source->LoadImageByCopyingParts(this->m_imageParts);
    }

    IfFailThrow(Init(loadedImage));

    if (AllowR2RForImage(m_pOwner) && IsNativeMachineFormat())
    {
        // Do base relocation and exception hookup, if necessary.
        // otherwise R2R will be disabled for this image.

        ApplyBaseRelocations(relocationMustWriteCopy);

        // Check if there is a static function table and install it. (Windows only, except x86)
#if !defined(TARGET_UNIX) && !defined(TARGET_X86)
        COUNT_T cbSize = 0;
        PT_RUNTIME_FUNCTION   pExceptionDir = (PT_RUNTIME_FUNCTION)GetDirectoryEntryData(IMAGE_DIRECTORY_ENTRY_EXCEPTION, &cbSize);
        DWORD tableSize = cbSize / sizeof(T_RUNTIME_FUNCTION);

        if (tableSize != 0)
        {
            // the only native code that we expect here is from R2R images
            _ASSERTE(HasReadyToRunHeader());

            if (!RtlAddFunctionTable(pExceptionDir, tableSize, (DWORD64)this->GetBase()))
                ThrowLastError();

            m_pExceptionDir = pExceptionDir;
        }
#endif //TARGET_X86
    }
}

ConvertedImageLayout::~ConvertedImageLayout()
{
    CONTRACTL
    {
        NOTHROW;
        GC_TRIGGERS;
        MODE_ANY;
    }
    CONTRACTL_END;

    FreeImageParts();

#if !defined(TARGET_UNIX) && !defined(TARGET_X86)
    if (m_pExceptionDir)
    {
        RtlDeleteFunctionTable(m_pExceptionDir);
    }
#endif
}

LoadedImageLayout::LoadedImageLayout(PEImage* pOwner, HRESULT* loadFailure)
{
    CONTRACTL
    {
        CONSTRUCTOR_CHECK;
        STANDARD_VM_CHECK;
        PRECONDITION(CheckPointer(pOwner));
    }
    CONTRACTL_END;

    m_pOwner = pOwner;
    _ASSERTE(!pOwner->IsCompressed());

#ifndef TARGET_UNIX
    _ASSERTE(!pOwner->IsInBundle());
    m_Module = CLRLoadLibraryEx(pOwner->GetPath(), NULL, GetLoadWithAlteredSearchPathFlag());
    if (m_Module == NULL)
    {
        // Fetch the HRESULT upfront before anybody gets a chance to corrupt it
        *loadFailure = HRESULT_FROM_GetLastError();
        return;
    }

    IfFailThrow(Init(m_Module, true));

#ifdef LOGGING
    SString ownerPath{ pOwner->GetPath() };
    LOG((LF_LOADER, LL_INFO1000, "PEImage: Opened HMODULE %s\n", ownerPath.GetUTF8()));
#endif // LOGGING

#else
    HANDLE hFile = pOwner->GetFileHandle();
    INT64 offset = pOwner->GetOffset();

    m_LoadedFile = PAL_LOADLoadPEFile(hFile, offset);
    if (m_LoadedFile == NULL)
    {
        // Fetch the HRESULT upfront before anybody gets a chance to corrupt it
        *loadFailure = HRESULT_FROM_GetLastError();
        return;
    }

#ifdef LOGGING
    SString ownerPath{ pOwner->GetPath() };
    LOG((LF_LOADER, LL_INFO1000, "PEImage: image %s (hFile %p) mapped @ %p\n",
        ownerPath.GetUTF8(), hFile, (void*)m_LoadedFile));
#endif // LOGGING

    IfFailThrow(Init((void*)m_LoadedFile));

    if (!HasCorHeader())
    {
        *loadFailure = COR_E_BADIMAGEFORMAT;
        Reset();
        return;
    }

    if (HasReadyToRunHeader())
    {
        //Do base relocation for PE, if necessary.
        if (!IsNativeMachineFormat())
        {
            *loadFailure = COR_E_BADIMAGEFORMAT;
            Reset();
            return;
        }

        // Unix specifies write sharing at map time (i.e. MAP_PRIVATE implies writecopy).
        ApplyBaseRelocations(/* relocationMustWriteCopy*/ false);
        SetRelocated();
    }
#endif
}

#if !defined(TARGET_UNIX)
LoadedImageLayout::LoadedImageLayout(PEImage* pOwner, HMODULE hModule)
{
    m_pOwner = pOwner;
    PEDecoder::Init((void*)hModule, /* relocated */ true);
}
#endif // !TARGET_UNIX

LoadedImageLayout::~LoadedImageLayout()
{
    CONTRACTL
    {
        NOTHROW;
        GC_TRIGGERS;
        MODE_ANY;
    }
    CONTRACTL_END;

#if !defined(TARGET_UNIX)
    if (m_Module)
        CLRFreeLibrary(m_Module);
#endif // !TARGET_UNIX
}

FlatImageLayout::FlatImageLayout(PEImage* pOwner)
{
    CONTRACTL
    {
        CONSTRUCTOR_CHECK;
        STANDARD_VM_CHECK;
        PRECONDITION(CheckPointer(pOwner));
    }
    CONTRACTL_END;
    m_pOwner = pOwner;

#ifdef LOGGING
    SString ownerPath{ pOwner->GetPath() };
    LOG((LF_LOADER, LL_INFO100, "PEImage: Opening flat %s\n", ownerPath.GetUTF8()));
#endif // LOGGING

    INT64 dataSize;
    void* data = pOwner->GetExternalData(&dataSize);
    if (data != nullptr)
    {
        // Image was provided as flat data via external assembly probing.
        // We do not manage the data - just initialize with it directly.
        _ASSERTE(dataSize != 0);
        Init(data, (COUNT_T)dataSize);
        return;
    }

    HANDLE hFile = pOwner->GetFileHandle();
    INT64 offset = pOwner->GetOffset();
    INT64 size = pOwner->GetSize();

    // If a size is not specified, load the whole file
    if (size == 0)
    {
        size = SafeGetFileSize(hFile, NULL);
        if (size == 0xffffffff && GetLastError() != NOERROR)
        {
            ThrowLastError();
        }
    }

    LPVOID addr = 0;

    // It's okay if resource files are length zero
    if (size > 0)
    {
        INT64 uncompressedSize;
        BOOL isCompressed = pOwner->IsCompressed(&uncompressedSize);

        DWORD mapAccess = PAGE_READONLY;
#if !defined(TARGET_UNIX)
        // to map sections into executable views on Windows the mapping must have EXECUTE permissions
        if (!isCompressed)
        {
            mapAccess = PAGE_EXECUTE_READ;
        }
#endif
        m_FileMap.Assign(CreateFileMapping(hFile, NULL, mapAccess, 0, 0, NULL));
        if (m_FileMap == NULL)
            ThrowLastError();

        // - Windows - MapViewOfFileEx requires offset to be allocation granularity aligned (typically 64KB)
        // - Linux/OSX - mmap requires offset to be page aligned (PAL sets allocation granularity to page size)
        UINT32 alignment = g_SystemInfo.dwAllocationGranularity;
        UINT64 mapBegin = AlignDown((UINT64)offset, alignment);
        UINT64 mapSize = ((UINT64)(offset + size)) - mapBegin;

        _ASSERTE((offset - mapBegin) < alignment);
        _ASSERTE((offset - mapBegin) < mapSize);
        _ASSERTE(mapSize >= (UINT64)size);

        LPVOID view = CLRMapViewOfFile(m_FileMap, FILE_MAP_READ, mapBegin >> 32, (DWORD)mapBegin, (DWORD)mapSize);
        if (view == NULL)
            ThrowLastError();

        m_FileView.Assign(view);
        addr = (LPVOID)((size_t)view + offset - mapBegin);

        if (isCompressed)
        {
#if defined(CORECLR_EMBEDDED)
            // The mapping we have just created refers to the region in the bundle that contains compressed data.
            // We will create another anonymous memory-only mapping and uncompress file there.
            // The flat image will refer to the anonymous mapping instead and we will release the original mapping.

            HandleHolder anonMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, uncompressedSize >> 32, (DWORD)uncompressedSize, NULL);
            if (anonMap == NULL)
                ThrowLastError();

            CLRMapViewHolder anonView = CLRMapViewOfFile(anonMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
            if (anonView == NULL)
                ThrowLastError();

            //NB: PE cannot be larger than 4GB and we are decompressing a managed assembly, which is a PE image,
            //    thus converting sizes to uint32 is ok.
            PAL_ZStream zStream;
            zStream.nextIn = (uint8_t*)addr;
            zStream.availIn = (uint32_t)size;
            zStream.nextOut = (uint8_t*)(void*)anonView;
            zStream.availOut = (uint32_t)uncompressedSize;

            // we match the compression side here. 15 is the window sise, negative means no zlib header.
            const int Deflate_DefaultWindowBits = -15;
            if (CompressionNative_InflateInit2_(&zStream, Deflate_DefaultWindowBits) != PAL_Z_OK)
                ThrowHR(COR_E_BADIMAGEFORMAT);

            int ret = CompressionNative_Inflate(&zStream, PAL_Z_NOFLUSH);

            // decompression should have consumed the entire input
            // and the entire output budgets
            if ((ret < 0) ||
                !(zStream.availIn == 0 && zStream.availOut == 0))
            {
                CompressionNative_InflateEnd(&zStream);
                ThrowHR(COR_E_BADIMAGEFORMAT);
            }

            CompressionNative_InflateEnd(&zStream);

            addr = anonView;
            size = uncompressedSize;
            // Replace file handles with the handles to anonymous map. This will release the handles to the original view and map.
            m_FileView.Assign(anonView.Extract());
            m_FileMap.Assign(anonMap.Extract());
#else
            _ASSERTE(!"Failure extracting contents of the application bundle. Compressed files used with a standalone (not singlefile) apphost.");
            ThrowHR(E_FAIL); // we don't have any indication of what kind of failure. Possibly a corrupt image.
#endif
        }
    }

    Init(addr, (COUNT_T)size);
}

FlatImageLayout::FlatImageLayout(PEImage* pOwner, const BYTE* array, COUNT_T size)
{
    CONTRACTL
    {
        CONSTRUCTOR_CHECK;
        THROWS;
        GC_TRIGGERS;
        MODE_ANY;
        INJECT_FAULT(COMPlusThrowOM(););
    }
    CONTRACTL_END;
    m_pOwner = pOwner;

    if (size == 0)
    {
        Init((void*)array, size);
    }
    else
    {
        DWORD mapAccess = PAGE_READWRITE;

#if defined(TARGET_WINDOWS)
        if (Amsi::IsBlockedByAmsiScan((void*)array, size))
        {
            // This is required to throw a BadImageFormatException for compatibility, but
            // use the message from ERROR_VIRUS_INFECTED to give better insight on what's wrong
            SString virusHrString;
            GetHRMsg(HRESULT_FROM_WIN32(ERROR_VIRUS_INFECTED), virusHrString);
            ThrowHR(COR_E_BADIMAGEFORMAT, virusHrString);
        }

        // to map sections into executable views on Windows the mapping must have EXECUTE permissions
        mapAccess = PAGE_EXECUTE_READWRITE;

#endif // defined(TARGET_WINDOWS)

        m_FileMap.Assign(CreateFileMapping(INVALID_HANDLE_VALUE, NULL, mapAccess, 0, size, NULL));
        if (m_FileMap == NULL)
            ThrowLastError();

        m_FileView.Assign(CLRMapViewOfFile(m_FileMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0));
        if (m_FileView == NULL)
            ThrowLastError();

        memcpy(m_FileView, array, size);
        Init((void*)m_FileView, size);
    }
}

void* FlatImageLayout::LoadImageByCopyingParts(SIZE_T* m_imageParts) const
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        THROWS;
        GC_NOTRIGGER;
    }
    CONTRACTL_END;

    void* preferredBase = NULL;
#ifdef FEATURE_ENABLE_NO_ADDRESS_SPACE_RANDOMIZATION
    if (g_useDefaultBaseAddr)
    {
        preferredBase = (void*)GetPreferredBase();
    }
#endif // FEATURE_ENABLE_NO_ADDRESS_SPACE_RANDOMIZATION

    DWORD allocationType = MEM_RESERVE | MEM_COMMIT;
    DWORD initialProtection = PAGE_READWRITE;
#ifdef HOST_UNIX
    // Tell PAL to use the executable memory allocator to satisfy this request for virtual memory.
    // This is required on MacOS and otherwise will allow us to place native R2R code close to the
    // coreclr library and thus improve performance by avoiding jump stubs in managed code.
    allocationType |= MEM_RESERVE_EXECUTABLE;
#endif
#if defined(HOST_OSX) && defined(HOST_ARM64)
    // On Apple Silicon, allocating the image region as plain PAGE_READWRITE and then promoting
    // executable sections to PAGE_EXECUTE_READ via mprotect has been observed to
    // intermittently leave pages non-executable at the kernel level. This manifests as sporadic
    // AccessViolationException crashes.
    //
    // Avoid the unreliable transition - reserve the whole region as PAGE_NOACCESS first, then
    // commit each section directly with its final protection.
    allocationType &= ~MEM_COMMIT;
    initialProtection = PAGE_NOACCESS;
#endif

    COUNT_T allocSize = ALIGN_UP(this->GetVirtualSize(), g_SystemInfo.dwAllocationGranularity);
    LPVOID base = ClrVirtualAlloc(preferredBase, allocSize, allocationType, initialProtection);
    if (base == NULL && preferredBase != NULL)
        base = ClrVirtualAlloc(NULL, allocSize, allocationType, initialProtection);

    if (base == NULL)
        ThrowLastError();

    // when loading by copying we have only one part to free.
    m_imageParts[0] = AllocatedPart(base);

    IMAGE_SECTION_HEADER* sectionStart = IMAGE_FIRST_SECTION(FindNTHeaders());
    IMAGE_SECTION_HEADER* sectionEnd = sectionStart + VAL16(FindNTHeaders()->FileHeader.NumberOfSections);

#if defined(HOST_OSX) && defined(HOST_ARM64)
    _ASSERTE((allocationType & MEM_COMMIT) == 0);
    _ASSERTE(initialProtection != PAGE_READWRITE);

    DWORD sizeOfHeaders = VAL32(FindNTHeaders()->OptionalHeader.SizeOfHeaders);

    // Commit and copy headers, then apply read-only protection.
    if (ClrVirtualAlloc(base, sizeOfHeaders, MEM_COMMIT, PAGE_READWRITE) == NULL)
        ThrowLastError();

    CopyMemory(base, (void*)GetBase(), sizeOfHeaders);

    DWORD oldProtection; // PAL layer doesn't properly set the previous protection, so we don't try to validate it here.
    if (!ClrVirtualProtect((void*)base, sizeOfHeaders, PAGE_READONLY, &oldProtection))
        ThrowLastError();

    // Commit and copy each section with its desired protection.
    for (IMAGE_SECTION_HEADER* section = sectionStart; section < sectionEnd; section++)
    {
        DWORD virtualSize = VAL32(section->Misc.VirtualSize);
        if (virtualSize == 0)
            continue;

        bool isExec = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        BYTE* sectionBase = (BYTE*)base + VAL32(section->VirtualAddress);
        DWORD copySize = min(VAL32(section->SizeOfRawData), virtualSize);

        if (ClrVirtualAlloc(sectionBase, virtualSize, MEM_COMMIT, isExec ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE) == NULL)
            ThrowLastError();

        if (isExec)
            PAL_JitWriteProtect(true);

        CopyMemory(sectionBase, (BYTE*)GetBase() + VAL32(section->PointerToRawData), copySize);

        if (isExec)
        {
            PAL_JitWriteProtect(false);
        }
        else if ((section->Characteristics & IMAGE_SCN_MEM_WRITE) == 0)
        {
            DWORD oldProt;
            if (!ClrVirtualProtect(sectionBase, virtualSize, PAGE_READONLY, &oldProt))
                ThrowLastError();
        }
    }
#else
    // We're going to copy everything first, and write protect what we need to later.

    // First, copy headers
    CopyMemory(base, (void*)GetBase(), VAL32(FindNTHeaders()->OptionalHeader.SizeOfHeaders));

    // Now, copy all sections to appropriate virtual address

    IMAGE_SECTION_HEADER* section = sectionStart;
    while (section < sectionEnd)
    {
        // Raw data may be less than section size if tail is zero, but may be more since VirtualSize is
        // not padded.
        DWORD size = min(VAL32(section->SizeOfRawData), VAL32(section->Misc.VirtualSize));

        CopyMemory((BYTE*)base + VAL32(section->VirtualAddress), (BYTE*)GetBase() + VAL32(section->PointerToRawData), size);

        // Note that our memory is zeroed already, so no need to initialize any tail.

        section++;
    }

    // Apply write protection to copied headers
    DWORD oldProtection;
    if (!ClrVirtualProtect((void*)base, VAL32(FindNTHeaders()->OptionalHeader.SizeOfHeaders),
        PAGE_READONLY, &oldProtection))
        ThrowLastError();

    // Finally, apply proper protection to copied sections
    for (section = sectionStart; section < sectionEnd; section++)
    {
        // Add appropriate page protection.
        DWORD newProtection = section->Characteristics & IMAGE_SCN_MEM_EXECUTE ?
            PAGE_EXECUTE_READ :
            section->Characteristics & IMAGE_SCN_MEM_WRITE ?
            PAGE_READWRITE :
            PAGE_READONLY;

        if (!ClrVirtualProtect((void*)((BYTE*)base + VAL32(section->VirtualAddress)),
            VAL32(section->Misc.VirtualSize),
            newProtection, &oldProtection))
        {
            ThrowLastError();
        }
    }
#endif // defined(HOST_OSX) && defined(HOST_ARM64)

    return base;
}

#ifdef TARGET_WINDOWS

// VirtualAlloc2
typedef PVOID(WINAPI* VirtualAlloc2Fn)(
    HANDLE                 Process,
    PVOID                  BaseAddress,
    SIZE_T                 Size,
    ULONG                  AllocationType,
    ULONG                  PageProtection,
    MEM_EXTENDED_PARAMETER* ExtendedParameters,
    ULONG                  ParameterCount);

VirtualAlloc2Fn pVirtualAlloc2 = NULL;

// MapViewOfFile3
typedef PVOID(WINAPI* MapViewOfFile3Fn)(
    HANDLE                 FileMapping,
    HANDLE                 Process,
    PVOID                  BaseAddress,
    ULONG64                Offset,
    SIZE_T                 ViewSize,
    ULONG                  AllocationType,
    ULONG                  PageProtection,
    MEM_EXTENDED_PARAMETER* ExtendedParameters,
    ULONG                  ParameterCount);

MapViewOfFile3Fn pMapViewOfFile3 = NULL;

static bool HavePlaceholderAPI()
{
    const MapViewOfFile3Fn INVALID_ADDRESS_SENTINEL = (MapViewOfFile3Fn)1;
    if (pMapViewOfFile3 == INVALID_ADDRESS_SENTINEL)
    {
        return false;
    }

    if (pMapViewOfFile3 == NULL)
    {
        HMODULE hm = WszLoadLibrary(W("kernelbase.dll"), NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (hm != NULL)
        {
            pVirtualAlloc2 = (VirtualAlloc2Fn)GetProcAddress(hm, "VirtualAlloc2");
            pMapViewOfFile3 = (MapViewOfFile3Fn)GetProcAddress(hm, "MapViewOfFile3");

            FreeLibrary(hm);
        }

        if (pMapViewOfFile3 == NULL || pVirtualAlloc2 == NULL)
        {
            pMapViewOfFile3 = INVALID_ADDRESS_SENTINEL;
            return false;
        }
    }

    return true;
}

static PVOID AllocPlaceholder(PVOID BaseAddress, SIZE_T Size)
{
    return pVirtualAlloc2(
        ::GetCurrentProcess(),
        BaseAddress,
        Size,
        MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
        PAGE_NOACCESS,
        NULL,
        0);
}

static PVOID MapIntoPlaceholder(
    HANDLE                 FileMapping,
    ULONG64                FromOffset,
    PVOID                  ToAddress,
    SIZE_T                 ViewSize,
    ULONG                  PageProtection
)
{
    return pMapViewOfFile3(FileMapping, ::GetCurrentProcess(), ToAddress, FromOffset, ViewSize, MEM_REPLACE_PLACEHOLDER, PageProtection, NULL, 0);
}

static PVOID CommitIntoPlaceholder(
    PVOID                  ToAddress,
    SIZE_T                 Size,
    ULONG                  PageProtection
)
{
    return pVirtualAlloc2(::GetCurrentProcess(), ToAddress, Size, MEM_COMMIT | MEM_RESERVE | MEM_REPLACE_PLACEHOLDER, PageProtection, NULL, 0);
}

static PVOID SplitPlaceholder(
    PVOID& placeholderStart,
    PVOID   placeholderEnd,
    SIZE_T  size
)
{
    _ASSERTE((char*)placeholderStart + size <= placeholderEnd);

    if ((char*)placeholderStart + size < placeholderEnd)
    {
        if (!VirtualFree(placeholderStart, size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER))
        {
            return NULL;
        }
    }

    PVOID result = placeholderStart;
    placeholderStart = (char*)placeholderStart + size;

    return result;
}

static SIZE_T OffsetWithinPage(SIZE_T addr)
{
    return addr & (GetOsPageSize() - 1);
}

static SIZE_T RoundToPage(SIZE_T size, SIZE_T offset)
{
    size_t result = size + OffsetWithinPage(offset);
    _ASSERTE(result >= size);
    return ROUND_UP_TO_PAGE(result);
}

void* FlatImageLayout::LoadImageByMappingParts(SIZE_T* m_imageParts) const
{
    CONTRACTL
    {
        INSTANCE_CHECK;
        THROWS;
        GC_NOTRIGGER;
    }
    CONTRACTL_END;

    if (!HavePlaceholderAPI() || m_pOwner->IsCompressed())
    {
        return NULL;
    }

    _ASSERTE(HasNTHeaders());

    // offset in m_FileMap is nonzero when the data is in a singlefile bundle.
    SIZE_T offset = (SIZE_T)m_pOwner->GetOffset();
    int imagePartIndex = 0;
    PVOID pReserved = NULL;
    PVOID reservedEnd = NULL;
    IMAGE_NT_HEADERS* ntHeader = FindNTHeaders();

    if  ((ntHeader->OptionalHeader.FileAlignment < GetOsPageSize()) &&
         (ntHeader->OptionalHeader.FileAlignment != ntHeader->OptionalHeader.SectionAlignment))
    {
        goto UNSUPPORTED;
    }

    if (this->GetSize() < GetOsPageSize() * 2)
    {
        goto UNSUPPORTED;
    }

    SIZE_T preferredBase = ntHeader->OptionalHeader.ImageBase;
    SIZE_T virtualSize = ntHeader->OptionalHeader.SizeOfImage;
    SIZE_T reserveSize = RoundToPage(virtualSize, offset);

    PVOID usedBaseAddr = NULL;
#ifdef FEATURE_ENABLE_NO_ADDRESS_SPACE_RANDOMIZATION
    if (g_useDefaultBaseAddr)
    {
        usedBaseAddr = (PVOID)preferredBase;
    }
#endif // FEATURE_ENABLE_NO_ADDRESS_SPACE_RANDOMIZATION

    pReserved = AllocPlaceholder(usedBaseAddr, reserveSize);
    if (pReserved == NULL)
        goto FAILED;

    reservedEnd = (char*)pReserved + reserveSize;
    IMAGE_DOS_HEADER* loadedHeader = (IMAGE_DOS_HEADER*)((SIZE_T)pReserved + OffsetWithinPage(offset));
    _ASSERTE(OffsetWithinPage(offset) == OffsetWithinPage((SIZE_T)loadedHeader));

    //first, map the PE header to the first page in the image.
    SIZE_T dataStart = offset;
    SIZE_T mapFrom = ROUND_DOWN_TO_PAGE(dataStart);
    SIZE_T dataEnd = dataStart + ntHeader->OptionalHeader.SizeOfHeaders;
    SIZE_T mapEnd  = ROUND_UP_TO_PAGE(dataEnd);
    SIZE_T mapSize = mapEnd - mapFrom;
    PVOID  pMapped = SplitPlaceholder(pReserved, reservedEnd, mapSize);
    if (!pMapped)
        goto FAILED;

    pMapped = MapIntoPlaceholder(m_FileMap, mapFrom, pMapped, mapSize, PAGE_READONLY);
    if (!pMapped)
        goto FAILED;

    m_imageParts[imagePartIndex++] = MappedPart(pMapped);

    //Get pointers to the section headers
    IMAGE_SECTION_HEADER* firstSection = (IMAGE_SECTION_HEADER*)(((SIZE_T)loadedHeader)
        + loadedHeader->e_lfanew
        + offsetof(IMAGE_NT_HEADERS, OptionalHeader)
        + VAL16(ntHeader->FileHeader.SizeOfOptionalHeader));

    unsigned numSections = ntHeader->FileHeader.NumberOfSections;
    // in a worst case we need 2 parts for every section and a header + 1 for unused tail.
    if ((numSections + 1) * 2 + 1 > ConvertedImageLayout::MAX_PARTS)
    {
        // too many sections. we do not expect this and do not want to handle here, but it is not an error.
        _ASSERTE(!"too many sections");
        goto UNSUPPORTED;
    }

    for (unsigned i = 0; i < numSections; ++i)
    {
        //for each section, map the section of the file to the correct virtual offset.
        IMAGE_SECTION_HEADER& currentHeader = firstSection[i];
        SIZE_T sectionBase = (SIZE_T)loadedHeader + currentHeader.VirtualAddress;
        SIZE_T sectionBaseAligned = ROUND_DOWN_TO_PAGE(sectionBase);

        if ((SIZE_T)pReserved > sectionBaseAligned)
        {
            // can't allow section mappings to overlap.
            // this could happen with legacy bundles and sub-page aligned data
            // we can't handle such cases here, but it is not an error.
            _ASSERTE(!"can't allow section mappings to overlap");
            goto UNSUPPORTED;
        }

        // Is there space between the previous section and this one? If so, split an unmapped placeholder to cover it.
        if ((SIZE_T)pReserved < sectionBaseAligned)
        {
            // we can handle a hole between sections, but it may indicate a noncompliant R2R PE.
            _ASSERTE(!"Hole between sections");

            SIZE_T holeSize = (SIZE_T)sectionBaseAligned - (SIZE_T)pReserved;
            _ASSERTE((char*)pReserved + holeSize <= reservedEnd);
            PVOID pHole = SplitPlaceholder(pReserved, reservedEnd, holeSize);
            if (!pHole)
                goto FAILED;

            // can't MEM_RELEASE the unused part yet, since the image must be contiguous. (see AssociateMemoryWithLoaderAllocator)
            m_imageParts[imagePartIndex++] = AllocatedPart(pHole);
        }

        DWORD pageProtection = currentHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE ?
            PAGE_EXECUTE_READ :
            currentHeader.Characteristics & IMAGE_SCN_MEM_WRITE ?
                PAGE_WRITECOPY :
                PAGE_READONLY;

        dataStart = offset + currentHeader.PointerToRawData;
        mapFrom = ROUND_DOWN_TO_PAGE(dataStart);
        dataEnd = dataStart + currentHeader.SizeOfRawData;
        mapEnd  = ROUND_UP_TO_PAGE(dataEnd);

        // the aligned end could extend beyond the end of the file.
        // then map only the aligned chunk that fits, the rest we will copy.
        while (mapEnd > offset + this->GetSize())
        {
            mapEnd -= GetOsPageSize();
        }

        // if we have something to map at page granularity, map it
        if (mapEnd > mapFrom)
        {
            mapSize = mapEnd - mapFrom;
            _ASSERTE((char*)pReserved + mapSize <= reservedEnd);
            pMapped = SplitPlaceholder(pReserved, reservedEnd, mapSize);
            if (!pMapped)
                goto FAILED;

            pMapped = MapIntoPlaceholder(m_FileMap, mapFrom, pMapped, mapSize, pageProtection);
            if (!pMapped)
                goto FAILED;

            m_imageParts[imagePartIndex++] = MappedPart(pMapped);
        }

        // if we have something left, copy it
        if (mapEnd < dataEnd)
        {
            SIZE_T toCopy = dataEnd - mapEnd;
            SIZE_T toAllocate = ROUND_UP_TO_PAGE(toCopy);
            _ASSERTE((char*)pReserved + toAllocate <= reservedEnd);
            PVOID pAllocated = SplitPlaceholder(pReserved, reservedEnd, toAllocate);
            if (!pAllocated)
                goto FAILED;

            pAllocated = CommitIntoPlaceholder(pAllocated, toAllocate, PAGE_READWRITE);
            if (!pAllocated)
                goto FAILED;

            m_imageParts[imagePartIndex++] = AllocatedPart(pAllocated);

            CopyMemory(pAllocated, (char*)this->GetBase() + mapEnd - offset, toCopy);
            VirtualProtect(pAllocated, toAllocate, pageProtection, &pageProtection);
        }
    }

    // Is there reserved space that we did not use?
    if (pReserved < reservedEnd)
    {
        // we can handle an image that request extra VM size, but it may indicate a noncompliant R2R PE.
        _ASSERTE(!"Unused part of an image.");
        // can't MEM_RELEASE the unused part yet, since the image must be contiguous. (see AssociateMemoryWithLoaderAllocator)
        m_imageParts[imagePartIndex++] = AllocatedPart(pReserved);
    }

    return loadedHeader;

FAILED:
    _ASSERTE(!"FAILED");
    if (pReserved && pReserved < reservedEnd)
        m_imageParts[imagePartIndex++] = AllocatedPart(pReserved);

    ThrowLastError();

UNSUPPORTED:
    if (pReserved && pReserved < reservedEnd)
        m_imageParts[imagePartIndex++] = AllocatedPart(pReserved);

    return NULL;
}

#endif //TARGET_WINDOWS

NativeImageLayout::NativeImageLayout(LPCWSTR fullPath)
{
    PVOID loadedImage;
#if TARGET_UNIX
    {
        HANDLE fileHandle = WszCreateFile(
            fullPath,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            ThrowLastError();
        }

        loadedImage = PAL_LOADLoadPEFile(fileHandle, 0);
    }
#else
    loadedImage = CLRLoadLibraryEx(fullPath, NULL, GetLoadWithAlteredSearchPathFlag());
#endif

    if (loadedImage == NULL)
    {
        ThrowLastError();
    }


#if TARGET_UNIX
    PEDecoder::Init(loadedImage, /* relocated */ false);
    // Unix specifies write sharing at map time (i.e. MAP_PRIVATE implies writecopy).
    ApplyBaseRelocations(/* relocationMustWriteCopy*/ false);
#else // TARGET_UNIX
    PEDecoder::Init(loadedImage, /* relocated */ true);
#endif // TARGET_UNIX
}
#endif // !DACESS_COMPILE

#ifdef DACCESS_COMPILE
void
PEImageLayout::EnumMemoryRegions(CLRDataEnumMemoryFlags flags)
{
    WRAPPER_NO_CONTRACT;
    DAC_ENUM_VTHIS();
    EMEM_OUT(("MEM: %p PEAssembly\n", dac_cast<TADDR>(this)));
    PEDecoder::EnumMemoryRegions(flags,false);
}
#endif //DACCESS_COMPILE
    using System.Configuration;
    
    /// <include file='doc\xsd.uex' path='docs/doc[@for="Xsd"]/*' />
    /// <devdoc>
    ///    <para>[To be supplied.]</para>
    /// </devdoc>
    public class Xsd {

        TextWriter CreateOutputWriter(string outputdir, string fileName, string newExtension) {
            string strippedName = Path.GetFileName(fileName);
            string newExtensionName = Path.ChangeExtension(strippedName, newExtension);
            string outputName = Path.Combine(outputdir, newExtensionName);

            Console.Out.WriteLine(Res.GetString(Res.InfoWrittingFile, outputName));
            return new StreamWriter(outputName, false, new System.Text.UTF8Encoding(true));
        }

        // Get a code generator for the specified language. language can either be a known abbreviation
        // for C#, VB or JScript. Or it can be a fully-qualified (with assembly) name for an CodeDomProvider
        // or a CodeDomProvider.
        void CreateCodeProvider(string language, ref CodeDomProvider codeProvider, ref string fileExtension) {
            if (CodeDomProvider.IsDefinedLanguage(language)) {
                try {
                    codeProvider = CodeDomProvider.CreateProvider(language);
                } 
                catch (Exception e) {
                    if (e is ThreadAbortException || e is StackOverflowException || e is OutOfMemoryException || e is ConfigurationException) {
                        throw;
                    }
                    throw new InvalidOperationException(Res.GetString(Res.ErrLanguage, language), e);
                } 
            }
            else {
                //try to reflect a custom code generator
                //ignore case when reflecting; language argument must specify the namespace
                Type t = Type.GetType(language, false, true);
                if (t == null)
                    throw new InvalidOperationException(Res.GetString(Res.ErrLanguage, language));
                object o = Activator.CreateInstance(t);
                if (o is CodeDomProvider)
                    codeProvider = (CodeDomProvider)o;
                else
                    throw new InvalidOperationException(Res.GetString(Res.ErrCodeDomProvider, language));
            }

            if (codeProvider != null) {
                fileExtension = codeProvider.FileExtension;
                if (fileExtension == null)
                    fileExtension = string.Empty;
                else if (fileExtension.Length > 0 && fileExtension[0] != '.')
                    fileExtension = "." + fileExtension;
            }
            else
                fileExtension = ".src";
        }

        private static XmlSchema ReadSchema(string location, bool throwOnAbsent) {
            if (!File.Exists(location)) {
                if (throwOnAbsent)
                    throw new FileNotFoundException(Res.GetString(Res.FileNotFound, location));
                else {
                    Console.WriteLine(Res.GetString(Res.SchemaValidationWarningDetails, Res.GetString(Res.FileNotFound, location)));
                    return null;
                }
            }
            XmlTextReader reader = new XmlTextReader(location, (new StreamReader(location)).BaseStream);
            reader.XmlResolver = null;
            schemaCompileErrors = false;
            XmlSchema schema = XmlSchema.Read(reader, new ValidationEventHandler(ValidationCallbackWithErrorCode));
            if (schemaCompileErrors)
                throw new InvalidOperationException(Res.GetString(Res.SchemaValidationError, location));
            return schema;
        }

        void ImportSchemaAsClasses(XmlSchema schema, string uri, IList elements, XmlSchemaImporter schemaImporter, XmlCodeExporter codeExporter) {
            if (schema == null)
                return;
            ArrayList mappings = new ArrayList();
            foreach (XmlSchemaElement element in schema.Elements.Values) {
                if (!element.IsAbstract) {
                    if (uri.Length == 0 ||
                        element.QualifiedName.Namespace == uri) {
                        bool found;
                        if (elements.Count == 0) {
                            found = true;
                        }
                        else {
                            found = false;
                            foreach (string e in elements) {
                                if (e == element.Name) {
                                    found = true;
                                    break;
                                }
                            }
                        }
                        if (found) {
                            mappings.Add(schemaImporter.ImportTypeMapping(element.QualifiedName));
                        }
                    }
                }
            }
            foreach (XmlTypeMapping xmlTypeMapping in mappings) {
                codeExporter.ExportTypeMapping(xmlTypeMapping);
            }
        }

        void ImportSchemasAsClasses(
            string outputdir,
            CodeDomProvider codeProvider,
            string fileExtension,
            IList fileNames, 
            string ns,
            string uri,
            CodeGenerationOptions options,
            IList elements, 
            StringCollection schemaImporterExtensions) {

            XmlSchemas schemasToCompile = new XmlSchemas();
            string outputSchemaName = "";

            Hashtable locations = new Hashtable();
            Hashtable uris = new Hashtable();
            foreach (string fileName in fileNames) {
                string trimmed = fileName.Trim();
                if (trimmed == null || trimmed.Length == 0)
                    continue;
                string path = Path.GetFullPath(trimmed).ToLower(CultureInfo.InvariantCulture);
                if (locations[path] == null) {
                    XmlSchema schema = ReadSchema(path, true);
                    locations.Add(path, schema);
                    Uri baseUri = new Uri(path);
                    uris.Add(schema, baseUri);
                    schemasToCompile.Add(schema , baseUri);
                    outputSchemaName += Path.ChangeExtension(trimmed,"").Replace('.','_');
                }
            }

            Hashtable includeSchemas = new Hashtable();
            Compile(schemasToCompile, uris, includeSchemas);
            try {
                outputSchemaName = outputSchemaName.Substring(0, outputSchemaName.Length - 1);
                CodeCompileUnit codeCompileUnit = new CodeCompileUnit();
                CodeNamespace codeNamespace = new CodeNamespace(ns);
                codeCompileUnit.Namespaces.Add(codeNamespace);
                GenerateVersionComment(codeNamespace);
                XmlCodeExporter codeExporter = new XmlCodeExporter(codeNamespace, codeCompileUnit, codeProvider, options, null);
                XmlSchemaImporter schemaImporter = new XmlSchemaImporter(schemasToCompile, options, codeProvider, new ImportContext(new CodeIdentifiers(), false));
                schemaImporter.Extensions.Add(new DataSetSchemaImporterExtension());
                foreach (string type in schemaImporterExtensions) {
                    Type t = Type.GetType(type.Trim(), true, false);
                    schemaImporter.Extensions.Add(t.FullName, t);
                }
                AddImports(codeNamespace, GetNamespacesForTypes(new Type[] { typeof(XmlAttributeAttribute) }));

                for (int i = 0; i < schemasToCompile.Count; i++) {
                    XmlSchema schema = schemasToCompile[i];
                    ImportSchemaAsClasses(schemasToCompile[i], uri, elements, schemaImporter, codeExporter);
                }
                foreach (XmlSchema s in includeSchemas.Values) {
                    ImportSchemaAsClasses(s, uri, elements, schemaImporter, codeExporter);
                }

                CodeTypeDeclarationCollection classes = codeNamespace.Types;
                if (classes == null || classes.Count == 0) {
                    Console.WriteLine(Res.GetString(Res.NoClassesGenerated));
                }
                else {
                    CodeGenerator.ValidateIdentifiers(codeNamespace);
                    TextWriter writer = CreateOutputWriter(outputdir, outputSchemaName, fileExtension);
                    codeProvider.GenerateCodeFromCompileUnit(codeCompileUnit, writer, null);
                    writer.Close();
                }
            }
            catch (Exception e) {
                if (e is ThreadAbortException || e is StackOverflowException || e is OutOfMemoryException) {
                    throw;
                }
                throw new InvalidOperationException(Res.GetString(Res.ErrGenerateClassesForSchema, outputSchemaName), e);
            }
        }

        internal class Namespace {
            internal const string SoapEncoding = "http://schemas.xmlsoap.org/soap/encoding/";
            internal const string Wsdl = "http://schemas.xmlsoap.org/wsdl/";
            internal const string ReservedXmlNs = "http://www.w3.org/XML/1998/namespace";
        }

        static bool schemaCompileErrors = false;
        internal static void ValidationCallbackWithErrorCode (object sender, ValidationEventArgs args) {
            string message;
            if (args.Exception.LineNumber == 0 && args.Exception.LinePosition == 0) {
                message = Res.GetString(Res.SchemaValidationWarningDetails, args.Message);
            }
            else {
                message = Res.GetString(Res.SchemaValidationWarningDetailsSource, args.Message, args.Exception.LineNumber.ToString(CultureInfo.InvariantCulture), args.Exception.LinePosition.ToString(CultureInfo.InvariantCulture));
            }
            if (args.Severity == XmlSeverityType.Error) {
                Console.WriteLine(message);
                schemaCompileErrors = true;
            }
        }

        internal static void XsdParametersValidationHandler(object sender, ValidationEventArgs args) {
            /*
            if (args.Severity != XmlSeverityType.Error)
                return;
            */
            string message = Res.GetString(Res.XsdParametersValidationError, XsdParameters.targetNamespace, args.Message);
            if (args.Exception.LineNumber != 0 || args.Exception.LinePosition != 0) {
                message += " " + Res.GetString(Res.ErrorPosition, args.Exception.LineNumber.ToString(CultureInfo.InvariantCulture), args.Exception.LinePosition.ToString(CultureInfo.InvariantCulture));
            }
            throw new InvalidOperationException(message);
        }
        
        private static void CollectIncludes(XmlSchema schema, Uri baseUri, Hashtable includeSchemas, string topUri) {
            if (schema == null)
                return;
            foreach (XmlSchemaExternal external in schema.Includes) {
                string schemaLocation = external.SchemaLocation;
                if (external is XmlSchemaImport) {
                    external.SchemaLocation = null;
                }
                else {
                    if (external.Schema == null && schemaLocation != null && schemaLocation.Length > 0) {
                        Uri includeUri = ResolveUri(baseUri, schemaLocation);
                        string uri = includeUri.ToString().ToLower(CultureInfo.InvariantCulture);
                        if (topUri == uri) {
                            external.Schema = new XmlSchema();
                            external.Schema.TargetNamespace = schema.TargetNamespace;
                            external.SchemaLocation = null;
                            return;
                        }
                        XmlSchema include = (XmlSchema)includeSchemas[uri];
                        if (include == null) {

                            // Compute include path the new way (using includeUri) as well the old way (using schemaLocation)
                            string includePath = schemaLocation;
                            string newIncludePath = GetPathFromUri(includeUri);
                            bool isNewIncludePathValid = (newIncludePath != null && File.Exists(newIncludePath));

                            // For backword compatibility, first check if file exists at schemaLocation (old way)
                            if (File.Exists(includePath))
                            {
                                // Print warning if a file also exists at include path (new way) 
                                if (isNewIncludePathValid)
                                {
                                    string oldIncludePath = Path.GetFullPath(includePath).ToLower(CultureInfo.InvariantCulture);
                                    if (oldIncludePath != newIncludePath)
                                        Warning(Res.GetString(Res.MultipleFilesFoundMatchingInclude4, schemaLocation,
                                            GetPathFromUri(baseUri), oldIncludePath, newIncludePath));
                                }
                            }
                            else if (isNewIncludePathValid)
                                includePath = newIncludePath;

                            include = ReadSchema(includePath, false);
                            includeSchemas[uri] = include;
                            CollectIncludes(include, includeUri, includeSchemas, topUri);
                        }
                        if (include != null) {
                            external.Schema = include;
                            external.SchemaLocation = null;
                        }
                    }
                }
            }
        }

        private static string GetPathFromUri(Uri uri)
        {
            if (uri != null)
            {
                try
                {
                    return Path.GetFullPath(uri.LocalPath).ToLower(CultureInfo.InvariantCulture);
                }
                catch (Exception e)
                {
                    if (e is ThreadAbortException || e is StackOverflowException || e is OutOfMemoryException || e is ConfigurationException)
                        throw;
                }
            }
            return null;
        }

        private static Uri ResolveUri(Uri baseUri, string relativeUri) {
            if (baseUri == null || (!baseUri.IsAbsoluteUri && baseUri.OriginalString.Length == 0)) {
                Uri uri = new Uri(relativeUri, UriKind.RelativeOrAbsolute);
                if ( !uri.IsAbsoluteUri ) {
                    uri = new Uri(Path.GetFullPath(relativeUri));
                }
                return uri;
            }
            else {
                if (relativeUri == null || relativeUri.Length == 0) {
                    return baseUri;
                }
                return new Uri(baseUri, relativeUri);
            }
        }

        private static void Compile(XmlSchemas userSchemas, Hashtable uris, Hashtable includeSchemas) {
            foreach (XmlSchema s in userSchemas) {
                if (s.TargetNamespace != null && s.TargetNamespace.Length == 0) {
                    s.TargetNamespace = null;
                }
                Uri uri = (Uri)uris[s];
                CollectIncludes(s, uri, includeSchemas, uri.ToString().ToLower(CultureInfo.InvariantCulture));
            }
            try {
                userSchemas.Compile(new ValidationEventHandler (ValidationCallbackWithErrorCode), true);
            }
            catch (Exception e) {
                if (e is ThreadAbortException || e is StackOverflowException || e is OutOfMemoryException) {
                    throw;
                }
                Console.WriteLine(Environment.NewLine + Res.GetString(Res.SchemaValidationWarning) + Environment.NewLine + e.Message + Environment.NewLine);
            }
            if (!userSchemas.IsCompiled) {
                Console.WriteLine(Environment.NewLine + Res.GetString(Res.SchemaValidationWarning) + Environment.NewLine);
            }
        }

        private static void GenerateVersionComment(CodeNamespace codeNamespace) {
            codeNamespace.Comments.Add(new CodeCommentStatement(""));
            AssemblyName assemblyName = Assembly.GetExecutingAssembly().GetName();
            codeNamespace.Comments.Add(new CodeCommentStatement(
                Res.GetString(Res.InfoVersionComment, assemblyName.Name, ThisAssembly.InformationalVersion)));
            codeNamespace.Comments.Add(new CodeCommentStatement(""));
        }


        /// <include file='doc\xsd.uex' path='docs/doc[@for="Xsd.AddImports"]/*' />
        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        internal static void AddImports(CodeNamespace codeNamespace, string[] namespaces) {
            foreach (string ns in namespaces)
                codeNamespace.Imports.Add(new CodeNamespaceImport(ns));
        }


        /// <include file='doc\xsd.uex' path='docs/doc[@for="Xsd.GetNamespacesForTypes"]/*' />
        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        internal static string[] GetNamespacesForTypes(Type[] types) {
            Hashtable names = new Hashtable();
            for (int i = 0; i < types.Length; i++) {
                string name = types[i].FullName;
                int dot = name.LastIndexOf('.');
                if (dot > 0)
                    names[name.Substring(0, dot)] = types[i];
            }
            string[] ns = new string[names.Keys.Count];
            names.Keys.CopyTo(ns, 0);
            return ns;
        }
       
        void ImportSchemasAsDataSets(
            string outputdir,
            CodeDomProvider codeProvider,
            string fileExtension,
            IList fileNames, 
            string ns, 
            string uri, 
            IList elements,
            bool enableLinqDataSets) {

            foreach (string fileName in fileNames) {
                try {                    
                    // REVIEW: (davidgut) what about culture?
                    StreamReader reader = File.OpenText(fileName);
                    TextWriter writer = CreateOutputWriter(outputdir, fileName, fileExtension);
                    string xsdContent = FixUpSchemaIncludes(reader.ReadToEnd(), fileName);
                    GenerateDataSetClasses(xsdContent, ns, writer, codeProvider, enableLinqDataSets);
                    writer.Close();
                }
                catch (Exception e) {
                    if (e is ThreadAbortException || e is StackOverflowException || e is OutOfMemoryException) {
                        throw;
                    }
                    throw new InvalidOperationException(Res.GetString(Res.ErrGeneral, fileName), e);
                }
            }
        }

        /// <include file='doc\xsd.uex' path='docs/doc[@for="Xsd.GenerateDataSetClasses"]/*' />
        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        internal static void GenerateDataSetClasses(
            string schemaContent, 
            string namespaceName, 
            TextWriter outputWriter, 
            CodeDomProvider codeProvider,
            bool enableLinqDataSets) {

            string dsName = null;
            try {
                CodeCompileUnit codeCompileUnit = new CodeCompileUnit();
                CodeNamespace codeNamespace = new CodeNamespace(namespaceName);
                codeCompileUnit.Namespaces.Add(codeNamespace);
                GenerateVersionComment(codeNamespace);
                // UNDONE,yannc: remove this if data set Generate API is updated to take a CodeCompileUnit

                if (enableLinqDataSets)
                {
                    dsName = System.Data.Design.TypedDataSetGenerator.Generate(schemaContent, codeCompileUnit, codeNamespace, 
                        codeProvider, System.Data.Design.TypedDataSetGenerator.GenerateOption.LinqOverTypedDatasets);
                }
                else
                {
                    dsName = System.Data.Design.TypedDataSetGenerator.Generate(schemaContent, codeCompileUnit, codeNamespace, codeProvider);
                }
                if(namespaceName == null) {
                    codeNamespace.Name = dsName;
                }
                codeProvider.GenerateCodeFromCompileUnit(codeCompileUnit, outputWriter, null);
            }
            catch (Exception e) {
                throw new InvalidOperationException(Res.GetString(Res.ErrGenerateDataSetClass, dsName), e);
            }
        }

        void ExportSchemas(string outputdir, IList dlls, IList typeNames) {
            XmlReflectionImporter importer = new XmlReflectionImporter();
            XmlSchemas schemas = new XmlSchemas();
            XmlSchemaExporter exporter = new XmlSchemaExporter(schemas);

            foreach (string dll in dlls) {
                Assembly a = Assembly.LoadFrom(dll);
                if (a == null)
                    throw new InvalidOperationException(Res.GetString(Res.ErrLoadAssembly, dll));

                try {
                    foreach (Type type in a.GetTypes()) {
                        if (!type.IsPublic)
                            continue;
                        if (type.IsAbstract && type.IsSealed)
                            continue;
                        if (type.IsInterface)
                            continue;
                        if (type.ContainsGenericParameters)
                            continue;

                        bool found;
                        if (typeNames.Count == 0) {
                            found = true;
                        }
                        else {
                            found = false;
                            foreach (string typeName in typeNames) {
                                if (type.FullName == typeName ||
                                    type.Name == typeName ||
                                    (typeName.EndsWith(".*") && 
                                    type.FullName.StartsWith(typeName.Substring(0, typeName.Length - 2)))) {
                                    found = true;
                                    break;
                                }
                            }
                        }

                        if (found) {
                            XmlTypeMapping xmlTypeMapping = importer.ImportTypeMapping(type);
                            exporter.ExportTypeMapping(xmlTypeMapping);
                        }
                    }
                    // need to preprocess all exported schemas to make sure that IXmlSerializable schemas are Merged and the resulting set is valid
                    schemas.Compile(new ValidationEventHandler (ValidationCallbackWithErrorCode), false);
                }
                catch (Exception e) {
                    if (e is ThreadAbortException || e is StackOverflowException || e is OutOfMemoryException) {
                        throw;
                    }
                    throw new InvalidOperationException(Res.GetString(Res.ErrGeneral, dll), e);
                }
            }

            for (int i = 0; i < schemas.Count; i++) {
                XmlSchema schema = schemas[i];
                try {
                    TextWriter writer = CreateOutputWriter(outputdir, "schema" + i.ToString(), ".xsd");
                    schemas[i].Write(writer);
                    writer.Close();
                }
                catch (Exception e) {
                    if (e is ThreadAbortException || e is StackOverflowException || e is OutOfMemoryException) {
                        throw;
                    }
                    throw new InvalidOperationException(Res.GetString(Res.ErrGeneral, schema.TargetNamespace), e);
                }
            }
            if (schemas.Count == 0) {
                Console.WriteLine(Res.GetString(Res.NoTypesGenerated));
            }
        }

        void ConvertXDRSchemas(string outputdir, IList xdrSchemas) {
            foreach (string xdrSchema in xdrSchemas) {
                try {

                    // REVIEW: (davidgut) what about culture?
                    DataSet dataSet = new DataSet();
                    dataSet.ReadXmlSchema(xdrSchema);
                    TextWriter writer = CreateOutputWriter(outputdir, xdrSchema, ".xsd");
                    XmlTextWriter w =  new XmlTextWriter(writer);
                    w.Formatting = Formatting.Indented;
                    w.WriteStartDocument();
                    dataSet.WriteXmlSchema(w);
                    w.Close();
                    writer.Close();
                }
                catch (Exception e) {
                    if (e is ThreadAbortException || e is StackOverflowException || e is OutOfMemoryException) {
                        throw;
                    }
                    throw new InvalidOperationException(Res.GetString(Res.ErrGeneral, xdrSchema), e);
                }
            }
        }

        
        void InferSchemas(string outputdir, IList instances) {
            foreach (string instance in instances) {
                try {

                    // REVIEW: (davidgut) what about culture?
                    DataSet dataSet = new DataSet();
                    dataSet.ReadXml(instance);
                    TextWriter writer = CreateOutputWriter(outputdir, instance, ".xsd");
                    XmlTextWriter w =  new XmlTextWriter(writer);
                    w.Formatting = Formatting.Indented;
                    w.WriteStartDocument();
                    dataSet.WriteXmlSchema(w);
                    w.Close();
                    writer.Close();
                }
                catch (Exception e) {
                    if (e is ThreadAbortException || e is StackOverflowException || e is OutOfMemoryException) {
                        throw;
                    }
                    throw new InvalidOperationException(Res.GetString(Res.ErrGeneral, instance), e);
                }
            }
        }

        /// <include file='doc\xsd.uex' path='docs/doc[@for="Xsd.Main"]/*' />
        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public static int Main(string[] args) {
            Xsd xsd = new Xsd();
            return xsd.Run(args);
        }

        //Function is used when an argument has 2+ letters short form.
        bool ArgumentMatchEx(string arg, string formal, int minletters) {
            //arg comes on '/xxx' form, formal in the 'xxx' one
            if (arg.Length > minletters + 1) {
                return ArgumentMatch(arg, formal);
            }
            else if (arg.Length == minletters + 1) {
                return (string.Compare(arg, 1, formal, 0, minletters, false, CultureInfo.InvariantCulture) == 0);
            }
            return false;
        }

        //Function is used when an argument has 2+ letters short form.
        bool ArgumentMatchEx(string arg, string formal, string shortForm) {
            //arg comes on '/xxx' form, formal in the 'xxx' one
            int shortFormLength = shortForm.Length + 1;
            if (arg.Length > shortFormLength) 
                return ArgumentMatch(arg, formal);
            else if (arg.Length == shortFormLength)
                return ArgumentMatch(arg, shortForm);
            return false;
        }

        // assumes all same case.        
        bool ArgumentMatch(string arg, string formal) {
            return ArgumentMatch(arg, formal, false);
        }

        // assumes all same case.        
        bool ArgumentMatch(string arg, string formal, bool exactMatch) {
            if (arg[0] != '/' && arg[0] != '-') {
                return false;
            }
            if (exactMatch) {
                arg = arg.Substring(1);
                return (arg == formal);
            }
            arg = arg.Substring(1);
            return (arg == formal || (arg.Length == 1 && arg[0] == formal[0]));
        }

        // For command line apps, cmd.exe cannot display right-to-left languages currently.  Change the
        // CurrentUICulture to meet their needs, falling back to our invariant resources.
        private static void SetConsoleUICulture()
        {
            Thread t = Thread.CurrentThread;
            t.CurrentUICulture = CultureInfo.CurrentUICulture.GetConsoleFallbackUICulture();

            if (Console.OutputEncoding.CodePage != Encoding.UTF8.CodePage &&
                Console.OutputEncoding.CodePage != t.CurrentUICulture.TextInfo.OEMCodePage &&
                Console.OutputEncoding.CodePage != t.CurrentUICulture.TextInfo.ANSICodePage)
            {
                t.CurrentUICulture = new CultureInfo("en-US");
            }
        }

        int Run(string[] args) {
            SetConsoleUICulture();
            try {
                XsdParameters xsdParameters = new XsdParameters();
                XsdParameters userParameters = null;
                    
                for (int i = 0; i < args.Length; i++) {
                    string arg = args[i];
                    string value = string.Empty;
                    bool argument = false;
                
                    if (arg.StartsWith("/") || arg.StartsWith("-")) {
                        argument = true;
                        int colonPos = arg.IndexOf(":");
                        if (colonPos != -1) {
                            value = arg.Substring(colonPos + 1);
                            arg = arg.Substring(0, colonPos);
                        }
                    }
                    arg = arg.ToLower(CultureInfo.InvariantCulture);

                    //the user may have wanted to provide an absolute path to the file, so detect that FIRST
                    //for example. "c:bob.xsd" will be (erroneously) split up into arg = "c" and value = "bob.xsd"
                    //however, "bob.xsd" will be "properly" split up into arg = "bob.xsd" and value = ""

                    if (!argument && arg.EndsWith(".xsd")) {
                        xsdParameters.XsdSchemas.Add(args[i]);
                    }
                    else if (!argument && arg.EndsWith(".xdr")) {
                        xsdParameters.XdrSchemas.Add(args[i]);
                    }
                    else if (!argument && arg.EndsWith(".xml")) {
                        xsdParameters.Instances.Add(args[i]);
                    }
                    else if (!argument && (arg.EndsWith(".dll") || arg.EndsWith(".exe"))) {
                        xsdParameters.Assemblies.Add(args[i]);
                    }
                    else if (ArgumentMatch(arg, "?") || ArgumentMatch(arg, "help")) {
                        WriteHeader();
                        WriteHelp();
                        return 0;
                    }
                    else if (ArgumentMatch(arg, "classes")) {
                        if (value.Length > 0) {
                            WriteHeader();
                            throw new InvalidOperationException(Res.GetString(Res.ErrInvalidArgument, arg + ":" + value));
                        }
                        xsdParameters.Classes = true;
                    }
                    else if (ArgumentMatch(arg, "dataset")) {
                        if (value.Length > 0) {
                            WriteHeader();
                            throw new InvalidOperationException(Res.GetString(Res.ErrInvalidArgument, arg + ":" + value));
                        }
                        xsdParameters.Dataset = true;
                    }
                    else if (ArgumentMatchEx(arg, "enablelinqdataset", "eld")) { // all lower-case used to match argument
                        if (value.Length > 0) 
                        {
                            WriteHeader();
                            throw new InvalidOperationException(Res.GetString(Res.ErrInvalidArgument, arg + ":" + value));
                        }
                        xsdParameters.EnableLinqDataSet = true;
                    }
                    else if (ArgumentMatch(arg, "element")) {
                        xsdParameters.Elements.Add(value);
                    }
                    else if (ArgumentMatch(arg, "fields")) {
                        xsdParameters.Options &= ~CodeGenerationOptions.GenerateProperties;
                    }
                    else if (ArgumentMatch(arg, "order", true)) {
                        xsdParameters.Options |= CodeGenerationOptions.GenerateOrder;
                    }
                    else if (ArgumentMatchEx(arg, "enabledatabinding", "edb")) { // all lower-case used to match argument
                        xsdParameters.Options |= CodeGenerationOptions.EnableDataBinding;
                    }
                    else if (ArgumentMatch(arg, "language")) {
                        xsdParameters.Language = value.ToLower(CultureInfo.InvariantCulture);
                    }
                    else if (ArgumentMatch(arg, "namespace")) {
                        xsdParameters.Namespace = value;
                    }
                    else if (ArgumentMatch(arg, "nologo")) {
                        if (value.Length > 0) {
                            WriteHeader();
                            throw new InvalidOperationException(Res.GetString(Res.ErrInvalidArgument, arg + ":" + value));
                        }
                        xsdParameters.Nologo = true;
                    }
                    else if (ArgumentMatch(arg, "out") || ArgumentMatch(arg, "outputdir")) {
                        xsdParameters.OutputDir = value;
                    }
                    else if (ArgumentMatch(arg, "type")) {
                        xsdParameters.Types.Add(value);
                    }
                    else if (ArgumentMatch(arg, "uri")) {
                        xsdParameters.Uri = value;
                    }
                    else if (ArgumentMatch(arg, "parameters")) {
                        userParameters = XsdParameters.Read(value);
                    }
                    else {
                        WriteHeader();
                        throw new InvalidOperationException(Res.GetString(Res.ErrInvalidArgument, args[i]));
                    }
                }

                if (userParameters != null) {
                    xsdParameters = userParameters.Merge(xsdParameters);
                }
                if (xsdParameters.Help) {
                    WriteHeader();
                    WriteHelp();
                    return 0;
                }
                if (!xsdParameters.Nologo)
                    WriteHeader();

                bool schemasFound = xsdParameters.XsdSchemas.Count > 0;
                bool xdrSchemasFound = xsdParameters.XdrSchemas.Count > 0;
                bool dllsFound = xsdParameters.Assemblies.Count > 0;
                bool instancesFound = xsdParameters.Instances.Count > 0;
            
                if (xsdParameters.OutputDir.Length == 0) {
                    xsdParameters.OutputDir = Directory.GetCurrentDirectory();
                }
                if (schemasFound) {
                    if (dllsFound || instancesFound || xdrSchemasFound) {
                        throw new InvalidOperationException(Res.GetString(Res.ErrInputFileTypes));
                    }
                    if (xsdParameters.Classes == xsdParameters.Dataset) {
                        throw new InvalidOperationException(Res.GetString(Res.ErrClassOrDataset));
                    }

                    CodeDomProvider codeProvider = null;
                    string fileExtension = string.Empty;

                    CreateCodeProvider(xsdParameters.Language, ref codeProvider, ref fileExtension);

                    if (xsdParameters.Classes)
                        ImportSchemasAsClasses(xsdParameters.OutputDir, codeProvider, fileExtension, xsdParameters.XsdSchemas, xsdParameters.Namespace, xsdParameters.Uri, xsdParameters.Options, xsdParameters.Elements, xsdParameters.SchemaImporterExtensions);
                    else
                        ImportSchemasAsDataSets(xsdParameters.OutputDir, codeProvider, fileExtension, xsdParameters.XsdSchemas, xsdParameters.Namespace, xsdParameters.Uri, xsdParameters.Elements, xsdParameters.EnableLinqDataSet);
                }
                else if (dllsFound) {
                    if (instancesFound || xdrSchemasFound)
                        throw new InvalidOperationException(Res.GetString(Res.ErrInputFileTypes));
                    ExportSchemas(xsdParameters.OutputDir, xsdParameters.Assemblies, xsdParameters.Types);
                }
                else if (xdrSchemasFound) {
                    if (instancesFound)
                        throw new InvalidOperationException(Res.GetString(Res.ErrInputFileTypes));
                    ConvertXDRSchemas(xsdParameters.OutputDir, xsdParameters.XdrSchemas);
                }
                else if (instancesFound) {
                    InferSchemas(xsdParameters.OutputDir, xsdParameters.Instances);
                }
                else {
                    WriteHelp();
                    return 0;
                }
            }
            catch (Exception e) {
                if (e is ThreadAbortException || e is StackOverflowException || e is OutOfMemoryException) {
                    throw;
                }
                Error(e, Res.GetString(Res.Error));
                return 1;
            }
            return 0;
        }

        static void Error(Exception e, string prefix) {
            Console.Error.WriteLine(prefix + e.Message);
            if (e is System.Data.Design.TypedDataSetGeneratorException) {
                foreach (string msg in ((System.Data.Design.TypedDataSetGeneratorException) e).ErrorList) {
                    Console.WriteLine(prefix + msg);
                }
            }
            if (e.InnerException != null) {
                Error(e.InnerException, "  - ");
            }
            else {
                Console.WriteLine(Res.GetString(Res.MoreHelp,"/?"));
            }
        }

        static void Warning(string message)
        {
            Console.WriteLine(Res.GetString(Res.Warning, message));
        }

        private void WriteHeader() {
            Console.WriteLine(Res.GetString(Res.Logo));
            // do not localize Copyright header
            Console.WriteLine(String.Format(CultureInfo.CurrentCulture, "[Microsoft (R) .NET Framework, Version {0}]", ThisAssembly.InformationalVersion));
            Console.WriteLine("Copyright (C) Microsoft Corporation. All rights reserved.");
        }

        void WriteHelp() {
            Console.WriteLine(Res.GetString(Res.HelpDescription, ThisAssembly.Title));
            Console.WriteLine(Res.GetString(Res.HelpUsage, ThisAssembly.Title));
            Console.WriteLine(Res.GetString(Res.HelpOptions));
            Console.WriteLine(Res.GetString(Res.HelpClasses, "/classes", "/c"));
            Console.WriteLine(Res.GetString(Res.HelpDataset, "/dataset", "/d"));
            Console.WriteLine(Res.GetString(Res.HelpEnableLinqDataSet, "/enableLinqDataSet", "/eld"));
            Console.WriteLine(Res.GetString(Res.HelpElement, "/element:", "/e:"));
            Console.WriteLine(Res.GetString(Res.HelpFields, "/fields", "/f"));
            Console.WriteLine(Res.GetString(Res.HelpOrder, "/order"));
            Console.WriteLine(Res.GetString(Res.HelpEnableDataBinding, "/enableDataBinding", "/edb"));
            Console.WriteLine(Res.GetString(Res.HelpLanguage, "/language:", "/l:"));
            Console.WriteLine(Res.GetString(Res.HelpNamespace, "/namespace:", "/n:"));
            Console.WriteLine(Res.GetString(Res.HelpNoLogo, "/nologo"));
            Console.WriteLine(Res.GetString(Res.HelpOut, "/out:", "/o:"));
            Console.WriteLine(Res.GetString(Res.HelpType,"/type:","/t:"));
            Console.WriteLine(Res.GetString(Res.HelpUri, "/uri:", "/u:"));
            Console.WriteLine(Res.GetString(Res.HelpAdvanced));
            Console.WriteLine(Res.GetString(Res.HelpParameters, "/parameters:", "/p:"));
            Console.WriteLine(Res.GetString(Res.HelpArguments));
            Console.WriteLine(Res.GetString(Res.HelpArgumentsDescription));
        }

        internal static string FixUpSchemaIncludes(string xsdContent, string xsdPath) {
            if (xsdContent == null || xsdPath == null) {
                return xsdContent;
            }

            try {
                bool madeChanges = false;
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.Load(XmlReader.Create(new StringReader(xsdContent)));

                XmlNamespaceManager nsMgr = new XmlNamespaceManager(xmlDoc.NameTable);
                nsMgr.AddNamespace("xs", XmlSchema.Namespace);
                string expression = "//xs:schema/xs:include";

                XmlNodeList nodeList = xmlDoc.SelectNodes(expression, nsMgr);
                foreach (XmlNode node in nodeList) {
                    XmlElement xmlElement = node as XmlElement;
                    if (xmlElement == null) {
                        continue;
                    }
                    foreach (XmlAttribute attribute in xmlElement.Attributes) {
                        if (String.Compare(attribute.Name, "schemaLocation", StringComparison.OrdinalIgnoreCase) == 0) {
                            string replacement = attribute.Value;

                            if (!Uri.IsWellFormedUriString(replacement, UriKind.Absolute) && !Path.IsPathRooted(replacement)) {
                                replacement = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(xsdPath)), replacement);
                                if (File.Exists(replacement)) {
                                    attribute.Value = replacement;
                                    madeChanges = true;
                                }
                            }
                        }
                    }
                }

                if (madeChanges) {
                    StringWriter stringWriter = new StringWriter();
                    xmlDoc.Save(XmlWriter.Create(stringWriter));
                    xsdContent = stringWriter.ToString();
                }
            }
            catch { }

            return xsdContent;
        }
    }

    public class XsdParameters {
        internal const string targetNamespace = "http://microsoft.com/dotnet/tools/xsd/";
        bool nologo;
        bool help;
        bool classes;
        bool dataset;
        bool enableLinqDataSet;
        string language;
        string ns;
        string outputdir;
        CodeGenerationOptions options = CodeGenerationOptions.GenerateProperties;
        bool optionsDefault = true;
        string uri;
        StringCollection xsdSchemas;
        StringCollection xdrSchemas;
        StringCollection instances;
        StringCollection dlls;
        StringCollection elements;
        StringCollection types;
        StringCollection schemaImporterExtensions;

        internal bool Classes {
            get { return classes; }
            set { classes = value; }
        }

        internal bool Dataset {
            get { return dataset; }
            set { dataset = value; }
        }

        internal bool EnableLinqDataSet {
            get { return enableLinqDataSet; }
            set { enableLinqDataSet = value; }
        }

        internal bool Help {
            get { return help; }
            set { help = value; }
        }

        internal string Language {
            get { return language == null ? "c#" : language; }
            set { language = value; }
        }

        internal string Namespace {
            get { return ns == null ? string.Empty : ns; }
            set { ns = value; }
        }

        internal bool Nologo {
            get { return nologo; }
            set { nologo = value; }
        }

        internal string OutputDir {
            get { return outputdir == null ? string.Empty : outputdir; }
            set { outputdir = value; }
        }

        internal CodeGenerationOptions Options {
            get { return options; }
            set { options = value; optionsDefault = false;}
        }

        internal string Uri {
            get { return uri == null ? string.Empty : uri; }
            set { uri = value; }
        }

        internal StringCollection XsdSchemas {
            get {
                if (xsdSchemas == null)
                    xsdSchemas = new StringCollection();
                return xsdSchemas; 
            }
        }

        internal StringCollection XdrSchemas {
            get {
                if (xdrSchemas == null)
                    xdrSchemas = new StringCollection();
                return xdrSchemas; 
            }
        }

        internal StringCollection Instances {
            get {
                if (instances == null)
                    instances = new StringCollection();
                return instances; 
            }
        }

        internal StringCollection Assemblies {
            get {
                if (dlls == null)
                    dlls = new StringCollection();
                return dlls; 
            }
        }

        internal StringCollection Elements {
            get {
                if (elements == null)
                    elements = new StringCollection();
                return elements; 
            }
        }

        internal StringCollection Types {
            get {
                if (types == null)
                    types = new StringCollection();
                return types; 
            }
        }

        internal StringCollection SchemaImporterExtensions {
            get {
                if (schemaImporterExtensions == null)
                    schemaImporterExtensions = new StringCollection();
                return schemaImporterExtensions; 
            }
        }

        internal XsdParameters() {
        }

        internal XsdParameters Merge(XsdParameters parameters) {
            if (parameters.classes)
                this.classes = parameters.classes;
            if (parameters.dataset)
                this.dataset = parameters.dataset;
            if (parameters.language != null)
                this.language = parameters.language;
            if (parameters.ns != null)
                this.ns = parameters.ns;
            if (parameters.nologo)
                this.nologo = parameters.nologo;
            if (parameters.outputdir != null)
                this.outputdir = parameters.outputdir;
            if (!parameters.optionsDefault)
                this.options = parameters.options;
            if (parameters.uri != null)
                this.uri = parameters.uri;

            foreach(string s in parameters.XsdSchemas)
                this.XsdSchemas.Add(s);
            foreach(string s in parameters.XdrSchemas)
                this.XdrSchemas.Add(s);
            foreach(string s in parameters.Instances)
                this.Instances.Add(s);
            foreach(string s in parameters.Assemblies)
                this.Assemblies.Add(s);
            foreach(string s in parameters.Elements)
                this.Elements.Add(s);
            foreach(string s in parameters.Types)
                this.Types.Add(s);
            foreach(string s in parameters.SchemaImporterExtensions)
                this.SchemaImporterExtensions.Add(s);

            return this;
        }

        internal static XsdParameters Read(string file) {
            if (file == null || file.Length == 0)
                return null;
            if (File.Exists(file))
                return Read(new XmlTextReader(file), new ValidationEventHandler(Xsd.XsdParametersValidationHandler));

            throw new FileNotFoundException(Res.GetString(Res.FileNotFound, file));
        }

        internal static XsdParameters Read(XmlReader xmlReader, ValidationEventHandler validationEventHandler) {
            XmlReaderSettings readerSettings = new XmlReaderSettings();
            readerSettings.ValidationType = ValidationType.Schema;
            readerSettings.ValidationFlags = XmlSchemaValidationFlags.ProcessIdentityConstraints;
            readerSettings.Schemas.Add(XsdParameters.Schema);

            if (validationEventHandler != null) {
                readerSettings.ValidationEventHandler += validationEventHandler;
            }
            else {
                readerSettings.ValidationEventHandler += new ValidationEventHandler(Xsd.XsdParametersValidationHandler);
            }
            XmlReader validatingReader = XmlReader.Create(xmlReader, readerSettings);
            XsdParametersSerializer ser = new XsdParametersSerializer();
            return (XsdParameters)ser.Deserialize(validatingReader);
        }
        
        static XmlSchema schema;
        public static XmlSchema Schema {
            get {
                if (schema == null) {
                    schema = XmlSchema.Read(new StringReader(xsdParametersSchema), null);
                }
                return schema;
            }
        }

        internal const string xsdParametersSchema = @"<?xml version='1.0' encoding='UTF-8' ?>
<xs:schema xmlns:tns='http://microsoft.com/dotnet/tools/xsd/' elementFormDefault='qualified' targetNamespace='http://microsoft.com/dotnet/tools/xsd/' xmlns:xs='http://www.w3.org/2001/XMLSchema'>
  <xs:simpleType name='options'>
    <xs:list>
      <xs:simpleType>
        <xs:restriction base='xs:string'>
          <xs:enumeration value='none' />
          <xs:enumeration value='properties' />
          <xs:enumeration value='order' />
          <xs:enumeration value='enableDataBinding' />
        </xs:restriction>
      </xs:simpleType>
    </xs:list>
  </xs:simpleType>
  
  <xs:complexType name='generateObjectModel'>
    <xs:sequence>
      <xs:element name='schema' minOccurs='0' maxOccurs='unbounded' type='xs:string'/>
    </xs:sequence>
    <xs:attribute name='language' default='cs' type='xs:string'/>
    <xs:attribute name='namespace' type='xs:string'/>
  </xs:complexType>

  <xs:complexType name='generateClasses'>
    <xs:complexContent mixed='false'>
      <xs:extension base='tns:generateObjectModel'>
        <xs:sequence>
          <xs:element name='element' minOccurs='0' maxOccurs='unbounded' type='xs:string'/>
          <xs:element minOccurs='0' name='schemaImporterExtensions'>
            <xs:complexType>
              <xs:sequence>
                <xs:element minOccurs='0' maxOccurs='unbounded' name='type' type='xs:string' />
              </xs:sequence>
            </xs:complexType>
          </xs:element>
        </xs:sequence>
        <xs:attribute name='options' default='properties' type='tns:options'/>
        <xs:attribute name='uri' type='xs:anyURI'/>
      </xs:extension>
    </xs:complexContent>
  </xs:complexType>

  <xs:complexType name='generateDataSet'>
    <xs:complexContent mixed='false'>
      <xs:extension base='tns:generateObjectModel'>
        <xs:attribute name='enableLinqDataSet' default='false' type='xs:boolean'/>
      </xs:extension>
    </xs:complexContent>
  </xs:complexType>

  <xs:complexType name='generateSchemas'>
    <xs:choice>
      <xs:element name='xdr' type='xs:string' maxOccurs='unbounded' />
      <xs:element name='xml' type='xs:string' maxOccurs='unbounded' />
      <xs:choice>
        <xs:element name='assembly' type='xs:string' maxOccurs='unbounded' />
        <xs:element name='type' type='xs:string' maxOccurs='unbounded' />
      </xs:choice>
    </xs:choice>
  </xs:complexType>

  <xs:complexType name='xsdParameters'>
    <xs:choice>
      <xs:element name='generateClasses' type='tns:generateClasses'/>
      <xs:element name='generateDataSet' type='tns:generateDataSet'/>
      <xs:element name='generateSchemas' type='tns:generateSchemas'/>
    </xs:choice>
    <xs:attribute name='output' type='xs:string'/>
    <xs:attribute name='nologo' type='xs:boolean'/>
    <xs:attribute name='help' type='xs:boolean'/>
  </xs:complexType>
  
  <xs:element name='xsd' type='tns:xsdParameters' />

</xs:schema>";

    }


    internal sealed class XsdParametersSerializer : XmlSerializer {

        protected override XmlSerializationReader CreateReader() {
            return new XmlSerializationReader1();
        }
        protected override XmlSerializationWriter CreateWriter() {
            throw new InvalidOperationException();
        }
        public override System.Boolean CanDeserialize(XmlReader xmlReader) {
            return true;
        }

        protected override void Serialize(System.Object objectToSerialize, XmlSerializationWriter writer) {
            throw new InvalidOperationException();
        }
        protected override System.Object Deserialize(XmlSerializationReader reader) {
            return ((XmlSerializationReader1)reader).Read7_xsd();
        }
    }

    internal class XmlSerializationReader1 : System.Xml.Serialization.XmlSerializationReader {

        internal object Read7_xsd() {
            object o = null;
            Reader.MoveToContent();
            if (Reader.NodeType == System.Xml.XmlNodeType.Element) {
                if (((object) Reader.LocalName == (object)id1_xsd && (object) Reader.NamespaceURI == (object)id2_Item)) {
                    o = Read6_XsdParameters(false, true);
                }
                else {
                    throw CreateUnknownNodeException();
                }
            }
            else {
                UnknownNode(null);
            }
            return (object)o;
        }

        XsdParameters Read5_GenerateClasses(XsdParameters xsd, bool isNullable, bool checkType) {
            xsd.Classes = true;
            System.Xml.XmlQualifiedName xsiType = checkType ? GetXsiType() : null;
            bool isNull = false;
            if (isNullable) isNull = ReadNull();
            if (checkType) {
                if (xsiType == null || ((object) ((System.Xml.XmlQualifiedName)xsiType).Name == (object)id6_GenerateClasses && (object) ((System.Xml.XmlQualifiedName)xsiType).Namespace == (object)id2_Item)) {
                }
                else
                    throw CreateUnknownTypeException((System.Xml.XmlQualifiedName)xsiType);
            }
            if (isNull) return null;
            StringCollection a_0 = xsd.XsdSchemas;
            StringCollection a_3 = xsd.Elements;
            StringCollection a_4 = xsd.SchemaImporterExtensions;
            while (Reader.MoveToNextAttribute()) {
                if (((object) Reader.LocalName == (object)id7_language && (object) Reader.NamespaceURI == (object)id4_Item)) {
                    xsd.Language = Reader.Value;
                }
                else if (((object) Reader.LocalName == (object)id8_namespace && (object) Reader.NamespaceURI == (object)id4_Item)) {
                    xsd.Namespace = Reader.Value;
                }
                else if (((object) Reader.LocalName == (object)id9_options && (object) Reader.NamespaceURI == (object)id4_Item)) {
                    xsd.Options = Read4_CodeGenerationOptions(Reader.Value);
                }
                else if (((object) Reader.LocalName == (object)id10_uri && (object) Reader.NamespaceURI == (object)id4_Item)) {
                    xsd.Uri = CollapseWhitespace(Reader.Value);
                }
                else if (!IsXmlnsAttribute(Reader.Name)) {
                    UnknownNode((object)xsd);
                }
            }
            Reader.MoveToElement();
            if (Reader.IsEmptyElement) {
                Reader.Skip();
                return xsd;
            }
            Reader.ReadStartElement();
            Reader.MoveToContent();
            int whileIterations1 = 0;
            int readerCount1 = ReaderCount;
            while (Reader.NodeType != System.Xml.XmlNodeType.EndElement && Reader.NodeType != System.Xml.XmlNodeType.None) {
                if (Reader.NodeType == System.Xml.XmlNodeType.Element) {
                    if (((object) Reader.LocalName == (object)id11_schema && (object) Reader.NamespaceURI == (object)id2_Item)) { {
                            a_0.Add(Reader.ReadElementString());
                        }
                    }
                    else if (((object) Reader.LocalName == (object)id12_element && (object) Reader.NamespaceURI == (object)id2_Item)) { {
                            a_3.Add(Reader.ReadElementString());
                        }
                    }
                    else if (((object) Reader.LocalName == (object)id13_schemaImporterExtensions && (object) Reader.NamespaceURI == (object)id2_Item)) {
                        if (!ReadNull()) {
                            StringCollection a_4_0 = xsd.@SchemaImporterExtensions;
                            if (Reader.IsEmptyElement) {
                                Reader.Skip();
                            }
                            else {
                                Reader.ReadStartElement();
                                Reader.MoveToContent();
                                int whileIterations2 = 0;
                                int readerCount2 = ReaderCount;
                                while (Reader.NodeType != System.Xml.XmlNodeType.EndElement && Reader.NodeType != System.Xml.XmlNodeType.None) {
                                    if (Reader.NodeType == System.Xml.XmlNodeType.Element) {
                                        if (((object) Reader.LocalName == (object)id14_type && (object) Reader.NamespaceURI == (object)id2_Item)) { {
                                                a_4_0.Add(Reader.ReadElementString());
                                            }
                                        }
                                        else {
                                            UnknownNode(null);
                                        }
                                    }
                                    else {
                                        UnknownNode(null);
                                    }
                                    Reader.MoveToContent();
                                    CheckReaderCount(ref whileIterations2, ref readerCount2);
                                }
                                ReadEndElement();
                            }
                        }
                    }
                    else {
                        UnknownNode((object)xsd);
                    }
                }
                else {
                    UnknownNode((object)xsd);
                }
                Reader.MoveToContent();
                CheckReaderCount(ref whileIterations1, ref readerCount1);
            }
            ReadEndElement();
            return xsd;
        }

        System.Collections.Hashtable _CodeGenerationOptionsValues;

        internal System.Collections.Hashtable CodeGenerationOptionsValues {
            get {
                if ((object)_CodeGenerationOptionsValues == null) {
                    System.Collections.Hashtable h = new System.Collections.Hashtable();
                    h.Add(@"properties", (System.Int64)System.Xml.Serialization.CodeGenerationOptions.@GenerateProperties);
                    h.Add(@"order", (System.Int64)System.Xml.Serialization.CodeGenerationOptions.@GenerateOrder);
                    h.Add(@"enableDataBinding", (System.Int64)System.Xml.Serialization.CodeGenerationOptions.@EnableDataBinding);
                    h.Add(@"none", (System.Int64)0);
                    _CodeGenerationOptionsValues = h;
                }
                return _CodeGenerationOptionsValues;
            }
        }

        System.Xml.Serialization.CodeGenerationOptions Read4_CodeGenerationOptions(string s) {
            return (System.Xml.Serialization.CodeGenerationOptions)ToEnum(s, CodeGenerationOptionsValues, @"System.Xml.Serialization.CodeGenerationOptions");
        }

        XsdParameters Read3_GenerateSchemas(XsdParameters xsd, bool isNullable, bool checkType) {
            System.Xml.XmlQualifiedName xsiType = checkType ? GetXsiType() : null;
            bool isNull = false;
            if (isNullable) isNull = ReadNull();
            if (checkType) {
                if (xsiType == null || ((object) ((System.Xml.XmlQualifiedName)xsiType).Name == (object)id5_generateSchemas && (object) ((System.Xml.XmlQualifiedName)xsiType).Namespace == (object)id2_Item)) {
                }
                else
                    throw CreateUnknownTypeException((System.Xml.XmlQualifiedName)xsiType);
            }
            if (isNull) return null;
            StringCollection a_0 = xsd.Instances;
            StringCollection a_1 = xsd.XdrSchemas;
            StringCollection a_2 = xsd.Assemblies;
            StringCollection a_3 = xsd.Types;
            bool[] paramsRead = new bool[4];
            while (Reader.MoveToNextAttribute()) {
                if (!IsXmlnsAttribute(Reader.Name)) {
                    UnknownNode((object)xsd);
                }
            }
            Reader.MoveToElement();
            if (Reader.IsEmptyElement) {
                Reader.Skip();
                return xsd;
            }
            Reader.ReadStartElement();
            Reader.MoveToContent();
            int whileIterations1 = 0;
            int readerCount1 = ReaderCount;
            while (Reader.NodeType != System.Xml.XmlNodeType.EndElement && Reader.NodeType != System.Xml.XmlNodeType.None) {
                if (Reader.NodeType == System.Xml.XmlNodeType.Element) {
                    if (((object) Reader.LocalName == (object)id15_xml && (object) Reader.NamespaceURI == (object)id2_Item)) { {
                            a_0.Add(Reader.ReadElementString());
                        }
                    }
                    else if (((object) Reader.LocalName == (object)id16_xdr && (object) Reader.NamespaceURI == (object)id2_Item)) { {
                            a_1.Add(Reader.ReadElementString());
                        }
                    }
                    else if (((object) Reader.LocalName == (object)id17_assembly && (object) Reader.NamespaceURI == (object)id2_Item)) { {
                            a_2.Add(Reader.ReadElementString());
                        }
                    }
                    else if (((object) Reader.LocalName == (object)id14_type && (object) Reader.NamespaceURI == (object)id2_Item)) { {
                            a_3.Add(Reader.ReadElementString());
                        }
                    }
                    else {
                        UnknownNode((object)xsd);
                    }
                }
                else {
                    UnknownNode((object)xsd);
                }
                Reader.MoveToContent();
                CheckReaderCount(ref whileIterations1, ref readerCount1);
            }
            ReadEndElement();
            return xsd;
        }

        XsdParameters Read2_GenerateDataset(XsdParameters xsd, bool isNullable, bool checkType) {
            xsd.Dataset = true;
            System.Xml.XmlQualifiedName xsiType = checkType ? GetXsiType() : null;
            bool isNull = false;
            if (isNullable) isNull = ReadNull();
            if (checkType) {
                if (xsiType == null || ((object) ((System.Xml.XmlQualifiedName)xsiType).Name == (object)id3_generateObjectModel && (object) ((System.Xml.XmlQualifiedName)xsiType).Namespace == (object)id2_Item)) {
                }
                else
                    throw CreateUnknownTypeException((System.Xml.XmlQualifiedName)xsiType);
            }
            if (isNull) return null;
            StringCollection a_0 = xsd.XsdSchemas;
            while (Reader.MoveToNextAttribute()) {
                if (((object) Reader.LocalName == (object)id7_language && (object) Reader.NamespaceURI == (object)id4_Item)) {
                    xsd.Language = Reader.Value;
                }
                else if (((object) Reader.LocalName == (object)id8_namespace && (object) Reader.NamespaceURI == (object)id4_Item)) {
                    xsd.Namespace = Reader.Value;
                }
                else if (((object) Reader.LocalName == (object)id24_enableLinqDataSet && (object) Reader.NamespaceURI == (object)id4_Item)) {
                    xsd.EnableLinqDataSet = System.Xml.XmlConvert.ToBoolean(Reader.Value);
                }
                else if (!IsXmlnsAttribute(Reader.Name)) {
                    UnknownNode((object)xsd);
                }
            }
            Reader.MoveToElement();
            if (Reader.IsEmptyElement) {
                Reader.Skip();
                return xsd;
            }
            Reader.ReadStartElement();
            Reader.MoveToContent();
            int whileIterations1 = 0;
            int readerCount1 = ReaderCount;
            while (Reader.NodeType != System.Xml.XmlNodeType.EndElement && Reader.NodeType != System.Xml.XmlNodeType.None) {
                if (Reader.NodeType == System.Xml.XmlNodeType.Element) {
                    if (((object) Reader.LocalName == (object)id11_schema && (object) Reader.NamespaceURI == (object)id2_Item)) { {
                            a_0.Add(Reader.ReadElementString());
                        }
                    }
                    else {
                        UnknownNode((object)xsd);
                    }
                }
                else {
                    UnknownNode((object)xsd);
                }
                Reader.MoveToContent();
                CheckReaderCount(ref whileIterations1, ref readerCount1);
            }
            ReadEndElement();
            return xsd;
        }

        XsdParameters Read6_XsdParameters(bool isNullable, bool checkType) {
            System.Xml.XmlQualifiedName xsiType = checkType ? GetXsiType() : null;
            bool isNull = false;
            if (isNullable) isNull = ReadNull();
            if (checkType) {
                if (xsiType == null || ((object) ((System.Xml.XmlQualifiedName)xsiType).Name == (object)id18_xsdParameters && (object) ((System.Xml.XmlQualifiedName)xsiType).Namespace == (object)id2_Item)) {
                }
                else
                    throw CreateUnknownTypeException((System.Xml.XmlQualifiedName)xsiType);
            }
            if (isNull) return null;
            XsdParameters o = new XsdParameters();
            bool[] paramsRead = new bool[6];
            while (Reader.MoveToNextAttribute()) {
                if (!paramsRead[3] && ((object) Reader.LocalName == (object)id19_output && (object) Reader.NamespaceURI == (object)id4_Item)) {
                    o.@OutputDir = Reader.Value;
                    paramsRead[3] = true;
                }
                else if (!paramsRead[4] && ((object) Reader.LocalName == (object)id20_nologo && (object) Reader.NamespaceURI == (object)id4_Item)) {
                    o.@Nologo = System.Xml.XmlConvert.ToBoolean(Reader.Value);
                    paramsRead[4] = true;
                }
                else if (!paramsRead[5] && ((object) Reader.LocalName == (object)id21_help && (object) Reader.NamespaceURI == (object)id4_Item)) {
                    o.@Help = System.Xml.XmlConvert.ToBoolean(Reader.Value);
                    paramsRead[5] = true;
                }
                else if (!IsXmlnsAttribute(Reader.Name)) {
                    UnknownNode((object)o);
                }
            }
            Reader.MoveToElement();
            if (Reader.IsEmptyElement) {
                Reader.Skip();
                return o;
            }
            Reader.ReadStartElement();
            Reader.MoveToContent();
            int whileIterations1 = 0;
            int readerCount1 = ReaderCount;
            while (Reader.NodeType != System.Xml.XmlNodeType.EndElement && Reader.NodeType != System.Xml.XmlNodeType.None) {
                if (Reader.NodeType == System.Xml.XmlNodeType.Element) {
                    if (!paramsRead[0] && ((object) Reader.LocalName == (object)id22_generateDataSet && (object) Reader.NamespaceURI == (object)id2_Item)) {
                        Read2_GenerateDataset(o, false, true);
                        paramsRead[0] = true;
                    }
                    else if (!paramsRead[1] && ((object) Reader.LocalName == (object)id5_generateSchemas && (object) Reader.NamespaceURI == (object)id2_Item)) {
                        Read3_GenerateSchemas(o, false, true);
                        paramsRead[1] = true;
                    }
                    else if (!paramsRead[2] && ((object) Reader.LocalName == (object)id23_generateClasses && (object) Reader.NamespaceURI == (object)id2_Item)) {
                        Read5_GenerateClasses(o, false, true);
                        paramsRead[2] = true;
                    }
                    else {
                        UnknownNode((object)o);
                    }
                }
                else {
                    UnknownNode((object)o);
                }
                Reader.MoveToContent();
                CheckReaderCount(ref whileIterations1, ref readerCount1);
            }
            ReadEndElement();
            return o;
        }

        protected override void InitCallbacks() {
        }

        System.String id6_GenerateClasses;
        System.String id5_generateSchemas;
        System.String id14_type;
        System.String id2_Item;
        System.String id9_options;
        System.String id16_xdr;
        System.String id13_schemaImporterExtensions;
        System.String id17_assembly;
        System.String id23_generateClasses;
        System.String id1_xsd;
        System.String id12_element;
        System.String id11_schema;
        System.String id4_Item;
        System.String id20_nologo;
        System.String id15_xml;
        System.String id21_help;
        System.String id3_generateObjectModel;
        System.String id18_xsdParameters;
        System.String id10_uri;
        System.String id7_language;
        System.String id22_generateDataSet;
        System.String id8_namespace;
        System.String id19_output;
        System.String id24_enableLinqDataSet;

        protected override void InitIDs() {
            id6_GenerateClasses = Reader.NameTable.Add(@"GenerateClasses");
            id5_generateSchemas = Reader.NameTable.Add(@"generateSchemas");
            id14_type = Reader.NameTable.Add(@"type");
            id2_Item = Reader.NameTable.Add(@"http://microsoft.com/dotnet/tools/xsd/");
            id9_options = Reader.NameTable.Add(@"options");
            id16_xdr = Reader.NameTable.Add(@"xdr");
            id13_schemaImporterExtensions = Reader.NameTable.Add(@"schemaImporterExtensions");
            id17_assembly = Reader.NameTable.Add(@"assembly");
            id23_generateClasses = Reader.NameTable.Add(@"generateClasses");
            id1_xsd = Reader.NameTable.Add(@"xsd");
            id12_element = Reader.NameTable.Add(@"element");
            id11_schema = Reader.NameTable.Add(@"schema");
            id4_Item = Reader.NameTable.Add(@"");
            id20_nologo = Reader.NameTable.Add(@"nologo");
            id15_xml = Reader.NameTable.Add(@"xml");
            id21_help = Reader.NameTable.Add(@"help");
            id3_generateObjectModel = Reader.NameTable.Add(@"generateObjectModel");
            id18_xsdParameters = Reader.NameTable.Add(@"xsdParameters");
            id10_uri = Reader.NameTable.Add(@"uri");
            id7_language = Reader.NameTable.Add(@"language");
            id22_generateDataSet = Reader.NameTable.Add(@"generateDataSet");
            id8_namespace = Reader.NameTable.Add(@"namespace");
            id19_output = Reader.NameTable.Add(@"output");
            id24_enableLinqDataSet = Reader.NameTable.Add(@"enableLinqDataSet");
        }
    }
}

