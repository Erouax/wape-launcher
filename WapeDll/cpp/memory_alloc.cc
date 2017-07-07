#pragma once
#include "global.h"

#ifndef _DEBUG
constexpr const auto kRtlGetProcessHeaps = cx::crc32("RtlGetProcessHeaps");
constexpr const auto kRtlAllocateHeap = cx::crc32("RtlAllocateHeap");
constexpr const auto kRtlFreeHeap = cx::crc32("RtlFreeHeap");
constexpr const auto kReAllocHeap = cx::crc32("RtlReAllocateHeap");
constexpr const auto kRtlSizeHeap = cx::crc32("RtlSizeHeap");

namespace {
void* MemCopy(void* dst, const void* src, size_t len) {
  if (dst && src) {
    auto dst0 = static_cast<volatile char*>(dst);
    auto src0 = static_cast<volatile char*>(const_cast<void*>(src));

    while (len) {
      len--;
      *dst0 = *src0;
      dst0++;
      src0++;
    }
  }

  return dst;
}


void MemSet(const void* ptr, BYTE rep, size_t len) {
  if (ptr) {
    auto tmp = static_cast<volatile char*>(const_cast<void*>(ptr));

    while (len) {
      *tmp = rep;
      len--;
      tmp++;
    }
  }
}


void* AllocateHeap(size_t size, ULONG flags) {
  static FP(RtlGetProcessHeaps) get_process_heaps = nullptr;
  static FP(RtlAllocateHeap) allocate_heap = nullptr;

  if (get_process_heaps == nullptr && allocate_heap == nullptr) {
    const auto ntdll = GetModuleBase(kNtdll);
    get_process_heaps = CFP(RtlGetProcessHeaps)
      (GetProcAddr(ntdll, kRtlGetProcessHeaps));
    allocate_heap = CFP(RtlAllocateHeap)
      (GetProcAddr(ntdll, kRtlAllocateHeap));
  }

  auto heap = PVOID{nullptr};
  get_process_heaps(1, &heap);
  return allocate_heap(heap, flags, size);
}


SIZE_T MemSize(void* ptr) {
  static FP(RtlGetProcessHeaps) get_process_heaps = nullptr;
  static FP(RtlSizeHeap) size_heap = nullptr;

  if (get_process_heaps == nullptr && size_heap == nullptr) {
    const auto ntdll = GetModuleBase(kNtdll);
    get_process_heaps = CFP(RtlGetProcessHeaps)
      (GetProcAddr(ntdll, kRtlGetProcessHeaps));
    size_heap = CFP(RtlSizeHeap)(GetProcAddr(ntdll, kRtlSizeHeap));
  }

  if (ptr) {
    auto heap = PVOID{nullptr};
    get_process_heaps(1, &heap);
    return size_heap(heap, 0, ptr);
  }

  return 0;
}


void MemFree(void* ptr) {
  static FP(RtlGetProcessHeaps) get_process_heaps = nullptr;
  static FP(RtlFreeHeap) free_heap = nullptr;

  if (get_process_heaps == nullptr && free_heap == nullptr) {
    const auto ntdll = GetModuleBase(kNtdll);
    get_process_heaps = CFP(RtlGetProcessHeaps)
      (GetProcAddr(ntdll, kRtlGetProcessHeaps));
    free_heap = CFP(RtlFreeHeap)(GetProcAddr(ntdll, kRtlFreeHeap));
  }

  auto heap = PVOID{nullptr};
  get_process_heaps(1, &heap);

  // zero the memory for security
  if (ptr) {
    const auto size = MemSize(ptr);

    if (size > 0) {
      MemSet(ptr, 0, size);
    }
  }

  free_heap(heap, 0, ptr);
}


void* MemReAlloc(void* ptr, size_t size) {
  SIZE_T prev_len = 0;

  if (ptr) {
    prev_len = MemSize(ptr);
  }

  auto new_addr = PVOID{nullptr};
  if (size > 0) {
    new_addr = AllocateHeap(size, 0);

    if (ptr && new_addr && prev_len) {
      if (size < prev_len) {
        prev_len = size;
      }

      MemCopy(new_addr, ptr, prev_len);
    }
  }

  if (ptr) {
    MemFree(ptr);
  }

  return new_addr;
}
}  // namespace


void* __cdecl malloc(size_t size) {
  return AllocateHeap(size, 0);
}


void* __cdecl calloc(size_t num, size_t size) {
  return AllocateHeap(num * size, HEAP_ZERO_MEMORY);
}


void* __cdecl realloc(void* ptr, size_t size) {
  return MemReAlloc(ptr, size);
}


void __cdecl free(void* ptr) {
  MemFree(ptr);
}


void* __cdecl operator new(size_t size) {
  return malloc(size);
}


void* operator new[](size_t size) {
  return malloc(size);
}


void __cdecl operator delete(void* ptr) {
  free(ptr);
}

void operator delete[](void* ptr) {
  free(ptr);
}


#ifdef _WIN64
void __cdecl operator delete(void* ptr, unsigned __int64)
#else
void __cdecl operator delete(void* ptr, unsigned __int32)
#endif
{
  free(ptr);
}
#endif
