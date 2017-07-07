#pragma once
#include "global.h"

#ifndef _DEBUG
constexpr const auto kRtlGetProcessHeaps = cx::crc32("RtlGetProcessHeaps");
constexpr const auto kRtlAllocateHeap = cx::crc32("RtlAllocateHeap");
constexpr const auto kRtlFreeHeap = cx::crc32("RtlFreeHeap");
constexpr const auto kReAllocHeap = cx::crc32("RtlReAllocateHeap");

void* __cdecl malloc(size_t size) {
  typedef void*(WINAPI *fn)(...);

  static LPVOID rtl_get_process_heaps = nullptr;
  static LPVOID rtl_allocate_heap = nullptr;

  if (rtl_get_process_heaps == nullptr &&
    rtl_allocate_heap == nullptr) {
    const auto ntdll = GetModuleBase(kNtdll);
    rtl_get_process_heaps = GetProcAddr(ntdll, kRtlGetProcessHeaps);
    rtl_allocate_heap = GetProcAddr(ntdll, kRtlAllocateHeap);
  }

  auto heap = HANDLE{nullptr};
  reinterpret_cast<fn>(rtl_get_process_heaps)(1, &heap);
  return reinterpret_cast<fn>(rtl_allocate_heap)(heap, 0, size);
}

void* __cdecl calloc(size_t num, size_t size) {
  typedef void*(WINAPI *fn)(...);

  static LPVOID rtl_get_process_heaps = nullptr;
  static LPVOID rtl_allocate_heap = nullptr;

  if (rtl_get_process_heaps == nullptr &&
    rtl_allocate_heap == nullptr) {
    const auto ntdll = GetModuleBase(kNtdll);
    rtl_get_process_heaps = GetProcAddr(ntdll, kRtlGetProcessHeaps);
    rtl_allocate_heap = GetProcAddr(ntdll, kRtlAllocateHeap);
  }

  auto heap = HANDLE{nullptr};
  reinterpret_cast<fn>(rtl_get_process_heaps)(1, &heap);
  return reinterpret_cast<fn>(rtl_allocate_heap)(heap, HEAP_ZERO_MEMORY, size);
}

void* __cdecl realloc(void* ptr, size_t size) {
  typedef void*(WINAPI *fn)(...);

	// RtlReAllocateHeap doesn't support nullptr?
	if (ptr == nullptr) {
		return malloc(size);
	}

  static LPVOID rtl_get_process_heaps = nullptr;
  static LPVOID rtl_re_alloc_heap = nullptr;

  if (rtl_get_process_heaps == nullptr &&
    rtl_re_alloc_heap == nullptr) {
    const auto ntdll = GetModuleBase(kNtdll);
    rtl_get_process_heaps = GetProcAddr(ntdll, kRtlGetProcessHeaps);
    rtl_re_alloc_heap = GetProcAddr(ntdll, kReAllocHeap);
  }

  auto heap = HANDLE{nullptr};
  reinterpret_cast<fn>(rtl_get_process_heaps)(1, heap);
  return reinterpret_cast<fn>(rtl_re_alloc_heap)(heap, 0, ptr, size);
}

void __cdecl free(void* ptr) {
  typedef void*(WINAPI *fn)(...);

  static LPVOID rtl_get_process_heaps = nullptr;
  static LPVOID rtl_free_heap = nullptr;

  if (rtl_get_process_heaps == nullptr &&
    rtl_free_heap == nullptr) {
    const auto ntdll = GetModuleBase(kNtdll);
    rtl_get_process_heaps = GetProcAddr(ntdll, kRtlGetProcessHeaps);
    rtl_free_heap = GetProcAddr(ntdll, kRtlFreeHeap);
  }

  auto heap = HANDLE{nullptr};
  reinterpret_cast<fn>(rtl_get_process_heaps)(1, &heap);
  reinterpret_cast<fn>(rtl_free_heap)(heap, 0, ptr);
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
