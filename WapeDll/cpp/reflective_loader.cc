// https://github.com/stephenfewer/ReflectiveDLLInjection
// modified by jesusnutsack
#include "reflective_loader.h"
#include <intrin.h>
#include "global.h"

// set this if the thread is supposed to be hidden from the debugger
#ifndef _DEBUG
#define THREAD_HIDDEN_FROM_DEBUGGER
#endif

#if !defined(_DEBUG) and !defined(THREAD_HIDDEN_FROM_DEBUGGER)
#pragma message("WARNING: You sure you want to compile without THREAD_HIDDEN_FROM_DEBUGGER flag?!")
#pragma message("WARNING: You sure you want to compile without THREAD_HIDDEN_FROM_DEBUGGER flag?!")
#pragma message("WARNING: You sure you want to compile without THREAD_HIDDEN_FROM_DEBUGGER flag?!")
#endif

namespace reflective_loader {
namespace {
constexpr auto kEntryPointMod = DWORD{0x31337};
}  // namespace

#define DEREF(name)     *reinterpret_cast<UINT_PTR*>(name)
#define DEREF_64(name)  *reinterpret_cast<DWORD64*>(name)
#define DEREF_32(name)  *reinterpret_cast<DWORD*>(name)
#define DEREF_16(name)  *reinterpret_cast<WORD*>(name)
#define DEREF_8(name)   *reinterpret_cast<BYTE*>(name)

typedef BOOL(WINAPI *FnDllMain)(HINSTANCE, DWORD, LPVOID);

namespace {
template<size_t N>
constexpr __forceinline
DWORD hash(const char (&S)[N]) {
  auto hash = DWORD{0};

  for (auto iii = size_t{0}; iii < N - 1; iii++) {
    hash = ((hash << 7) & static_cast<DWORD>(-1)) | (hash >> (32 - 7));
    hash ^= S[iii];
  }

  return hash;
}

constexpr const auto kNtDll =
  hash("NTDLL.DLL");
constexpr const auto kNtAllocateVirtualMemory =
  hash("NtAllocateVirtualMemory");
constexpr const auto kRtlCreateUnicodeStringFromAsciiz =
  hash("RtlCreateUnicodeStringFromAsciiz");
constexpr const auto kRtlFreeUnicodeString =
  hash("RtlFreeUnicodeString");
constexpr const auto kLdrLoadDll =
  hash("LdrLoadDll");
constexpr const auto kLdrGetProcedureAddress =
  hash("LdrGetProcedureAddress");
constexpr const auto kNtFlushInstructionCache =
  hash("NtFlushInstructionCache");
#ifdef THREAD_HIDDEN_FROM_DEBUGGER
constexpr const auto kNtQueryInformationThread =
	hash("NtQueryInformationThread");
constexpr const auto kFunctionCount = 7;
#else
constexpr const auto kFunctionCount = 6;
#endif
}  // namespace

typedef struct _IMAGE_RELOC {
  WORD offset : 12;
  WORD type : 4;
} IMAGE_RELOC, *PIMAGE_RELOC;

NTSTATUS NTAPI ReflectiveLoader(ReflectiveLoaderData* loader_data) {
  decltype(&NtAllocateVirtualMemory) mem_alloc = nullptr;
  decltype(&RtlCreateUnicodeStringFromAsciiz) unicode_from_ascii = nullptr;
  decltype(&RtlFreeUnicodeString) unicode_free = nullptr;
  decltype(&LdrLoadDll) load_dll = nullptr;
  decltype(&LdrGetProcedureAddress) get_proc_addr = nullptr;
  decltype(&NtFlushInstructionCache) flush_inst_cache = nullptr;
#ifdef THREAD_HIDDEN_FROM_DEBUGGER
	decltype(&NtQueryInformationThread) query_thread_info = nullptr;
#endif

  USHORT usCounter;

  // the initial location of this image in memory
  ULONG_PTR uiLibraryAddress;
  // the kernels base address and later this images newly loaded base address
  ULONG_PTR uiBaseAddress;

  // variables for processing the kernels export table
  ULONG_PTR uiAddressArray;
  ULONG_PTR uiNameArray;
  ULONG_PTR uiExportDir;
  ULONG_PTR uiNameOrdinals;

  // variables for loading this image
  ULONG_PTR uiHeaderValue;
  ULONG_PTR uiValueA;
  ULONG_PTR uiValueB;
  ULONG_PTR uiValueC;
	ULONG_PTR uiValueD;
	ULONG_PTR uiValueE;

  // module loading variables
  UNICODE_STRING unicodeA;
  ANSI_STRING ansiA;

#ifdef THREAD_HIDDEN_FROM_DEBUGGER
	BOOLEAN hidden;
#endif

#pragma region STEP 0: grab the image_base the reflective loader data
  uiLibraryAddress = reinterpret_cast<ULONG_PTR>(loader_data->image_base);
#pragma endregion

#pragma region STEP 1: process the kernels exports for the functions our loader needs...
  // get the Process Enviroment Block
#ifdef _WIN64
  uiBaseAddress = __readgsqword(0x60);
#else
  uiBaseAddress = __readfsdword(0x30);
#endif

  // get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
  uiBaseAddress = reinterpret_cast<ULONG_PTR>(reinterpret_cast<PPEB>(uiBaseAddress)->Ldr);

  // get the first entry of the InMemoryOrder module list
  uiValueA = reinterpret_cast<ULONG_PTR>(reinterpret_cast<PPEB_LDR_DATA>(uiBaseAddress)->InMemoryOrderModuleList.Flink);
  while (uiValueA) {
		// get pointer to the record
		uiValueB = reinterpret_cast<ULONG_PTR>(CONTAINING_RECORD(uiValueA, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
    // get pointer to current modules name (unicode string)
    uiValueC = reinterpret_cast<ULONG_PTR>(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(uiValueB)->BaseDllName.Buffer);
    // set bCounter to the length for the loop
		usCounter = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(uiValueB)->BaseDllName.Length / sizeof(WCHAR);
    // clear dwHash which will store the hash of the module name
		uiValueD = 0;

    // compute the hash of the module name...
    do {
			uiValueD = ((uiValueD << 7) & static_cast<DWORD>(-1)) | (uiValueD >> (32 - 7));
      // normalize to uppercase if the module name is in lowercase
      if (*reinterpret_cast<WCHAR*>(uiValueC) >= L'a') {
				uiValueD ^= *reinterpret_cast<WCHAR*>(uiValueC) - 0x20;
      } else {
				uiValueD ^= *reinterpret_cast<WCHAR*>(uiValueC);
      }
			uiValueC += sizeof(WCHAR);
    } while (--usCounter);

    // to keep track of whether we found all our functions
    // if 0 - break out of the module search loop.
    usCounter = 1337;

    // compare the hash with that of ntdll.dll
    if (uiValueD == kNtDll) {
      // get this modules base address
      uiBaseAddress = reinterpret_cast<ULONG_PTR>(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(uiValueB)->DllBase);
      // get the VA of the modules NT Header
      uiExportDir = uiBaseAddress + reinterpret_cast<PIMAGE_DOS_HEADER>(uiBaseAddress)->e_lfanew;
      // uiNameArray = the address of the modules export directory entry
      uiNameArray = reinterpret_cast<ULONG_PTR>(&reinterpret_cast<PIMAGE_NT_HEADERS>(uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
      // get the VA of the export directory
      uiExportDir = (uiBaseAddress + reinterpret_cast<PIMAGE_DATA_DIRECTORY>(uiNameArray)->VirtualAddress);
      // get the VA for the array of name pointers
      uiNameArray = (uiBaseAddress + reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(uiExportDir)->AddressOfNames);
      // get the VA for the array of name ordinals
      uiNameOrdinals = (uiBaseAddress + reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(uiExportDir)->AddressOfNameOrdinals);
      
      usCounter = kFunctionCount;

      // loop while we still have imports to find
      while (usCounter > 0) {
        // compute the hash values for this function name
        uiValueB = uiBaseAddress + DEREF_32(uiNameArray);
				uiValueD = 0;
        while (DEREF_8(uiValueB)) {
					uiValueD = ((uiValueD << 7) & static_cast<DWORD>(-1)) | (uiValueD >> (32 - 7));
					uiValueD ^= DEREF_8(uiValueB);
          uiValueB++;
        }

        // if we have found a function we want we get its virtual address
        switch (uiValueD) {
          case kNtAllocateVirtualMemory:
          case kRtlCreateUnicodeStringFromAsciiz:
          case kRtlFreeUnicodeString:
          case kLdrLoadDll:
          case kLdrGetProcedureAddress:
          case kNtFlushInstructionCache:
#ifdef THREAD_HIDDEN_FROM_DEBUGGER
					case kNtQueryInformationThread:
#endif
            break;
          default:
            goto NextFunctionName;
        }

        // get the VA for the array of addresses
        uiAddressArray = (uiBaseAddress + reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(uiExportDir)->AddressOfFunctions);

        // use this functions name ordinal as an index into the array of name pointers
        uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

        switch (uiValueD) {
          case kNtAllocateVirtualMemory:
            mem_alloc = reinterpret_cast<decltype(mem_alloc)>(uiBaseAddress + DEREF_32(uiAddressArray));
            break;
          case kRtlCreateUnicodeStringFromAsciiz:
            unicode_from_ascii = reinterpret_cast<decltype(unicode_from_ascii)>(uiBaseAddress + DEREF_32(uiAddressArray));
            break;
          case kRtlFreeUnicodeString:
            unicode_free = reinterpret_cast<decltype(unicode_free)>(uiBaseAddress + DEREF_32(uiAddressArray));
            break;
          case kLdrLoadDll:
            load_dll = reinterpret_cast<decltype(load_dll)>(uiBaseAddress + DEREF_32(uiAddressArray));
            break;
          case kLdrGetProcedureAddress:
            get_proc_addr = reinterpret_cast<decltype(get_proc_addr)>(uiBaseAddress + DEREF_32(uiAddressArray));
            break;
          case kNtFlushInstructionCache:
            flush_inst_cache = reinterpret_cast<decltype(flush_inst_cache)>(uiBaseAddress + DEREF_32(uiAddressArray));
            break;
#ifdef THREAD_HIDDEN_FROM_DEBUGGER
					case kNtQueryInformationThread: {
						// if the thread is supposed to be hidden from debuggers
						// but is not actually hidden, don't continue execution.
						query_thread_info = reinterpret_cast<decltype(query_thread_info)>(uiBaseAddress + DEREF_32(uiAddressArray));
						if (NT_SUCCESS(query_thread_info(NtCurrentThread(), ThreadHideFromDebugger, &hidden, sizeof(hidden), nullptr))) {
							if (!hidden) {
								// to indicate the launcher doesn't have to free anything.
								loader_data->image_base = nullptr;
								goto end;
							}
						}
						break;
					}
#endif
          default:
            break;
        }

        // decrement search target counter to indicat we found a function
        usCounter--;

NextFunctionName:
        // get the next exported function name
        uiNameArray += sizeof(DWORD);
        // get the next exported function name ordinal
        uiNameOrdinals += sizeof(WORD);
      }
    }

    // we stop searching when we have found everything we need.
    if (usCounter == 0) {
      break;
    }

    // get the next entry
    uiValueA = DEREF(uiValueA);
  }
#pragma endregion

#pragma region STEP 2: load our image into a new permanent location in memory...
  // get the VA of the NT Header for the PE to be loaded
  uiHeaderValue = uiLibraryAddress + reinterpret_cast<PIMAGE_DOS_HEADER>(uiLibraryAddress)->e_lfanew;

  // allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
  // relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	uiBaseAddress = 0;
	uiValueA = reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->OptionalHeader.SizeOfImage;
  mem_alloc(NtCurrentProcess(), reinterpret_cast<PVOID*>(&uiBaseAddress), 0, &uiValueA, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

  // we must now copy over the headers
  uiValueA = reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->OptionalHeader.SizeOfHeaders;
  uiValueB = uiLibraryAddress;
  uiValueC = uiBaseAddress;

  while (uiValueA--) {
    *reinterpret_cast<BYTE*>(uiValueC++) = *reinterpret_cast<BYTE*>(uiValueB++);
  }
#pragma endregion 

#pragma region STEP 3: load in all of our sections...
  // uiValueA = the VA of the first section
	uiValueA = reinterpret_cast<ULONG_PTR>(&reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->OptionalHeader) + reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->FileHeader.SizeOfOptionalHeader;
  // iterate through all sections, loading them into memory.
  usCounter = reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->FileHeader.NumberOfSections;

  while (usCounter--) {
    // uiValueB is the VA for this section
    uiValueB = (uiBaseAddress + reinterpret_cast<PIMAGE_SECTION_HEADER>(uiValueA)->VirtualAddress);
    // uiValueC if the VA for this sections data
    uiValueC = (uiLibraryAddress + reinterpret_cast<PIMAGE_SECTION_HEADER>(uiValueA)->PointerToRawData);
    // copy the section over
    uiValueD = reinterpret_cast<PIMAGE_SECTION_HEADER>(uiValueA)->SizeOfRawData;

    while (uiValueD--) {
			*reinterpret_cast<BYTE*>(uiValueB++) = *reinterpret_cast<BYTE*>(uiValueC++);
    }

    // get the VA of the next section
    uiValueA += sizeof(IMAGE_SECTION_HEADER);
  }
#pragma endregion

#pragma region STEP 4: process our images import table...
  // uiValueB = the address of the import directory
  uiValueB = reinterpret_cast<ULONG_PTR>(&reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

  // we assume their is an import table to process
  // uiValueC is the first entry in the import table
  uiValueC = (uiBaseAddress + reinterpret_cast<PIMAGE_DATA_DIRECTORY>(uiValueB)->VirtualAddress);

  // itterate through all imports
  while (reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(uiValueC)->Name) {
    // use LrLoadDll to load the imported module into memory
    unicode_from_ascii(&unicodeA, reinterpret_cast<PSTR>(uiBaseAddress + reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(uiValueC)->Name));
  	load_dll(nullptr, nullptr, &unicodeA, reinterpret_cast<PHANDLE>(&uiLibraryAddress));
    unicode_free(&unicodeA);

    // uiValueD = VA of the OriginalFirstThunk
    uiValueD = (uiBaseAddress + reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(uiValueC)->OriginalFirstThunk);
    // uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
    uiValueA = (uiBaseAddress + reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(uiValueC)->FirstThunk);

    // itterate through all imported functions, importing by ordinal if no name present
    while (DEREF(uiValueA)) {
      // sanity check uiValueD as some compilers only import by FirstThunk
      if (uiValueD && reinterpret_cast<PIMAGE_THUNK_DATA>(uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
        // get the VA of the modules NT Header
        uiExportDir = uiLibraryAddress + reinterpret_cast<PIMAGE_DOS_HEADER>(uiLibraryAddress)->e_lfanew;
        // uiNameArray = the address of the modules export directory entry
        uiNameArray = reinterpret_cast<ULONG_PTR>(&reinterpret_cast<PIMAGE_NT_HEADERS>(uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
        // get the VA of the export directory
        uiExportDir = uiLibraryAddress + reinterpret_cast<PIMAGE_DATA_DIRECTORY>(uiNameArray)->VirtualAddress;
        // get the VA for the array of addresses
        uiAddressArray = uiLibraryAddress + reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(uiExportDir)->AddressOfFunctions;
        // use the import ordinal (- export ordinal base) as an index into the array of addresses
        uiAddressArray += (IMAGE_ORDINAL(reinterpret_cast<PIMAGE_THUNK_DATA>(uiValueD)->u1.Ordinal) - reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(uiExportDir)->Base) * sizeof(DWORD);

        // patch in the address for this imported function
        DEREF(uiValueA) = uiLibraryAddress + DEREF_32(uiAddressArray);
      } else {
        // get the VA of this functions import by name struct
        uiValueB = uiBaseAddress + DEREF(uiValueA);

				// calculate length of function name to initialize the ANSI_STRING
				// required for the LdrGetProcedureAddress function.
				uiValueE = reinterpret_cast<ULONG_PTR>(reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(uiValueB)->Name);
				usCounter = 0;
				while (DEREF_8(uiValueE)) {
					usCounter++;
					uiValueE++;
				}
        
        // initialize ANSI_STRING structure for use with LdrGetProcedureAddress
        ansiA.Length = usCounter;
        ansiA.MaximumLength = usCounter + 1;
        ansiA.Buffer = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(uiValueB)->Name;

        // use LdrGetProcedureAddress and patch in the address for this imported function
        get_proc_addr(reinterpret_cast<PVOID>(uiLibraryAddress), &ansiA, 0ul, reinterpret_cast<PVOID*>(&uiValueE));
				DEREF(uiValueA) = uiValueE;
      }
      
      // get the next imported function
			uiValueA += sizeof(ULONG_PTR);

      if (uiValueD) {
        uiValueD += sizeof(ULONG_PTR);
      }
    }

    // get the next import
    uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
  }
#pragma endregion

#pragma region STEP 5: process all of our images relocations...
  // calculate the base address delta and perform relocations (even if we load at desired image base)
  uiLibraryAddress = uiBaseAddress - reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->OptionalHeader.ImageBase;

  // uiValueB = the address of the relocation directory
  uiValueB = reinterpret_cast<ULONG_PTR>(&reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

  // check if their are any relocations present
  if (reinterpret_cast<PIMAGE_DATA_DIRECTORY>(uiValueB)->Size) {
    // uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
    uiValueC = (uiBaseAddress + reinterpret_cast<PIMAGE_DATA_DIRECTORY>(uiValueB)->VirtualAddress);

    // and we itterate through all entries...
    while (reinterpret_cast<PIMAGE_BASE_RELOCATION>(uiValueC)->SizeOfBlock) {
      // uiValueA = the VA for this relocation block
      uiValueA = (uiBaseAddress + reinterpret_cast<PIMAGE_BASE_RELOCATION>(uiValueC)->VirtualAddress);

      // uiValueB = number of entries in this relocation block
      uiValueB = (reinterpret_cast<PIMAGE_BASE_RELOCATION>(uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

      // uiValueD is now the first entry in the current relocation block
      uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

      // we itterate through all the entries in the current block...
      while (uiValueB--) {
        // perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
        // we dont use a switch statement to avoid the compiler building a jump table
        // which would not be very position independent!
        if (reinterpret_cast<PIMAGE_RELOC>(uiValueD)->type == IMAGE_REL_BASED_DIR64) {
          *reinterpret_cast<ULONG_PTR*>(uiValueA + reinterpret_cast<PIMAGE_RELOC>(uiValueD)->offset) += uiLibraryAddress;
        } else if (reinterpret_cast<PIMAGE_RELOC>(uiValueD)->type == IMAGE_REL_BASED_HIGHLOW) {
          *reinterpret_cast<DWORD*>(uiValueA + reinterpret_cast<PIMAGE_RELOC>(uiValueD)->offset) += static_cast<DWORD>(uiLibraryAddress);
        } else if (reinterpret_cast<PIMAGE_RELOC>(uiValueD)->type == IMAGE_REL_BASED_HIGH) {
          *reinterpret_cast<WORD*>(uiValueA + reinterpret_cast<PIMAGE_RELOC>(uiValueD)->offset) += HIWORD(uiLibraryAddress);
        } else if (reinterpret_cast<PIMAGE_RELOC>(uiValueD)->type == IMAGE_REL_BASED_LOW) {
          *reinterpret_cast<WORD*>(uiValueA + reinterpret_cast<PIMAGE_RELOC>(uiValueD)->offset) += LOWORD(uiLibraryAddress);
        }

        // get the next entry in the current relocation block
        uiValueD += sizeof(IMAGE_RELOC);
      }

      // get the next entry in the relocation directory
      uiValueC = uiValueC + reinterpret_cast<PIMAGE_BASE_RELOCATION>(uiValueC)->SizeOfBlock;
    }
  }
#pragma endregion 

#pragma region STEP 6: call our images entry point
  // uiValueA = the VA of our newly loaded DLL/EXE's entry point
  uiValueA = uiBaseAddress + (reinterpret_cast<PIMAGE_NT_HEADERS>(uiHeaderValue)->OptionalHeader.AddressOfEntryPoint - kEntryPointMod);

	// store the newly allocated memory so the launcher can free it on self destruct
	loader_data->relocated = reinterpret_cast<LPVOID>(uiBaseAddress);

  // We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
  flush_inst_cache(NtCurrentProcess(), nullptr, 0);

  // call our respective entry point, fudging our hInstance value
  reinterpret_cast<FnDllMain>(uiValueA)(reinterpret_cast<HINSTANCE>(uiBaseAddress), DLL_PROCESS_ATTACH, loader_data);
#pragma endregion

#pragma region STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
#ifdef THREAD_HIDDEN_FROM_DEBUGGER
end:
#endif
  return STATUS_SUCCESS;
#pragma endregion
}

//===============================================================================================//
// Force compiler to include the unreferenced loader without having to export it
#ifdef _WIN64
__pragma(comment(linker, "/INCLUDE:__ReflectiveLoader_fp"));
#else
__pragma(comment(linker, "/INCLUDE:___ReflectiveLoader_fp"));
#endif
typedef void(*fnReflectiveLoader)();
extern "C" fnReflectiveLoader __ReflectiveLoader_fp = reinterpret_cast<fnReflectiveLoader>(&ReflectiveLoader);
//===============================================================================================//

#undef DEREF_8
#undef DEREF_16
#undef DEREF_32
#undef DEREF_64
#undef DEREF
}  // namespace reflective_loader

#ifdef THREAD_HIDDEN_FROM_DEBUGGER
#undef THREAD_HIDDEN_FROM_DEBUGGER
#endif