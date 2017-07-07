#include "segment_resource.h"
#include "global.h"

namespace {
constexpr const uint32_t kSegmentFileChunkMap[] = {};

template<class T, size_t N>
constexpr __forceinline auto array_size(const T (&S)[N]) {
  return N;
}

#define RtlOffsetToPointer(B, O) ((PCHAR)(((PCHAR)(B)) + ((ULONG_PTR)(O))))
#define MAKE_PTR(B, O, T) ((T)RtlOffsetToPointer(B, O))

PIMAGE_NT_HEADERS PeImageNtHeader(PVOID const image_base) {
  auto dos_header = static_cast<PIMAGE_DOS_HEADER>(image_base);
  auto nt_header = PIMAGE_NT_HEADERS{ nullptr };

  if (dos_header->e_magic == IMAGE_DOS_SIGNATURE) {
    nt_header = MAKE_PTR(image_base,
      dos_header->e_lfanew,
      PIMAGE_NT_HEADERS);
    if (nt_header->Signature == IMAGE_NT_SIGNATURE) {
      return nt_header;
    }
  }

  return nullptr;
}
}  // namespace

std::unique_ptr<uint8_t[]> ReconstructSegmentResource(HMODULE image_base) {
  const auto nt_header = PeImageNtHeader(image_base);

  // calculate total size
  auto total_size = size_t{0};
  for (auto iii = 0;
       iii < array_size(kSegmentFileChunkMap);
       iii++) {
    auto sections = nt_header->FileHeader.NumberOfSections;
    auto section = IMAGE_FIRST_SECTION(nt_header);

    do {
      const auto hash = cx::crc32(reinterpret_cast<char*>(section->Name));
      if (hash == kSegmentFileChunkMap[iii]) {
        total_size += *MAKE_PTR(image_base, section->VirtualAddress, uint32_t*);
      }
    } while (section++, sections--);
  }

  if (total_size == 0) {
    return nullptr;
  }

  // allocate buffer to store the data
  auto buffer = std::make_unique<uint8_t[]>(total_size);
  auto ptr = buffer.get();

  // reconstruct the resource
  for (auto iii = 0;
       iii < array_size(kSegmentFileChunkMap);
       iii++) {
    auto sections = nt_header->FileHeader.NumberOfSections;
    auto section = IMAGE_FIRST_SECTION(nt_header);

    do {
      const auto hash = cx::crc32(reinterpret_cast<char*>(section->Name));
      if (hash == kSegmentFileChunkMap[iii]) {
        auto data = MAKE_PTR(image_base, section->VirtualAddress, uint8_t*);
        const auto size = *reinterpret_cast<uint32_t*>(data);

        memcpy(ptr, data + sizeof(uint32_t), size);
        ptr += size;
      }
    } while (section++, sections--);
  }

  return buffer;
}

#undef MAKE_PTR
#undef RtlOffsetToPointer
