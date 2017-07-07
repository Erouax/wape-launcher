#include "minecraft.h"

constexpr const auto kLwjgl = cx::crc32("LWJGL");

bool GetMinecraftProccessDetails(std::vector<ProcessDetails>* details) {
  std::unordered_set<DWORD> pids;

  if (FindProcessesByWindowClass(kLwjgl, &pids)) {
    for (const auto pid : pids) {
      auto process_details = GetProcessDetails(pid);

      if (process_details) {
        if (process_details->command_line.find(
          wstrenc(L"MojangTricksIntelDriversForPerformance"))
          != std::string::npos) {
          details->push_back(*process_details);
        }
      }
    }

    return details->size() > 0;
  }

  return false;
}
