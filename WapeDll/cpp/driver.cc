#include "driver.h"

bool GetLoadedDrivers(std::vector<std::wstring>* drivers) {
  if (!drivers) {
    return false;
  }

  auto required = DWORD{};
  if (!g_api_cache->K32(BOOL, K32EnumDeviceDrivers, nullptr, 0, &required) ||
    !required) {
    return false;
  }

  auto buffer = std::make_unique<LPVOID[]>(required);
  if (!buffer) {
    return false;
  }

  if (!g_api_cache->K32(BOOL, K32EnumDeviceDrivers,
    buffer.get(),
    (required * sizeof(LPVOID)),
    &required)) {
    return false;
  }

  wchar_t name[1024];
  for (auto iii = 0u; iii < required / sizeof(LPVOID); iii++) {
    RtlZeroMemory(name, sizeof(name));

    if (g_api_cache->K32(DWORD, K32GetDeviceDriverBaseNameW,
      buffer[iii],
      name,
      (sizeof(name) / sizeof(wchar_t)) - 1)) {
      drivers->push_back(std::wstring(name));
    }
  }

  return drivers->size() > 0;
}
