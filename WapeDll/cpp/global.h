#pragma once

#if !defined UNICODE
#error ANSI build is not supported
#endif

#include "winheaders.h"
#include "api_cache.h"
#include "cx_strenc.h"

class ApiCache;
extern ApiCache* g_api_cache;