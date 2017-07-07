#pragma once
#include <jni.h>

char* utf8_next( const char* str, jchar* value);

void utf8_convert_to_unicode(const char* utf8_str,
                             jchar* unicode_str,
                             int unicode_length);

int utf8_unicode_length(const char* str);
