#include "utf8.h"

char* utf8_next(const char* str, jchar* value) {
  unsigned const char *ptr = (const unsigned char *)str;
  unsigned char ch, ch2, ch3;
  int length = -1;              /* bad length */
  jchar result;
  switch ((ch = ptr[0]) >> 4) {
    default:
      result = ch;
      length = 1;
      break;

    case 0x8: case 0x9: case 0xA: case 0xB: case 0xF:
      /* Shouldn't happen. */
      break;

    case 0xC: case 0xD:
      /* 110xxxxx  10xxxxxx */
      if (((ch2 = ptr[1]) & 0xC0) == 0x80) {
        unsigned char high_five = ch & 0x1F;
        unsigned char low_six = ch2 & 0x3F;
        result = (high_five << 6) + low_six;
        length = 2;
        break;
      }
      break;

    case 0xE:
      /* 1110xxxx 10xxxxxx 10xxxxxx */
      if (((ch2 = ptr[1]) & 0xC0) == 0x80) {
        if (((ch3 = ptr[2]) & 0xC0) == 0x80) {
          unsigned char high_four = ch & 0x0f;
          unsigned char mid_six = ch2 & 0x3f;
          unsigned char low_six = ch3 & 0x3f;
          result = (((high_four << 6) + mid_six) << 6) + low_six;
          length = 3;
        }
      }
      break;
  } /* end of switch */

  if (length <= 0) {
    *value = ptr[0];    /* default bad result; */
    return (char*)(ptr + 1); // make progress somehow
  }

  *value = result;

  // The assert is correct but the .class file is wrong
  // assert(UNICODE::utf8_size(result) == length, "checking reverse computation");
  return (char *)(ptr + length);
}

void utf8_convert_to_unicode(const char* utf8_str,
                             jchar* unicode_str,
                             int unicode_length) {
  unsigned char ch;
  const char *ptr = (const char *)utf8_str;
  int index = 0;

  /* ASCII case loop optimization */
  for (; index < unicode_length; index++) {
    if ((ch = ptr[0]) > 0x7F) { break; }
    unicode_str[index] = ch;
    ptr = (const char *)(ptr + 1);
  }

  for (; index < unicode_length; index++) {
    ptr = utf8_next(ptr, &unicode_str[index]);
  }
}

int utf8_unicode_length(const char* str) {
  int num_chars = 0;
  for (const char* p = str; *p; p++) {
    if (((*p) & 0xC0) != 0x80) {
      num_chars++;
    }
  }
  return num_chars;
}
