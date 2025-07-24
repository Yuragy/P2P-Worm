#ifndef PTT_H
#define PTT_H

#ifdef _WIN32
  #ifdef PTT_EXPORTS
    #define PTT_API __declspec(dllexport)
  #else
    #define PTT_API __declspec(dllimport)
  #endif
#else
  #define PTT_API __attribute__((visibility("default")))
#endif

#include <stddef.h>

PTT_API int ptt_init(void);
PTT_API int ptt_export(const char *ccache_path,
                       unsigned char *out_buf,
                       size_t out_capacity,
                       size_t *out_len);
PTT_API void ptt_cleanup(void);

#endif // PTT_H
