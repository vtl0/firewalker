#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

void **firewalker(unsigned int pointers_count) {
  void **found_modules;
  uintptr_t ptr;
  uintptr_t *walker;
#if !defined(_NO_WINAPI_TEST)
  MEMORY_BASIC_INFORMATION mbi;
#endif
  unsigned int count;

  found_modules = calloc(pointers_count + 1, sizeof(void*));
  if (found_modules == NULL)
    return NULL;

  count = 0;

#if UINTPTR_MAX == 0xFFFFFFFFFFFFFFFFull
  __asm__ volatile("mov %%rsp, %0" : "+r"(walker)::);
#else
  __asm__ volatile("mov %%esp, %0" : "+r"(walker)::);
#endif
  for (unsigned int i = 0; i < pointers_count; i++) {
    ptr = walker[-i];
    if (ptr > (1ULL << (sizeof(void *) * 4 - 1))) {
#if !defined(_NO_WINAPI_TEST)
      if (!VirtualQuery((LPCVOID)ptr, &mbi, sizeof(mbi)))
        continue;
      if (!(mbi.Protect & PAGE_EXECUTE_READ))
        continue;
#elif UINTPTR_MAX == 0xFFFFFFFFFFFFFFFFull
#warning "NOT USING WINAPI IS HIGHLY UNREALIABLE"
      if ((ptr >> 40) != 0x7F || (((ptr >> 16) & 0xFF) == 0 || ((ptr >> 24) & 0xFF) == 0
        || ((ptr >> 32) & 0xFF) == 0)) {
        continue;
      }
#else
#error "I found no good way of reliably detecting code pointer without the WinAPI in 32 bits"
#endif
      // totals 4 MiB of reading, considering .text generally comes before
      // .data, this will suffice for most DLLs (1024 * 4096 == 4 MiB)
      for (int j = 0; j < 1024; j++) {
        PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)(ptr & ~4095);
        
        // actually test before going to previous page
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
          ptr = ((ptr - 1) & ~4095);
          dos_header = (PIMAGE_DOS_HEADER)ptr;
        }
        // detect DOS file header
        if (dos_header->e_magic == IMAGE_DOS_SIGNATURE) {
          bool present = 0;
          for (int k = 0; k < count; k++) {
            if (found_modules[k] == (void *)dos_header) {
              present = 1;
              break;
            }
          }

          if (present)
            break;

          found_modules[count++] = (void*)dos_header;
        }        
      }
    }
  }

  if (count)
    return found_modules;

  free(found_modules);
  return NULL;
}

int main(int argc, char **argv) {
  void **modules;

  if (argc < 2)
    modules = firewalker(64);
  else
    modules = firewalker(atoi(argv[1]));
    
  if (modules == NULL) {
    printf("Found no modules through stack walking\n");
    return 1;
  }

  for (int i = 0; modules[i]; i++) {
    printf("Found module at %p\n", modules[i]);
  }

  free(modules);
  return 0;
}
