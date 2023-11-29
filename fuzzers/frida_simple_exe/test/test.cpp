/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <inttypes.h>

// shared memory stuff
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
  #include <windows.h>
#else
  #include <sys/mman.h>
#endif

#define MAX_SAMPLE_SIZE 1000000
#define SHM_SIZE (4 + MAX_SAMPLE_SIZE)
unsigned char *shm_data;

bool use_shared_memory;

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)

int setup_shmem(const char *name) {
  HANDLE map_file;

  map_file = OpenFileMapping(FILE_MAP_ALL_ACCESS,  // read/write access
                             FALSE,                // do not inherit the name
                             name);                // name of mapping object

  if (map_file == NULL) {
    printf("Error accessing shared memory\n");
    return 0;
  }

  shm_data = (unsigned char *)MapViewOfFile(
      map_file,             // handle to map object
      FILE_MAP_ALL_ACCESS,  // read/write permission
      0, 0, SHM_SIZE);

  if (shm_data == NULL) {
    printf("Error accessing shared memory\n");
    return 0;
  }

  return 1;
}

#else

int setup_shmem(const char *name) {
  int fd;

  // get shared memory file descriptor (NOT a file)
  fd = shm_open(name, O_RDONLY, S_IRUSR | S_IWUSR);
  if (fd == -1) {
    printf("Error in shm_open\n");
    return 0;
  }

  // map shared memory to process address space
  shm_data =
      (unsigned char *)mmap(NULL, SHM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
  if (shm_data == MAP_FAILED) {
    printf("Error in mmap\n");
    return 0;
  }

  return 1;
}

#endif

// used to force a crash
char *crash = NULL;

// ensure we can find the target

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
  #define FUZZ_TARGET_MODIFIERS __declspec(dllexport)
#else
  #define FUZZ_TARGET_MODIFIERS __attribute__((noinline))
#endif

// actual target function
// I'm cheating all the way :-
extern "C" void FUZZ_TARGET_MODIFIERS fuzz_internal(
  char    *sample_bytes, uint32_t sample_size)
{
  // printf("EXE>> fuzz_internal %p sample_bytes %p (%s), sample_size %d\n", 
    // fuzz_internal, sample_bytes, sample_bytes, sample_size);
  if (sample_size >= 4) {
    // check if the sample spells "test", but do it char-by-char to guide the fuzzer
    if (sample_bytes[0] == 't') {
      if (sample_bytes[1] == 'e') {
        // make it a bit harder for the fuzzer
        if (*(uint32_t *)(sample_bytes) == 0x74736575) { //This will never happen
        // if (*(uint32_t *)(sample_bytes) == 0x74736574) {
          printf("Found test. Going to crash.\n");
          // if so, crash
          crash[0] = 1;
        }
      }
      // if (sample_bytes[1] == 'e') {
      //   if (sample_bytes[2] == 's') {
      //     if (sample_bytes[3] == 't') {
      //       printf("Found test. Going to crash.\n");
      //       // if so, crash
      //       crash[0] = 1;
      //     }
      //   }
      // }
    }
  }
}


extern "C" void FUZZ_TARGET_MODIFIERS fuzz(char *name) {
  char    *sample_bytes = NULL;
  uint32_t sample_size = 0;

  printf("EXE>> fuzz %p name %s\n", fuzz, name);
  // read the sample either from file or
  // shared memory
  if (use_shared_memory) {
    sample_size = *(uint32_t *)(shm_data);
    if (sample_size > MAX_SAMPLE_SIZE) sample_size = MAX_SAMPLE_SIZE;
    sample_bytes = (char *)malloc(sample_size);
    memcpy(sample_bytes, shm_data + sizeof(uint32_t), sample_size);
  } else {
    FILE *fp = fopen(name, "rb");
    if (!fp) {
      printf("Error opening %s a\n", name);
      return;
    }
    fseek(fp, 0, SEEK_END);
    sample_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    sample_bytes = (char *)malloc(sample_size);
    fread(sample_bytes, 1, sample_size, fp);
    fclose(fp);
  }
  
  printf("EXE>> calling fuzz_internal sample_bytes %p sample_size %d\n", sample_bytes, sample_size);
  fuzz_internal(sample_bytes, sample_size);

  if (sample_bytes) free(sample_bytes);
}


// // Testing Ctrl+C handling
// BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) { 
//     switch (fdwCtrlType) { 
//     case CTRL_C_EVENT: 
//         printf("Ctrl-C event\n\n");
//         return TRUE; 
//     default: 
//         return FALSE; 
//     } 
// }

extern "C" int FUZZ_TARGET_MODIFIERS main(int argc, char **argv) {

  // // register Ctrl+C handler
  // SetConsoleCtrlHandler(CtrlHandler, TRUE);

  printf("Sleeping for 30 seconds to allow for debugger to attach\n");
  Sleep(30 * 1000);

  // if (argc != 3) {
  //   printf("Usage: %s <-f|-m> <file or shared memory name>\n", argv[0]);
  //   return 0;
  // }

  printf("EXE>> main %p argc %d, argv[1] %s, argv[2] %s\n", main, argc, argv[1], argv[2]);
  char* type = "-f";
  char* name = "test\\ok_input.txt";
  // if (argc > 1) 
  //   type = argv[1];
  // if (argc > 2)
  //   name = argv[2];

  if (!strcmp(type, "-m")) {
    use_shared_memory = true;
  } else if (!strcmp(type, "-f")) {
    use_shared_memory = false;
  } else {
    printf("Usage: %s <-f|-m> <file or shared memory name>\n", argv[0]);
    return 0;
  }

  // map shared memory here as we don't want to do it
  // for every operation
  if (use_shared_memory) {
    if (!setup_shmem(name)) { printf("Error mapping shared memory\n"); }
  }

  // LoadLibraryA("frida_simple_exe.dll");
  fuzz(name);

  printf("Bye\n");
  return 0;
}
