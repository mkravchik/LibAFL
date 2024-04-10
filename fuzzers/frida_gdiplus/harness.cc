#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <vector>
#include <iostream>

#include <windows.h>
#include <gdiplus.h>

using namespace std;
using namespace Gdiplus;

GdiplusStartupInput gdiplusStartupInput;
ULONG_PTR           gdiplusToken;

// Some DLLs are lazily loaded during image loading
// FridaInstrumentationHelper doesn't instrument DLLs that are loaded after
// init, so they're manually loaded here
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
      LoadLibraryA("ole32.dll");
      LoadLibraryA("gdi32full.dll");
      LoadLibraryA("WindowsCodecs.dll");
      LoadLibraryA("shcore.dll");
      GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
      LoadLibraryA("gdi32.dll");
      // DebugBreak();
      break;
  }
  return TRUE;
}

extern "C" __declspec(dllexport) int LLVMFuzzerTestOneInput(const uint8_t *data,
                                                            size_t size) {
  static DWORD init = 0;
  // if (!init) {
  // init = 1;
  // }

  // TEMP hack to test the hooking
  // if there data is longer than 100 
  // if the 99th byte is between 128 and 156, load setupcl.dll
  if (size > 100){
    if (data[99] > 128 && data[99] < 156){
      LoadLibraryA("setupcl.dll");
    }
    else if (data[99] > 156 && data[99] < 176){
      LoadLibraryW(L"shacct.dll");
    }
  }
  HGLOBAL m_hBuffer = ::GlobalAlloc(GMEM_MOVEABLE, size);
  if (m_hBuffer) {
    void *pBuffer = ::GlobalLock(m_hBuffer);
    if (pBuffer) {
      memcpy(pBuffer, data, size);
      // CopyMemory(pBuffer, data, size);

      IStream *pStream = NULL;
      if (::CreateStreamOnHGlobal(m_hBuffer, FALSE, &pStream) == S_OK) {
        Gdiplus::Bitmap *m_pBitmap = Gdiplus::Bitmap::FromStream(pStream);
        pStream->Release();
        if (m_pBitmap) {
          delete m_pBitmap;
          m_pBitmap = NULL;
        }
      }
      ::GlobalUnlock(m_hBuffer);
    }
    ::GlobalFree(m_hBuffer);
    m_hBuffer = NULL;
  }

  // GdiplusShutdown(gdiplusToken);
  return 0;
}
