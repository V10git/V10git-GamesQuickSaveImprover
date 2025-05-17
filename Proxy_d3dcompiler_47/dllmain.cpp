#include <Windows.h>

#define DLLPATH "org_d3dcompiler_47.dll"

#pragma comment(linker, "/EXPORT:D3DAssemble=" DLLPATH ".D3DAssemble")
#pragma comment(linker, "/EXPORT:D3DCompile=" DLLPATH ".D3DCompile")
#pragma comment(linker, "/EXPORT:D3DCompile2=" DLLPATH ".D3DCompile2")
#pragma comment(linker, "/EXPORT:D3DCompileFromFile=" DLLPATH ".D3DCompileFromFile")
#pragma comment(linker, "/EXPORT:D3DCompressShaders=" DLLPATH ".D3DCompressShaders")
#pragma comment(linker, "/EXPORT:D3DCreateBlob=" DLLPATH ".D3DCreateBlob")
#pragma comment(linker, "/EXPORT:D3DCreateFunctionLinkingGraph=" DLLPATH ".D3DCreateFunctionLinkingGraph")
#pragma comment(linker, "/EXPORT:D3DCreateLinker=" DLLPATH ".D3DCreateLinker")
#pragma comment(linker, "/EXPORT:D3DDecompressShaders=" DLLPATH ".D3DDecompressShaders")
#pragma comment(linker, "/EXPORT:D3DDisassemble=" DLLPATH ".D3DDisassemble")
#pragma comment(linker, "/EXPORT:D3DDisassemble10Effect=" DLLPATH ".D3DDisassemble10Effect")
#pragma comment(linker, "/EXPORT:D3DDisassemble11Trace=" DLLPATH ".D3DDisassemble11Trace")
#pragma comment(linker, "/EXPORT:D3DDisassembleRegion=" DLLPATH ".D3DDisassembleRegion")
#pragma comment(linker, "/EXPORT:D3DGetBlobPart=" DLLPATH ".D3DGetBlobPart")
#pragma comment(linker, "/EXPORT:D3DGetDebugInfo=" DLLPATH ".D3DGetDebugInfo")
#pragma comment(linker, "/EXPORT:D3DGetInputAndOutputSignatureBlob=" DLLPATH ".D3DGetInputAndOutputSignatureBlob")
#pragma comment(linker, "/EXPORT:D3DGetInputSignatureBlob=" DLLPATH ".D3DGetInputSignatureBlob")
#pragma comment(linker, "/EXPORT:D3DGetOutputSignatureBlob=" DLLPATH ".D3DGetOutputSignatureBlob")
#pragma comment(linker, "/EXPORT:D3DGetTraceInstructionOffsets=" DLLPATH ".D3DGetTraceInstructionOffsets")
#pragma comment(linker, "/EXPORT:D3DLoadModule=" DLLPATH ".D3DLoadModule")
#pragma comment(linker, "/EXPORT:D3DPreprocess=" DLLPATH ".D3DPreprocess")
#pragma comment(linker, "/EXPORT:D3DReadFileToBlob=" DLLPATH ".D3DReadFileToBlob")
#pragma comment(linker, "/EXPORT:D3DReflect=" DLLPATH ".D3DReflect")
#pragma comment(linker, "/EXPORT:D3DReflectLibrary=" DLLPATH ".D3DReflectLibrary")
#pragma comment(linker, "/EXPORT:D3DReturnFailure1=" DLLPATH ".D3DReturnFailure1")
#pragma comment(linker, "/EXPORT:D3DSetBlobPart=" DLLPATH ".D3DSetBlobPart")
#pragma comment(linker, "/EXPORT:D3DStripShader=" DLLPATH ".D3DStripShader")
#pragma comment(linker, "/EXPORT:D3DWriteBlobToFile=" DLLPATH ".D3DWriteBlobToFile")
#pragma comment(linker, "/EXPORT:DebugSetMute=" DLLPATH ".DebugSetMute")

BOOL WINAPI _DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        LoadLibrary("GamesQuickSaveImprover.dll");
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
