/*
 * Copyright (C) 2017 Apple Inc. All rights reserved.
 * Copyright (C) 2017 Yusuke Suzuki <utatane.tea@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include <wtf/StackTrace.h>

#include <wtf/Assertions.h>
#include <wtf/PrintStream.h>

#if USE(LIBBACKTRACE)
#include <string.h>
#include <wtf/NeverDestroyed.h>
#endif

#if HAVE(BACKTRACE_SYMBOLS) || HAVE(BACKTRACE)
#include <execinfo.h>
#endif

#if HAVE(DLADDR)
#include <cxxabi.h>
#include <dlfcn.h>
#endif

#if OS(WINDOWS)
#include <windows.h>
#include <wtf/win/DbgHelperWin.h>
#endif

void WTFGetBacktrace(void** stack, int* size)
{
#if HAVE(BACKTRACE)
    *size = backtrace(stack, *size);
#elif OS(WINDOWS)
    *size = RtlCaptureStackBackTrace(0, *size, stack, nullptr);
#else
    UNUSED_PARAM(stack);
    *size = 0;
#endif
}

namespace WTF {

#if USE(LIBBACKTRACE)
static struct backtrace_state* backtraceState()
{
    static NeverDestroyed<struct backtrace_state*> backtraceState = backtrace_create_state(nullptr, 1, nullptr, nullptr);
    return backtraceState;
}

static void backtraceSyminfoCallback(void* data, uintptr_t, const char* symname, uintptr_t, uintptr_t)
{
    const char** symbol = static_cast<const char**>(data);
    *symbol = symname;
}

static int backtraceFullCallback(void* data, uintptr_t, const char*, int, const char* function)
{
    const char** symbol = static_cast<const char**>(data);
    *symbol = function;
    return 0;
}

char** symbolize(void* const* addresses, int size)
{
    struct backtrace_state* state = backtraceState();
    if (!state)
        return nullptr;

    char** symbols = static_cast<char**>(malloc(sizeof(char*) * size));

    for (int i = 0; i < size; ++i) {
        uintptr_t pc = reinterpret_cast<uintptr_t>(addresses[i]);
        char* symbol;

        backtrace_pcinfo(state, pc, backtraceFullCallback, nullptr, &symbol);
        if (!symbol)
            backtrace_syminfo(backtraceState(), pc, backtraceSyminfoCallback, nullptr, &symbol);

        if (symbol) {
            char* demangled = abi::__cxa_demangle(symbol, nullptr, nullptr, nullptr);
            if (demangled)
                symbols[i] = demangled;
            else
                symbols[i] = strdup(symbol);
        } else
            symbols[i] = strdup("???");
    }
    return symbols;
}
#endif

ALWAYS_INLINE size_t StackTrace::instanceSize(int capacity)
{
    ASSERT(capacity >= 1);
    return sizeof(StackTrace) + (capacity - 1) * sizeof(void*);
}

std::unique_ptr<StackTrace> StackTrace::captureStackTrace(int maxFrames, int framesToSkip)
{
    maxFrames = std::max(1, maxFrames);
    size_t sizeToAllocate = instanceSize(maxFrames);
    std::unique_ptr<StackTrace> trace(new (NotNull, fastMalloc(sizeToAllocate)) StackTrace());

    // Skip 2 additional frames i.e. StackTrace::captureStackTrace and WTFGetBacktrace.
    framesToSkip += 2;
    int numberOfFrames = maxFrames + framesToSkip;

    WTFGetBacktrace(&trace->m_skippedFrame0, &numberOfFrames);
    if (numberOfFrames) {
        RELEASE_ASSERT(numberOfFrames >= framesToSkip);
        trace->m_size = numberOfFrames - framesToSkip;
    } else
        trace->m_size = 0;

    trace->m_capacity = maxFrames;

    return trace;
}

auto StackTrace::demangle(void* pc) -> std::optional<DemangleEntry>
{
#if HAVE(DLADDR)
    const char* mangledName = nullptr;
    const char* cxaDemangled = nullptr;
    Dl_info info;
    if (dladdr(pc, &info) && info.dli_sname)
        mangledName = info.dli_sname;
    if (mangledName) {
        int status = 0;
        cxaDemangled = abi::__cxa_demangle(mangledName, nullptr, nullptr, &status);
        UNUSED_PARAM(status);
    }
    if (mangledName || cxaDemangled)
        return DemangleEntry { mangledName, cxaDemangled };
#else
    UNUSED_PARAM(pc);
#endif
    return std::nullopt;
}

void StackTrace::dump(PrintStream& out, const char* indentString) const
{
    const auto* stack = this->stack();
#if USE(LIBBACKTRACE)
    char** symbols = symbolize(stack, m_size);
    if (!symbols)
        return;
#elif HAVE(BACKTRACE_SYMBOLS)
    char** symbols = backtrace_symbols(stack, m_size);
    if (!symbols)
        return;
#elif OS(WINDOWS)
    HANDLE hProc = GetCurrentProcess();
    uint8_t symbolData[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)] = { 0 };
    auto symbolInfo = reinterpret_cast<SYMBOL_INFO*>(symbolData);

    symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbolInfo->MaxNameLen = MAX_SYM_NAME;
#endif

    if (!indentString)
        indentString = "";
    for (int i = 0; i < m_size; ++i) {
        const char* mangledName = nullptr;
        const char* cxaDemangled = nullptr;
#if HAVE(BACKTRACE_SYMBOLS)
        mangledName = symbols[i];
#elif OS(WINDOWS)
        if (DbgHelper::SymFromAddress(hProc, reinterpret_cast<DWORD64>(stack[i]), nullptr, symbolInfo))
            mangledName = symbolInfo->Name;
#endif
        auto demangled = demangle(stack[i]);
        if (demangled) {
            mangledName = demangled->mangledName();
            cxaDemangled = demangled->demangledName();
        }
        const int frameNumber = i + 1;
        if (mangledName || cxaDemangled)
            out.printf("%s%s%-3d %p %s\n", m_prefix ? m_prefix : "", indentString, frameNumber, stack[i], cxaDemangled ? cxaDemangled : mangledName);
        else
            out.printf("%s%s%-3d %p\n", m_prefix ? m_prefix : "", indentString, frameNumber, stack[i]);
    }

#if USE(LIBBACKTRACE)
    for (int i = 0; i < m_size; ++i)
        free(symbols[i]);
    free(symbols);
#elif HAVE(BACKTRACE_SYMBOLS)
    free(symbols);
#endif
}

} // namespace WTF
