/**
 * @file veh_tracer.hpp
 * @brief Non-intrusive hardware breakpoint (DR0-DR7) and VEH tracing wrapper for Windows x64.
 */

#pragma once

#include <cstdint>
#include <functional>

#if defined(_WIN32)
#include <windows.h>
#include <tlhelp32.h>
#endif

namespace veh_tracer {

enum class TriggerCondition : uint8_t {
    Execute   = 0b00,
    WriteOnly = 0b01,
    IOAccess  = 0b10,
    ReadWrite = 0b11
};

enum class WatchLength : uint8_t {
    Byte1 = 0b00,
    Byte2 = 0b01,
    Byte8 = 0b10,
    Byte4 = 0b11
};

struct TraceRecord {
    uint32_t  slot_index;
    uint32_t  thread_id;
    uintptr_t rip;
    uintptr_t rsp;
    uintptr_t rax;
    uintptr_t rcx;
    uintptr_t rdx;
};

using TraceCallback = std::function<void(const TraceRecord&)>;

class HardwareTracer {
public:
    HardwareTracer() = default;
    ~HardwareTracer() { shutdown(); }

    bool initialize(TraceCallback cb) {
        callback_ = std::move(cb);
#if defined(_WIN32)
        instance_ = this;
        veh_handle_ = AddVectoredExceptionHandler(1, &HardwareTracer::veh_filter);
        return veh_handle_ != nullptr;
#else
        return false;
#endif
    }

    void shutdown() {
#if defined(_WIN32)
        if (veh_handle_) {
            RemoveVectoredExceptionHandler(veh_handle_);
            veh_handle_ = nullptr;
        }
#endif
    }

    bool set_breakpoint(
        uint8_t slot,
        uintptr_t address,
        TriggerCondition cond,
        WatchLength len)
    {
        if (slot > 3) {
            return false;
        }
#if defined(_WIN32)
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        HANDLE hThread = GetCurrentThread();
        if (!GetThreadContext(hThread, &ctx)) {
            return false;
        }

        switch (slot) {
        case 0: ctx.Dr0 = address; break;
        case 1: ctx.Dr1 = address; break;
        case 2: ctx.Dr2 = address; break;
        case 3: ctx.Dr3 = address; break;
        }

        /* Enable Local Exact Breakpoint bit (L0-L3) in DR7 */
        ctx.Dr7 |= (1ULL << (slot * 2));

        /* Configure 2-bit R/W condition and 2-bit LEN field at bits 16..31 of DR7 */
        const uint64_t shift = 16ULL + (slot * 4ULL);
        const uint64_t config_bits =
            (static_cast<uint64_t>(len) << 2) | static_cast<uint64_t>(cond);
        ctx.Dr7 &= ~(0xFULL << shift);
        ctx.Dr7 |= (config_bits << shift);

        return SetThreadContext(hThread, &ctx) != FALSE;
#else
        (void)address;
        (void)cond;
        (void)len;
        return false;
#endif
    }

private:
#if defined(_WIN32)
    static LONG CALLBACK veh_filter(PEXCEPTION_POINTERS ep) {
        if (!ep || !ep->ExceptionRecord || !ep->ContextRecord) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        PCONTEXT ctx = ep->ContextRecord;
        uint64_t status = ctx->Dr6 & 0xFULL;
        if (status == 0) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        uint32_t hit_slot = 0;
        for (uint32_t i = 0; i < 4; ++i) {
            if (status & (1ULL << i)) {
                hit_slot = i;
                break;
            }
        }

        if (instance_ && instance_->callback_) {
            TraceRecord rec{};
            rec.slot_index = hit_slot;
            rec.thread_id  = GetCurrentThreadId();
            rec.rip        = ctx->Rip;
            rec.rsp        = ctx->Rsp;
            rec.rax        = ctx->Rax;
            rec.rcx        = ctx->Rcx;
            rec.rdx        = ctx->Rdx;
            instance_->callback_(rec);
        }

        /* Clear DR6 trap bits and set Resume Flag (EFLAGS.RF, bit 16) to step past hit */
        ctx->Dr6 &= ~0xFULL;
        ctx->EFlags |= (1U << 16);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    void* veh_handle_ = nullptr;
    static inline HardwareTracer* instance_ = nullptr;
#endif
    TraceCallback callback_;
};

} // namespace veh_tracer

