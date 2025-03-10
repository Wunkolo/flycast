/*
	Copyright (c) 2018, Magnus Norddahl
	Copyright 2021 flyinghead

	This file is part of Flycast.

    Flycast is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Flycast is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Flycast.  If not, see <https://www.gnu.org/licenses/>.
*/
// Based on Asmjit unwind info registration and stack walking code for Windows, Linux and macOS
// https://gist.github.com/dpjudas/925d5c4ffef90bd8114be3b465069fff
#include "oslib/unwind_info.h"
#if defined(_M_X64) || defined(_M_ARM64)
#include <windows.h>
#include <dbghelp.h>
#include <algorithm>

#if defined(_M_X64)
#define UWOP_PUSH_NONVOL 0
#define UWOP_ALLOC_LARGE 1
#define UWOP_ALLOC_SMALL 2
#define UWOP_SET_FPREG 3
#define UWOP_SAVE_NONVOL 4
#define UWOP_SAVE_NONVOL_FAR 5
#define UWOP_SAVE_XMM128 8
#define UWOP_SAVE_XMM128_FAR 9
#define UWOP_PUSH_MACHFRAME 10
#elif defined(_M_ARM64)
// ARM64 unwind-op codes
// https://docs.microsoft.com/en-us/cpp/build/arm64-exception-handling#unwind-codes
// https://www.corsix.org/content/windows-arm64-unwind-codes
typedef enum UNWIND_CODE_OPS {
	UWOP_NOP = 0xE3,
	UWOP_ALLOC_S = 0x00,           // sub sp, sp, i*16 (512-btes)
	UWOP_ALLOC_L = 0xE0'00'00'00,  // sub sp, sp, i*16 (256MiB)
	UWOP_SAVE_FPLR = 0x40,         // stp fp, lr, [sp+i*8]
	UWOP_SAVE_FPLRX = 0x80,        // stp fp, lr, [sp-(i+1)*8]!
	UWOP_SET_FP = 0xE1,            // mov fp, sp
	UWOP_END = 0xE4,
} UNWIND_CODE_OPS;

using UNWIND_CODE = uint32_t;

// 8-byte unwind code for up to +512-byte "sub sp, sp, #stack_space"
// https://docs.microsoft.com/en-us/cpp/build/arm64-exception-handling#unwind-codes
uint8_t OpAllocS(int stack_space) {
	// See unwind code alloc_s in
	// https://docs.microsoft.com/en-us/cpp/build/arm64-exception-handling#unwind-codes
	verify(stack_space >= 0);
	verify(stack_space < 512);
	verify(stack_space & 0b111 == 0);
	return UWOP_ALLOC_S | (stack_space / 16);
}

#endif

void UnwindInfo::start(void *address)
{
	startAddr = (u8 *)address;
	// Start off with 32-bits of data to later hold the
	// UNWIND_INFO
	codes.resize(4, 0);
}

#if defined(_M_X64)
void UnwindInfo::pushReg(u32 offset, int reg)
{
	codes.push_back(offset | (UWOP_PUSH_NONVOL << 8) | (reg << 12));
}
#elif defined(_M_ARM64)
// Registers are DWARF register-ids:
// x0-x30		0 - 30
// SP			31
// d0-d31		64 - 95

void UnwindInfo::saveReg(u32 offset, int reg, int stackOffset)
{
	// GP registers only
	verify(reg <= 31);

	// https://www.corsix.org/content/windows-arm64-unwind-codes#arm64_save_any_reg
	// save_any_reg
	// 11100111 000nnnnn 00iiiiii
	// str x(0+n), [sp+i*8]
	codes.push_back(0b11100111);
	codes.push_back(reg);
	codes.push_back(stackOffset / 8);
}
void UnwindInfo::saveExtReg(u32 offset, int reg, int stackOffset)
{
	// FP registers only
	verify(reg >= 64);
	verify(reg >= 95);

	reg -= 64;

	// https://www.corsix.org/content/windows-arm64-unwind-codes#arm64_save_any_reg
	// save_any_reg
	// 11100111 000nnnnn 01iiiiii	
	// str d(0+n), [sp+i*8]
	codes.push_back(0b11100111);
	codes.push_back(reg);
	codes.push_back((stackOffset / 8) | 01000000);
}
#endif

void UnwindInfo::allocStack(u32 offset, int size)
{
#if defined(_M_X64)
	verify(size <= 128);
	verify((size & 7) == 0);
	codes.push_back(offset | (UWOP_ALLOC_SMALL << 8) | ((size / 8 - 1) << 12));
#elif defined(_M_ARM64)
	verify(offset == 0); 
	codes.push_back(OpAllocS(size));
#endif
}

void UnwindInfo::endProlog(u32 offset)
{
#if defined(_M_X64)
	codes.push_back(0);
	codes.push_back(0);
	std::reverse(codes.begin(), codes.end());
	codes[0] = 1 | (offset  << 8);		// version (1), flags (0) and prolog size (offset)
	codes[1] = (u8)codes.size() - 2;	// unwind codes count
	if (codes.size() & 1)				// table size must be even
		codes.push_back(0);
#elif defined(_M_ARM64)
#endif
}

size_t UnwindInfo::end(u32 offset, ptrdiff_t rwRxOffset)
{
	const u8 *endAddr = startAddr + offset;

#if defined(_M_ARM64)
	{
		codes.push_back(UWOP_END);

		// Ensure codes is a multiple of four bytes
		u8 padding = codes.size() % sizeof(u32);
		while(padding--)
		{
			codes.push_back(UWOP_NOP);
		}


		// Finalize xdata
		IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA& unwind_info_a64 = *(IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA*)codes.data();
		unwind_info_a64 = {};
		unwind_info_a64.FunctionLength = offset;
		verify(codes.size() % sizeof(u32) == 0);
		unwind_info_a64.CodeWords = codes.size() / sizeof(u32);
	}
#endif

	// Align to 4 byte boundary
	if ((uintptr_t)endAddr & 3)
		offset += 4 - ((uintptr_t)endAddr & 3);
	u8 *unwindInfo = startAddr + offset;
	// Copy opcodes
	std::memcpy(unwindInfo, codes.data(), codes.size() * sizeof(OpCode));

	// Function info written after opcodes
	RUNTIME_FUNCTION& table = *(RUNTIME_FUNCTION *)(unwindInfo + codes.size() * sizeof(OpCode));
	table.BeginAddress = 0;

#if defined(_M_X64)
	table.EndAddress = (DWORD)(endAddr - startAddr);
#ifndef __MINGW64__
	table.UnwindInfoAddress = (DWORD)(unwindInfo - startAddr);
#else
	table.UnwindData = (DWORD)(unwindInfo - startAddr);
#endif
	bool result = RtlAddFunctionTable(&table, 1, (DWORD64)startAddr);
	tables.push_back(table);
	DEBUG_LOG(DYNAREC, "RtlAddFunctionTable %p sz %d rc %d tables: %d", startAddr, table[0].EndAddress, result, (u32)tables.size());
#elif defined(_M_ARM64)
	// ARM64 instructions are always multiples of 4 bytes
	// Windows ignores the bottom 2 bits
	table.FunctionLength = (DWORD)(endAddr - startAddr) / 4;
	table.UnwindData = (DWORD)(unwindInfo - startAddr);

	bool result = RtlAddFunctionTable(&table, 1, (DWORD64)startAddr);
	tables.push_back(&table);
	DEBUG_LOG(DYNAREC, "RtlAddFunctionTable %p sz %d rc %d tables: %d", startAddr, table.FunctionLength * 4, result, (u32)tables.size());
#endif

	return (unwindInfo + codes.size() * sizeof(OpCode) + sizeof(RUNTIME_FUNCTION)) - endAddr;
}

void UnwindInfo::clear()
{
	DEBUG_LOG(DYNAREC, "UnwindInfo::clear");
	for (RUNTIME_FUNCTION *table : tables)
		RtlDeleteFunctionTable(table);
	tables.clear();
}

void UnwindInfo::registerFrame(void *frame)
{
}

void UnwindInfo::deregisterFrame(void *frame)
{
}

#endif
