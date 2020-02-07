/* DWARF2 EH unwinding support for x86.
   Copyright (C) 2014 Free Software Foundation, Inc.

This file is part of GCC.

GCC is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3, or (at your option)
any later version.

GCC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

Under Section 7 of GPL version 3, you are granted additional
permissions described in the GCC Runtime Library Exception, version
3.1, as published by the Free Software Foundation.

You should have received a copy of the GNU General Public License and
a copy of the GCC Runtime Library Exception along with this program;
see the files COPYING3 and COPYING.RUNTIME respectively.  If not, see
<http://www.gnu.org/licenses/>.  */

/* Do code reading to identify a signal frame, and set the frame
   state data appropriately.  See unwind-dw2.c for the structs.  */

#if !defined(inhibit_libc) && defined(__QNXNTO__) && _NTO_VERSION >= 660

#include <ucontext.h>
#include <sys/link.h>

struct address_range
{
  _Unwind_Ptr begin;
  _Unwind_Ptr end;
};

static int
load_contains_pc (const struct dl_phdr_info *info, size_t size, void *ptr)
{
  long n;
  struct address_range *range = (struct address_range *)ptr;
  const Elf32_Phdr *phdr = info->dlpi_phdr;

  (void)size;

  for (n = info->dlpi_phnum; --n >= 0; phdr++)
    {
      if (phdr->p_type == PT_LOAD)
        {
	      _Unwind_Ptr vaddr = (_Unwind_Ptr)phdr->p_vaddr + info->dlpi_addr;
	      if (range->begin >= vaddr && range->end < vaddr + phdr->p_memsz)
	        return 1;
	    }
	}
  return 0;
}

#define MD_FALLBACK_FRAME_STATE_FOR x86_fallback_frame_state

static _Unwind_Reason_Code
x86_fallback_frame_state (struct _Unwind_Context *context,
			  _Unwind_FrameState *fs)
{
  unsigned char *pc;
  mcontext_t *mctx;
  long new_cfa;
  struct address_range range;

  /*
   <__signalstub+0>:	mov    0x2c(%esp),%eax
   <__signalstub+4>:	mov    %edi,0x18(%eax)
   <__signalstub+7>:	mov    %esi,0x1c(%eax)
   <__signalstub+10>:	mov    %ebp,0x20(%eax)
   <__signalstub+13>:	mov    %ebx,0x28(%eax)
   <__signalstub+16>:	mov    %edx,0x2c(%eax)
   <__signalstub+19>:	mov    %ecx,0x30(%eax)
   <__signalstub+22>:	mov    %esp,%esi
   <__signalstub+24>:	mov    %eax,%edi
   <__signalstub+26>:	push   %eax
   <__signalstub+27>:	push   %esi
   <__signalstub+28>:	pushl  (%esi)
   <__signalstub+30>:	call   *0x28(%esi)
   <__signalstub+33>:	push   %esi             <--- PC
   <__signalstub+34>:	mov    %edi,%eax
   <__signalstub+36>:	mov    0x18(%eax),%edi
   <__signalstub+39>:	mov    0x1c(%eax),%esi
   <__signalstub+42>:	mov    0x20(%eax),%ebp
   <__signalstub+45>:	mov    0x28(%eax),%ebx
   <__signalstub+48>:	mov    0x2c(%eax),%edx
   <__signalstub+51>:	mov    0x30(%eax),%ecx
   <__signalstub+54>:	sub    $0x4,%esp
   <__signalstub+57>:	mov    $0x1b,%eax
   <__signalstub+62>:	int    $0x28
   <__signalstub+64>:	ret    
   <__signalstub+65>:	ret    
  */

  pc = context->ra - 33;
  range.begin = (_Unwind_Ptr)pc;
  range.end = range.begin + 65;
  if (dl_iterate_phdr (load_contains_pc, &range)
      &&   *(unsigned int*)(pc) == 0x2c24448b
      && *(unsigned int*)(pc+4) == 0x89187889
      && *(unsigned int*)(pc+8) == 0x68891c70
      && *(unsigned int*)(pc+12) == 0x28588920
      && *(unsigned int*)(pc+16) == 0x892c5089
      && *(unsigned int*)(pc+20) == 0xe6893048
      && *(unsigned int*)(pc+24) == 0x5650c789
      && *(unsigned int*)(pc+28) == 0x56ff36ff
      && *(unsigned int*)(pc+32) == 0xf8895628
      && *(unsigned int*)(pc+36) == 0x8b18788b
      && *(unsigned int*)(pc+40) == 0x688b1c70
      && *(unsigned int*)(pc+44) == 0x28588b20
      && *(unsigned int*)(pc+48) == 0x8b2c508b
      && *(unsigned int*)(pc+52) == 0xec833048
      && *(unsigned int*)(pc+56) == 0x1bb804
      && *(unsigned int*)(pc+60) == 0x28cd0000
      && *(unsigned char*)(pc+64) == 0xc3)
    {
      struct handler_args {
	    int signo;
	    siginfo_t *sip;
	    ucontext_t *ucontext;
      } *handler_args = context->cfa;
      mctx = &handler_args->ucontext->uc_mcontext;
    }
  else
    return _URC_END_OF_STACK;

  new_cfa = mctx->cpu.esp;

  fs->regs.cfa_how = CFA_REG_OFFSET;
  fs->regs.cfa_reg = 4;
  fs->regs.cfa_offset = new_cfa - (long) context->cfa;

  /* The SVR4 register numbering macros aren't usable in libgcc.  */
  fs->regs.reg[0].how = REG_SAVED_OFFSET;
  fs->regs.reg[0].loc.offset = (long)&mctx->cpu.eax - new_cfa;
  fs->regs.reg[3].how = REG_SAVED_OFFSET;
  fs->regs.reg[3].loc.offset = (long)&mctx->cpu.ebx - new_cfa;
  fs->regs.reg[1].how = REG_SAVED_OFFSET;
  fs->regs.reg[1].loc.offset = (long)&mctx->cpu.ecx - new_cfa;
  fs->regs.reg[2].how = REG_SAVED_OFFSET;
  fs->regs.reg[2].loc.offset = (long)&mctx->cpu.edx - new_cfa;
  fs->regs.reg[6].how = REG_SAVED_OFFSET;
  fs->regs.reg[6].loc.offset = (long)&mctx->cpu.esi - new_cfa;
  fs->regs.reg[7].how = REG_SAVED_OFFSET;
  fs->regs.reg[7].loc.offset = (long)&mctx->cpu.edi - new_cfa;
  fs->regs.reg[5].how = REG_SAVED_OFFSET;
  fs->regs.reg[5].loc.offset = (long)&mctx->cpu.ebp - new_cfa;
  fs->regs.reg[8].how = REG_SAVED_OFFSET;
  fs->regs.reg[8].loc.offset = (long)&mctx->cpu.eip - new_cfa;
  fs->retaddr_column = 8;
  fs->signal_frame = 1;

  return _URC_NO_REASON;
}

#endif

