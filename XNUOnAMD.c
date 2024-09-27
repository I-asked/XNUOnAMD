#include <mach/mach_types.h>
#include <mach-o/loader.h>
#include <string.h>
#include <IOKit/IOLib.h>
#include <i386/proc_reg.h>
#include "mach_stuff.h"
#include "disasm.h"


enum { kKASLRAlign = (1 << 20) };


static inline vm_offset_t computeTextAddress(struct segment_command **textOut, struct section **sectOut, struct symtab_command **symsOut, struct segment_command **linkOut) {
	struct mach_header *hdr = (struct mach_header *)(~(kKASLRAlign - 1) & (vm_address_t)IOLog);
	
	while (hdr->magic != MH_MAGIC)
		hdr = (struct mach_header *)((vm_address_t)hdr - kKASLRAlign);
	
	struct segment_command *text = 0;
	struct section *sect = 0;
	struct symtab_command *syms = 0;
	struct segment_command *link = 0;
	
	struct load_command *cmds = (struct load_command *)((vm_address_t)hdr + sizeof(struct mach_header)),
	*cmd = cmds;
	for (vm_offset_t i = 0; i < hdr->ncmds; ++i, cmd = (struct load_command *)((vm_address_t)cmd + cmd->cmdsize)) {
		switch (cmd->cmd) {
			case LC_SEGMENT: {
				struct segment_command *seg = (struct segment_command *)cmd;
				struct section *secs = (struct section *)(seg + 1);
				if (!link && strcmp(seg->segname, "__LINKEDIT") == 0) {
					link = seg;
				} else if (!text && strcmp(seg->segname, "__TEXT") == 0) {
					text = seg;
					for (int j = 0; j < seg->nsects; ++j) {
						if (strcmp(secs[j].sectname, "__text") == 0) {
							sect = &secs[j];
						}
					}
				}
			} break;
			case LC_SYMTAB: {
				if (syms) {
					continue;
				}
				syms = (struct symtab_command *)cmd;
			} break;
			default:
				break;
		}
	}
	
	if (!text || !syms || !link) {
		IOLog("oops! text=%p; syms=%p\n", text, syms);
		return -1;
	}
	
	if (textOut && sectOut) {
		*textOut = text;
		*sectOut = sect;
	}
	
	if (symsOut && linkOut) {
		*symsOut = syms;
		*linkOut = link;
	}
	
	return (vm_offset_t)hdr;
}

vm_address_t findSymbol(const char *needle, vm_offset_t kbase, struct symtab_command *haystack, struct segment_command *link) {
	const struct nlist *sym = (struct nlist *)(link->vmaddr + haystack->symoff - link->fileoff);
	const char *strBase = (char *)(link->vmaddr + haystack->stroff - link->fileoff);
	const unsigned strLen = haystack->strsize;
	for (int i = 0; i < haystack->nsyms; ++i, sym++) {
		const unsigned slen = 1 + strlen(needle);
		if (strLen < slen + sym->n_un.n_strx) {
			return 0;
		}
		if (strncmp(strBase + sym->n_un.n_strx, needle, slen) == 0) {
			return sym->n_value;
		}
	}
	return 0;
}


#define INTR_OFF() __asm__ volatile ("cli")
#define INTR_ON() __asm__ volatile ("sti")

void (* unix_syscall)(x86_saved_state_t *)		= 0;
vm_map_t (* get_task_map_reference)(task_t)		= 0;
task_t (* get_threadtask)(thread_t)				= 0;
kern_return_t (* vm_map_read_user)(vm_map_t map,
								   vm_map_address_t src_addr,
								   void *dst_p,
								   vm_size_t size
								   )			= 0;
void (* thread_exception_return)(void)			= 0;
void (* mach_call_munger)(x86_saved_state_t *)	= 0;
unsigned char *user_trap						= 0;

extern void vm_map_deallocate(vm_map_t);


int my_user_trap(x86_saved_state_t *saved_state) {		
	uint16_t	insn;
	vm_map_t	map;
	signed		cerr = 1;
	if (is_saved_state32(saved_state)) {
		x86_saved_state32_t	*regs;
		regs = saved_state32(saved_state);
		
		if (regs->trapno != 6 /* T_INVALID_OPCODE */) {
			return 1;
		}
		
		map = get_task_map_reference(get_threadtask(current_thread()));
		if (map) {
			cerr = vm_map_read_user(map, regs->eip, &insn, sizeof(insn));
			vm_map_deallocate(map);
		}
		
		if (cerr) {
			return cerr;
		}
		
		if (insn == 0x340f) {
			/* 0x0f 0x34 -> SYSENTER (Intel-specific) */
			
			regs->eip = regs->edx;
			regs->uesp = regs->ecx;
			
			if ((signed)regs->eax < 0) {
				mach_call_munger(saved_state);
			} else {
				unix_syscall(saved_state);
			}
			
			thread_exception_return();
			
			return 0;
		} else if (insn == 0x350f) {
			/* 0x0f 0x35 -> SYSEXIT (Intel-specific) */
			
			regs->eip = regs->edx;
			regs->uesp = regs->ecx;
			
			thread_exception_return();
			
			return 0;
		}
	}
	return 1;
}


extern void new_user_trap;
extern void new_user_trap_end;
extern void old_user_trap;
extern void old_user_trap_end;
extern vm_address_t old_user_trap_ret;

static int altered = FALSE;


kern_return_t XNUOnAMD_start (kmod_info_t *ki, void *d) {
	struct segment_command *text = 0;
	struct section *sect = 0;
	struct symtab_command *syms = 0;
	struct segment_command *link = 0;
	vm_offset_t kbase = -1;
	int lockSet = FALSE;
	
	int cerr = -1;
	if ((kbase = computeTextAddress(&text, &sect, &syms, &link)) == -1) {
		goto end;
	}
	if (!text || !syms || !sect || !link) {
		goto end;
	}
	void *lo_mach_scall	= 0;
	cerr = 0;
#define SETSYM(S) if (!cerr) { if (!(S = (void *)findSymbol("_" #S, kbase, syms, link))) { cerr = -1; } else { IOLog(#S "=%p\n", S); } }
	SETSYM(user_trap)
	
	SETSYM(unix_syscall)
	SETSYM(get_task_map_reference)
	SETSYM(get_threadtask)
	SETSYM(vm_map_read_user)
	SETSYM(thread_exception_return)
	
	SETSYM(lo_mach_scall)
#undef SETSYM
	if (cerr) {
		goto end;
	}
	
	unsigned char *ptr = lo_mach_scall;
	IOLog("Obtained ptr=%p\n", ptr);
	for (;;) {
		unsigned len;
		IOLog("op = %02x\n", *ptr);
		ldisasm(ptr, &len);
		if (len == 5 && *ptr == 0xe8) {
			break;
		}
		if (len == -1 || ptr > ((unsigned char *)lo_mach_scall + 0x400)) {
			IOLog("Pointer overflow @ ldisasm No. 1; len=%d\n", len);
			goto end;
		}
		ptr += len;
	}
	int reloff = (5 + *(int *)(1 + ptr));
	mach_call_munger = (void *)((vm_address_t)ptr + reloff);
	IOLog("%02x %02x %02x %02x %02x -> mach_call_munger=%p+(%d) -> %p\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr, reloff, mach_call_munger);
	
	INTR_OFF();
	set_cr0(get_cr0()&~CR0_WP); // clear WP bit
	lockSet = TRUE;
	
	if (get_cr0()&CR0_WP) {
		cerr = -1;
		goto end;
	}
	
	const unsigned minsz = &new_user_trap_end - &new_user_trap;
	IOLog("MinSZ=%d; user_trap=%p; userTrap[0]=0x%02x\n", minsz, user_trap, user_trap[0]);
	// compute the total amount of insns to patch
	unsigned insnNext = 0;
	while (insnNext < minsz) {
		unsigned length;
		ldisasm(&user_trap[insnNext], &length);
		if (length == -1) {
			goto end;
		}
		insnNext += length;
	}
	IOLog("insnNext=%d\n", insnNext);

	if (insnNext > (&old_user_trap_end - &old_user_trap)) {
		cerr = -1;
		goto end;
	}
	
	// copy the insns to `old_user_trap`
	for (int i = 0; i < insnNext; ++i) {
		((unsigned char *)&old_user_trap)[i] = user_trap[i];
	}
	old_user_trap_ret = (vm_address_t)((char *)user_trap + insnNext);
	IOLog("old_user_trap_ret=0x%08x\n", old_user_trap_ret);
	for (int i = 0; i < minsz; ++i) {
		user_trap[i] = ((unsigned char *)&new_user_trap)[i];
	}
	altered = TRUE;
	
end:
	if (lockSet) {
		set_cr0(get_cr0()|CR0_WP);
		INTR_ON();
	}
	
    return KERN_SUCCESS;
}


kern_return_t XNUOnAMD_stop (kmod_info_t *ki, void *d) {
	const unsigned minsz = &new_user_trap_end - &new_user_trap;
	if (altered) {
		INTR_OFF();
		set_cr0(get_cr0()&~CR0_WP);
		for (int i = 0; i < minsz; ++i) {
			user_trap[i] = ((unsigned char *)&old_user_trap)[i];
		}
		set_cr0(get_cr0()|CR0_WP);
		INTR_ON();
		altered = FALSE;
	}
	
    return KERN_SUCCESS;
}
