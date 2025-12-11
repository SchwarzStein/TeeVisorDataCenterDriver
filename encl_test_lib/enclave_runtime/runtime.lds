OUTPUT_FORMAT(elf64-x86-64)
ENTRY(enclave_entry)

SECTIONS
{
	. = 0;
    __encl_base = .;
    . = SEGMENT_START("text-segment", 0) + SIZEOF_HEADERS;
    .note.gnu.build-id : { *(.note.gnu.build-id) }
    .hash          : { *(.hash) }
    .gnu.hash      : { *(.gnu.hash) }
    .dynsym        : { *(.dynsym) }
    .dynstr        : { *(.dynstr) }
    .gnu.version   : { *(.gnu.version) }
    .gnu.version_d : { *(.gnu.version_d) }
    .gnu.version_r : { *(.gnu.version_r) }

	.text : {
		*(.text.handler)
		. = ALIGN(4096);
		*(.text*)
		*(.rodata*)
		FILL(0xDEADBEEF);
		. = ALIGN(4096);
	}

	.data : {
		*(.data*)
	}
}

ASSERT(!DEFINED(_GLOBAL_OFFSET_TABLE_), "Libcalls through GOT are not supported in enclaves")
