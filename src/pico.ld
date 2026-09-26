/* pico.ld - the layout the freestanding links install themselves with.
 *
 * Replaces picolibc's picolibc_linux.ld. What it must provide is dictated by
 * src/idle.c's eviction windows and by the layout invariant tests/run.sh
 * greps for:
 *
 *   - ENTRY(_start): idle_text_lo must be the FIRST byte of the text
 *     segment (the KEEP-sorted .init.* placement; ".init.idle" sorts before
 *     ".init.start", where src/start.c's _start lives, so everything before
 *     idle_sleep's own page -- the bootstrap included -- is in the drop
 *     range).
 *   - etext: the end of the executable segment.
 *   - _pid_base = the first page of the RW segment (ADDR(.rodata)): the
 *     segment begins there, page-aligned, and idle_sleep drops
 *     [PCEIL(_pid_base), PFLOOR(min(__tls_space, __data_start))) -- the clean
 *     file-backed pages of rodata and .data.rel.ro.
 *   - __data_start = ADDR(.data), __tls_space = the first byte ever written.
 *     There is no TLS in this binary (single-threaded; errno and the canary
 *     are plain .bss), so __tls_space is simply .data's own start: the drop
 *     covers rodata + .data.rel.ro and keeps the .data/.bss page.
 *
 * There is no .tdata/.tbss, so tests/run.sh's min-marker falls back to
 * .data, which is exactly what the runtime symbols say here.
 */

ENTRY(_start)

PHDRS
{
	text PT_LOAD FLAGS(5);   /* R E */
	ram PT_LOAD FLAGS(6);    /* RW: the whole writable file image */
}

SECTIONS
{
	. = 0x100000;

	.init : {
		KEEP (*(SORT_BY_NAME(.init) SORT_BY_NAME(.init.*)))
	} :text

	.text : {
		*(.text.startup .text.startup.*)
		*(.text.unlikely .text.unlikely.*)
		*(.text .text.* .gnu.linkonce.t.*)
	} :text

	PROVIDE (etext = .);

	/* The RW segment starts page-aligned so that _pid_base is also a page
	   boundary: idle drops from its own first page onward. */
	. = ALIGN(0x1000);

	.rodata : {
		*(.rdata)
		*(.rodata .rodata.*)
		*(.gnu.linkonce.r.*)
		*(.srodata.cst16) *(.srodata.cst8) *(.srodata.cst4) *(.srodata.cst2)
		*(.srodata .srodata.*)
	} :ram

	.data.rel.ro : {
		*(.data.rel.ro .data.rel.ro.*)
	} :ram

	.data : {
		*(.data .data.*)
		*(.gnu.linkonce.d.*)
		*(.sdata .sdata.*)
		. = ALIGN(8);
	} :ram

	.bss (NOLOAD) : {
		*(.sbss .sbss.*)
		*(.bss .bss.*)
		*(.gnu.linkonce.b.*)
		*(COMMON)
		. = ALIGN(8);
	} :ram

	PROVIDE (_pid_base = ADDR(.rodata));
	PROVIDE (__data_start = ADDR(.data));
	PROVIDE (__tls_space = ADDR(.data));
	PROVIDE (__bss_start = ADDR(.bss));
	PROVIDE (end = .);
	PROVIDE (_end = .);

	/* Nothing here uses unwinding, ctors or ABI-tag notes; drop whatever the
	   compiler emits so the final image cannot accrue a writable or
	   executable section nobody references. */
	/DISCARD/ : {
		*(.note.gnu.property) *(.note.ABI-tag) *(.comment)
		*(.ARM.attributes) *(.gnu.attributes)
		*(.eh_frame) *(.eh_frame.*)
		*(.init_array) *(.init_array.*) *(.fini_array) *(.fini_array.*)
		*(.ctors) *(.dtors)
	}
}
