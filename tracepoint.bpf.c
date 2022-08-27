#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/*

References:
- https://github.com/up9inc/mizu/blob/develop/tap/tlstapper/bpf/tcp_kprobes.c
- https://github.com/bcnote3314/eBPF_example/blob/d97fae7567ddb2496897efc87fd5f800703625e2/src/examples/tcp/tcp.c#L222
- https://github.com/torvalds/linux/blob/79ef0c00142519bc34e1341447f3797436cc48bf/Documentation/trace/kprobes.rst
- https://github.com/torvalds/linux/blob/169e77764adc041b1dacba84ea90516a895d43b2/tools/bpf/bpftool/Documentation/bpftool-gen.rst

*/

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	bpf_printk("execve %s", ctx->args[0]);
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int kprobe__tcp__recvmsg(struct pt_regs *ctx) {
	const char fmt_str[] = "tcp_recvmsg\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
