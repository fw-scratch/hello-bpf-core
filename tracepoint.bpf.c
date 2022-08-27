#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/*

References:
- https://github.com/up9inc/mizu/blob/develop/tap/tlstapper/bpf/tcp_kprobes.c
- https://github.com/bcnote3314/eBPF_example/blob/d97fae7567ddb2496897efc87fd5f800703625e2/src/examples/tcp/tcp.c#L222
- https://github.com/bcnote3314/eBPF_example/blob/main/src/examples/tcp_connect/tcp_connect.c
- https://github.com/torvalds/linux/blob/79ef0c00142519bc34e1341447f3797436cc48bf/Documentation/trace/kprobes.rst
- https://github.com/torvalds/linux/blob/169e77764adc041b1dacba84ea90516a895d43b2/tools/bpf/bpftool/Documentation/bpftool-gen.rst
- https://github.com/SENIORFROGZ/ruffname/blob/aab2ca1113759e1e6adce2ad3e7d2ed8130e457b/pkg/ebpf/c/bpf_helpers.h#L112
- https://github.com/torvalds/linux/blob/f86d1fbbe7858884d6754534a0afbb74fc30bc26/net/ipv4/tcp_bpf.c#L188
- https://github.com/torvalds/linux/blob/master/include/linux/socket.h#L52

*/

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	bpf_printk("execve %s", ctx->args[0]);
	return 0;
}

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_PARM6(x) ((x)->r9)

SEC("kprobe/tcp_recvmsg")
int kprobe__tcp__recvmsg(struct pt_regs *ctx) {
	struct sock *sk = PT_REGS_PARM1(ctx);
	const char fmt_str[] = "tcp_recvmsg\n";
	bpf_trace_printk(fmt_str, sizeof(fmt_str));

	bpf_printk("param 1 sock      %x", &PT_REGS_PARM1(ctx));
	bpf_printk("param 2 msg       %x", &PT_REGS_PARM2(ctx));
	bpf_printk("param 3 len       %u", &PT_REGS_PARM3(ctx));
	bpf_printk("param 4 flags     %u", &PT_REGS_PARM4(ctx));
	bpf_printk("param 5 addr_len  %u", &PT_REGS_PARM5(ctx));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
