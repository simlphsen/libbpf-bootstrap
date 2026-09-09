// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
	return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
	return 0;
}
*/

SEC("kprobe/fuse_create_open")
int BPF_KPROBE(fuse_create_open, struct inode *dir, struct dentry *entry)
{
	if (bpf_get_current_uid_gid() != 0) return 0;

	void* ptr = BPF_CORE_READ(entry, d_u.d_alias.pprev);
	
	bpf_printk("xxx fuse_create_open: ptr = %lx, ino = %lu\n", ptr, BPF_CORE_READ(dir, i_ino));
	return 0;
}

SEC("kprobe/fuse_atomic_open")
int BPF_KPROBE(fuse_atomic_open, struct inode *dir, struct dentry *entry)
{
	if (bpf_get_current_uid_gid() != 0) return 0;

	void* ptr = BPF_CORE_READ(entry, d_u.d_alias.pprev);
	
	bpf_printk("xxx fuse_atomic_open: ptr = %lx, ino = %lu\n", ptr, BPF_CORE_READ(dir, i_ino));
	return 0;
}

SEC("kprobe/fuse_lookup")
int BPF_KPROBE(fuse_lookup, struct inode *dir, struct dentry *entry)
{
	if (bpf_get_current_uid_gid() != 0) return 0;

	void* ptr = BPF_CORE_READ(entry, d_u.d_alias.pprev);
	
	bpf_printk("xxx fuse_lookup: ptr = %lx, ino = %lu\n", ptr, BPF_CORE_READ(dir, i_ino));
	return 0;
}



