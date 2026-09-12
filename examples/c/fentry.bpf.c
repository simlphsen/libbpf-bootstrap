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


struct lock_key {
    __u32 pid;
    __u64 mm;
};

/* 1. 记录尝试获取锁的时间戳 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct lock_key);
    __type(value, __u64);
} lock_start_time SEC(".maps");

/* 2. 记录成功持有锁的时间戳 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct lock_key);
    __type(value, __u64);
} lock_held_time SEC(".maps");


/* 开始尝试获取锁 */
SEC("tp_btf/mmap_lock_start_locking")
int BPF_PROG(trace_mmap_lock_start_locking, struct mm_struct *mm, const char *memcg_path, bool write)
{
    struct lock_key key = {};
    key.pid = (__u32)bpf_get_current_pid_tgid();
    key.mm = (__u64)mm;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&lock_start_time, &key, &ts, BPF_ANY);

    return 0;
}


/* 获取锁的结果返回 */
SEC("tp_btf/mmap_lock_acquire_returned")
int BPF_PROG(trace_mmap_lock_acquire_returned, struct mm_struct *mm, const char *memcg_path, bool write, bool success)
{
    struct lock_key key = {};
    key.pid = (__u32)bpf_get_current_pid_tgid();
    key.mm = (__u64)mm;

    __u64 *start_ts = bpf_map_lookup_elem(&lock_start_time, &key);
    u64 now = bpf_ktime_get_ns();
    u64 wait_us = 0;

    if (start_ts) {
        wait_us = (now - *start_ts);
        bpf_map_delete_elem(&lock_start_time, &key);
    }

    if (success) {
        // 成功拿到锁，记录持锁起始时间
        bpf_map_update_elem(&lock_held_time, &key, &now, BPF_ANY);
    } 

	if (wait_us > 100000000) {
        // 获取失败，直接打印
        char comm[16];
        bpf_get_current_comm(&comm, sizeof(comm));
		u64 kstack[8] = {0};
	    int kstack_sz = bpf_get_stack(ctx, kstack, sizeof(kstack), 0);

        bpf_printk("mmap_lock ACQUIRE: comm=%s pid=%d mm=%s mode=%s wait_us=%llu succ=%d ks=%pS %pS %pS\n",
                   comm, key.pid, memcg_path,
                   write ? "WRITE" : "READ", wait_us, success, kstack[5], kstack[6], kstack[7]);
    }

    return 0;
}


/* 锁释放 */
SEC("tp_btf/mmap_lock_released")
int BPF_PROG(trace_mmap_lock_released, struct mm_struct *mm, const char *memcg_path, bool write)
{
    struct lock_key key = {};
    key.pid = (__u32)bpf_get_current_pid_tgid();
    key.mm = (__u64)mm;

    __u64 *held_ts = bpf_map_lookup_elem(&lock_held_time, &key);
    if (!held_ts)
        return 0;

    u64 now = bpf_ktime_get_ns();
    u64 hold_us = (now - *held_ts);
    bpf_map_delete_elem(&lock_held_time, &key);

	if (hold_us < 100000000) return 0;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

	u64 kstack[8] = {0};
    int kstack_sz = bpf_get_stack(ctx, kstack, sizeof(kstack), 0);

    /* 直接将结果输出至 trace_pipe */
    bpf_printk("mmap_lock RELEASE: comm=%s pid=%d mm=%s mode=%s hold_us=%llu ks=%pS %pS %pS\n",
               comm, key.pid, memcg_path,
               write ? "WRITE" : "READ", hold_us, kstack[5], kstack[6], kstack[7]);

    return 0;
}

struct {
 __uint(type, BPF_MAP_TYPE_RINGBUF);
 __uint(max_entries, 2 * 1024 * 1024);
} rb SEC(".maps");

struct bitmap_e {
	unsigned long bitmap[16384];
};

struct zram {
	unsigned long *bitmap;
	unsigned long nr_pages;
} __attribute__((preserve_access_index));

struct zram *zg = NULL;

SEC("kprobe/zram_read_page")
int BPF_KPROBE(zram_read_page, struct zram *z)
{
	if (zg) return 0;
	zg = z;
	bpf_printk("xxx zram_read_page: ptr = %lx, ino = %lu\n", z, BPF_CORE_READ(z, nr_pages));
	return 0;
}

SEC("kprobe/disksize_show")
int BPF_KPROBE(disksize_show)
{
	if (!zg) return 0;
	unsigned long *bitmap = BPF_CORE_READ(zg, bitmap);

	struct bitmap_e *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (e) {
		bpf_probe_read_kernel(e->bitmap, sizeof(e->bitmap), bitmap);
		bpf_ringbuf_submit(e, 0);
	}
	
	unsigned long tmp[16];
	bpf_probe_read_kernel(tmp, sizeof(tmp), bitmap);
	for (int i = 0; i < 16; i++) {
		bpf_printk("xxx zram_bitmap: ptr = %lx\n", tmp[i]);
	}
	return 0;
}



