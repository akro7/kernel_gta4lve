#!/usr/bin/env python3
"""Apply documented BakaSU manual hooks and verified V3 settings to Linux 4.14.

Unpublished CuteCat BBG, Re-Kernel, NoMount, SuSFS, CPU/GPU overclock, and
72 Hz DTBO integrations are intentionally not added here.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEXTS = {}


def replace_once(relative_path: str, old: str, new: str, label: str) -> None:
    text = TEXTS.get(relative_path)
    if text is None:
        text = (ROOT / relative_path).read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{relative_path}: expected one match for {label}, found {count}")
    TEXTS[relative_path] = text.replace(old, new, 1)


# BakaSU v4.2.0-rc3 manual hooks required for non-GKI Linux 4.14.
replace_once(
    "fs/exec.c",
    "static int do_execveat_common(int fd, struct filename *filename,\n"
    "\t\t\t      struct user_arg_ptr argv,\n"
    "\t\t\t      struct user_arg_ptr envp,\n"
    "\t\t\t      int flags)\n",
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "__attribute__((hot))\n"
    "extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,\n"
    "\t\t\t\tvoid *argv, void *envp, int *flags);\n"
    "__attribute__((hot))\n"
    "extern int ksu_handle_post_execveat(int *fd, struct filename **filename_ptr,\n"
    "\t\t\t\tvoid *argv, void *envp, int *flags, int *retval);\n"
    "#endif\n\n"
    "static int do_execveat_common(int fd, struct filename *filename,\n"
    "\t\t\t      struct user_arg_ptr argv,\n"
    "\t\t\t      struct user_arg_ptr envp,\n"
    "\t\t\t      int flags)\n",
    "execve hook declarations",
)
replace_once(
    "fs/exec.c",
    "\tint retval;\n\n\tif (IS_ERR(filename))",
    "\tint retval;\n\n"
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);\n"
    "#endif\n\n"
    "\tif (IS_ERR(filename))",
    "execve pre-hook",
)
replace_once(
    "fs/exec.c",
    "out_ret:\n\tputname(filename);\n\treturn retval;",
    "out_ret:\n"
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "\tksu_handle_post_execveat(&fd, &filename, &argv, &envp, &flags, &retval);\n"
    "#endif\n"
    "\tputname(filename);\n\treturn retval;",
    "execve post-hook",
)

replace_once(
    "fs/open.c",
    "SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)\n{",
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "__attribute__((hot))\n"
    "extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,\n"
    "\t\t\t\tint *mode, int *flags);\n"
    "#endif\n\n"
    "SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)\n{",
    "faccessat hook declaration",
)
replace_once(
    "fs/open.c",
    "\tunsigned int lookup_flags = LOOKUP_FOLLOW;\n\n\tif (mode & ~S_IRWXO)",
    "\tunsigned int lookup_flags = LOOKUP_FOLLOW;\n\n"
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n"
    "#endif\n\n"
    "\tif (mode & ~S_IRWXO)",
    "faccessat hook call",
)

replace_once(
    "fs/stat.c",
    "#if !defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_SYS_NEWFSTATAT)\n",
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "__attribute__((hot))\n"
    "extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);\n"
    "extern void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);\n"
    "#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)\n"
    "extern void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr);\n"
    "#endif\n"
    "#endif\n\n"
    "#if !defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_SYS_NEWFSTATAT)\n",
    "stat hook declarations",
)
replace_once(
    "fs/stat.c",
    "SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,\n"
    "\t\tstruct stat __user *, statbuf, int, flag)\n{\n"
    "\tstruct kstat stat;\n\tint error;\n\n"
    "\terror = vfs_fstatat(dfd, filename, &stat, flag);",
    "SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,\n"
    "\t\tstruct stat __user *, statbuf, int, flag)\n{\n"
    "\tstruct kstat stat;\n\tint error;\n\n"
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "\tksu_handle_stat(&dfd, &filename, &flag);\n"
    "#endif\n"
    "\terror = vfs_fstatat(dfd, filename, &stat, flag);",
    "newfstatat hook",
)
replace_once(
    "fs/stat.c",
    "SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)\n{\n"
    "\tstruct kstat stat;\n\tint error = vfs_fstat(fd, &stat);\n\n"
    "\tif (!error)\n\t\terror = cp_new_stat(&stat, statbuf);\n\n\treturn error;",
    "SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)\n{\n"
    "\tstruct kstat stat;\n\tint error = vfs_fstat(fd, &stat);\n\n"
    "\tif (!error)\n\t\terror = cp_new_stat(&stat, statbuf);\n\n"
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "\tksu_handle_newfstat_ret(&fd, &statbuf);\n"
    "#endif\n"
    "\treturn error;",
    "newfstat return hook",
)
replace_once(
    "fs/stat.c",
    "SYSCALL_DEFINE2(fstat64, unsigned long, fd, struct stat64 __user *, statbuf)\n{\n"
    "\tstruct kstat stat;\n\tint error = vfs_fstat(fd, &stat);\n\n"
    "\tif (!error)\n\t\terror = cp_new_stat64(&stat, statbuf);\n\n"
    "\treturn error;",
    "SYSCALL_DEFINE2(fstat64, unsigned long, fd, struct stat64 __user *, statbuf)\n{\n"
    "\tstruct kstat stat;\n\tint error = vfs_fstat(fd, &stat);\n"
    "\tif (!error)\n\t\terror = cp_new_stat64(&stat, statbuf);\n"
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "\tksu_handle_fstat64_ret(&fd, &statbuf);\n"
    "#endif\n"
    "\treturn error;",
    "fstat64 return hook",
)
replace_once(
    "fs/stat.c",
    "SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,\n"
    "\t\tstruct stat64 __user *, statbuf, int, flag)\n{\n"
    "\tstruct kstat stat;\n\tint error;\n\n"
    "\terror = vfs_fstatat(dfd, filename, &stat, flag);",
    "SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,\n"
    "\t\tstruct stat64 __user *, statbuf, int, flag)\n{\n"
    "\tstruct kstat stat;\n\tint error;\n\n"
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "\tksu_handle_stat(&dfd, &filename, &flag);\n"
    "#endif\n"
    "\terror = vfs_fstatat(dfd, filename, &stat, flag);",
    "fstatat64 hook",
)

replace_once(
    "kernel/reboot.c",
    "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,\n"
    "\t\tvoid __user *, arg)\n{",
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);\n"
    "#endif\n\n"
    "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,\n"
    "\t\tvoid __user *, arg)\n{",
    "reboot hook declaration",
)
replace_once(
    "kernel/reboot.c",
    "\tint ret = 0;\n\n\t/* We only trust the superuser with rebooting the system. */",
    "\tint ret = 0;\n\n"
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n"
    "#endif\n\n"
    "\t/* We only trust the superuser with this call. */",
    "reboot hook call",
)

# Match CuteCat V3's LZ4-by-default behavior using the driver's built-in compressor.
replace_once(
    "drivers/block/zram/zram_drv.c",
    'static const char *default_compressor = "lzo-rle";',
    'static const char *default_compressor = "lz4";',
    "ZRAM default compressor",
)

# Apply only V3 settings whose symbols exist in this tree/BakaSU tag.
defconfig = ROOT / "arch/arm64/configs/gta4lve_eur_open_defconfig"
lines = defconfig.read_text().splitlines()
settings = {
    "CONFIG_KSU": "y",
    "CONFIG_KSU_MANUAL_HOOK": "y",
    "CONFIG_KSU_TRACEPOINT_HOOK": "n",
    "CONFIG_KSU_MULTI_MANAGER_SUPPORT": "y",
    "CONFIG_KSU_TOOLKIT_SUPPORT": "y",
    "CONFIG_KSU_FULL_NAME_FORMAT": '"%TAG_NAME%"',
    "CONFIG_KSU_SUSFS": "n",
    "CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK": "y",
    "CONFIG_KSU_MANUAL_HOOK_AUTO_INITRC_HOOK": "y",
    "CONFIG_KSU_MANUAL_HOOK_AUTO_INPUT_HOOK": "y",
    "CONFIG_DEVTMPFS": "y",
    "CONFIG_PID_NS": "y",
    "CONFIG_USER_NS": "y",
    "CONFIG_CPU_FREQ_GOV_COMMON": "y",
    "CONFIG_CPU_FREQ_GOV_CONSERVATIVE": "y",
    "CONFIG_CPU_FREQ_GOV_INTERACTIVE": "y",
    "CONFIG_CPU_FREQ_GOV_ONDEMAND": "y",
    "CONFIG_CPU_FREQ_GOV_POWERSAVE": "y",
    "CONFIG_NETFILTER_ADVANCED": "y",
    "CONFIG_IP6_NF_NAT": "y",
    "CONFIG_KALLSYMS_ALL": "y",
    "CONFIG_ZRAM": "y",
    "CONFIG_CRYPTO_LZ4": "y",
    "CONFIG_LZ4_COMPRESS": "y",
}
for key, value in settings.items():
    lines = [line for line in lines if not line.startswith(f"{key}=") and line != f"# {key} is not set"]
    lines.append(f"{key}={value}" if value != "n" else f"# {key} is not set")

for relative_path, text in TEXTS.items():
    (ROOT / relative_path).write_text(text)
defconfig.write_text("\n".join(lines) + "\n")
print("Applied BakaSU 4.14 manual hooks, ShadowSU signature-compatible KSU config, V3-supported options, and LZ4 ZRAM default.")
