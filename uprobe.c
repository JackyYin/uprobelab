#include <libelf.h>
#include <gelf.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>

#define IOC_MAGIC 'x'
#define IOCTL_ATTACH_UPROBE _IOW(IOC_MAGIC, 0, void *)

struct uprobe_attach_info {
    int fd;
    long long offset;
};

static int devfd = 0;

static int find_symbol_and_attach(int fd, char *symbol_name)
{
    Elf *elf = NULL;
    Elf_Scn *scn = NULL;
    GElf_Phdr phdr;
    GElf_Shdr shdr;
    size_t shstrndx;
    unsigned long baseaddr;

    elf = elf_begin(fd, ELF_C_READ, NULL); 
    if (!elf)
        return elf_errno();

    for (int i = 0; ; i++) {
        if (!gelf_getphdr(elf, i, &phdr))
            break;

        if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X))
            continue;

        baseaddr = phdr.p_vaddr - phdr.p_offset;
        fprintf(stdout, "baseaddr: %ld\n", baseaddr);
    }

    while ((scn = elf_nextscn(elf, scn))) {
        if (!gelf_getshdr(scn, &shdr))
            continue;

        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
            continue;

        Elf_Data *data = NULL;
        while ((data = elf_getdata(scn, data))) {
            if (data->d_size % shdr.sh_entsize)
                continue;

            GElf_Sym sym;
            const char *name = NULL;
            for (int i = 0; i < (data->d_size / shdr.sh_entsize) ; i++) {
                if (!gelf_getsym(data, i, &sym))
                    continue;

                if (!sym.st_value)
                    continue;

                if (!(name = elf_strptr(elf, shdr.sh_link, sym.st_name)) || *name == '\0')
                    continue;

                if (!strcmp(name, symbol_name)) {
                    fprintf(stdout, "symbol name: %s, symbol offset: %ld\n", name, sym.st_value - baseaddr);

                    struct uprobe_attach_info upinfo = {
                        .fd = fd,
                        .offset = sym.st_value - baseaddr
                    };

                    if (ioctl(devfd, IOCTL_ATTACH_UPROBE, (unsigned long)&upinfo) < 0) {
                        fprintf(stderr, "failed to call ioctl, %d\n", errno);
                    }
                }
            }
        }
    }
}

static int scanning_proc_for_pid_exe(long pid, char *symbol_name)
{
    int fd;
    char path[sizeof("/proc//exe") + 10];

    sprintf(path, "/proc/%ld/exe", pid);
    fprintf(stdout, "%s\n", path);
    fd = open(path, O_RDONLY);

    if (fd == -1)
        return -errno; 

    find_symbol_and_attach(fd, symbol_name);
    close(fd);
    return 0;
}

static void scanning_proc_for_pid(long pid, char *symbol_name)
{
    scanning_proc_for_pid_exe(pid, symbol_name);
}

static int scanning_procfs(char *symbol_name)
{
    DIR *procdir;
    struct dirent *procent;

    procdir = opendir("/proc");
    if (!procdir)
        return -errno;

    while ((procent = readdir(procdir))) {
        long pid = strtol(procent->d_name, NULL, 10);
        if (procent->d_type == DT_DIR && pid) {
            scanning_proc_for_pid(pid, symbol_name);
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Please provide symbol name!\n");
        exit(-1);
    }

    devfd = open("/dev/myuprobe", O_RDWR);

    if (devfd < 0) {
        fprintf(stderr, "Not able to open uprobe char device!\n");
        exit(-1);
    }

    if (elf_version(EV_CURRENT) == EV_NONE)
        exit(-1);

    scanning_procfs(argv[1]);
}
