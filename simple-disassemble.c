#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <libelf.h>
#include <gelf.h>
#include <capstone/capstone.h>

// Define command-line options
#define OPT_DISASSEMBLE 'd'
#define OPT_HEADERS 'h'
#define OPT_SYMBOLS 's'
#define OPT_RELOCATIONS 'r'
#define OPT_DYNAMIC 'D'
#define OPT_ALL 'a'

// Define bit positions for options
#define BIT_DISASSEMBLE 0
#define BIT_HEADERS 1
#define BIT_SYMBOLS 2
#define BIT_RELOCATIONS 3
#define BIT_DYNAMIC 4

// Function prototypes
void print_usage(const char *prog_name);
void print_elf_header(Elf *elf);
void print_program_headers(Elf *elf);
void print_section_headers(Elf *elf);
void print_symbols(Elf *elf);
void print_relocations(Elf *elf);
void print_dynamic_section(Elf *elf);
void disassemble_code(Elf *elf, const char *section_name);

int main(int argc, char **argv) {
    int opt;
    int flags = 0;
    char *filename = NULL;
    int fd = -1;
    Elf *elf = NULL;
    
    // Parse command-line options
    while ((opt = getopt(argc, argv, "dhsrDa")) != -1) {
        switch (opt) {
            case OPT_DISASSEMBLE:
                flags |= (1 << BIT_DISASSEMBLE);
                break;
            case OPT_HEADERS:
                flags |= (1 << BIT_HEADERS);
                break;
            case OPT_SYMBOLS:
                flags |= (1 << BIT_SYMBOLS);
                break;
            case OPT_RELOCATIONS:
                flags |= (1 << BIT_RELOCATIONS);
                break;
            case OPT_DYNAMIC:
                flags |= (1 << BIT_DYNAMIC);
                break;
            case OPT_ALL:
                flags = ~0;
                break;
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    
    // If no options specified, show all information
    if (flags == 0) {
        flags = ~0;
    }
    
    // Get the filename
    if (optind >= argc) {
        fprintf(stderr, "Error: No ELF file specified\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    filename = argv[optind];
    
    // Open the file
    if ((fd = open(filename, O_RDONLY)) < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    
    // Initialize ELF library
    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "ELF library initialization failed: %s\n", elf_errmsg(-1));
        close(fd);
        exit(EXIT_FAILURE);
    }
    
    // Start ELF parsing
    if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
        fprintf(stderr, "elf_begin() failed: %s\n", elf_errmsg(-1));
        close(fd);
        exit(EXIT_FAILURE);
    }
    
    // Verify it's an ELF file
    if (elf_kind(elf) != ELF_K_ELF) {
        fprintf(stderr, "%s is not an ELF file\n", filename);
        elf_end(elf);
        close(fd);
        exit(EXIT_FAILURE);
    }
    
    // Process based on flags
    if (flags & (1 << BIT_HEADERS)) {
        print_elf_header(elf);
        print_program_headers(elf);
        print_section_headers(elf);
    }
    
    if (flags & (1 << BIT_SYMBOLS)) {
        print_symbols(elf);
    }
    
    if (flags & (1 << BIT_RELOCATIONS)) {
        print_relocations(elf);
    }
    
    if (flags & (1 << BIT_DYNAMIC)) {
        print_dynamic_section(elf);
    }
    
    if (flags & (1 << BIT_DISASSEMBLE)) {
        disassemble_code(elf, ".text");
    }
    
    // Cleanup
    elf_end(elf);
    close(fd);
    
    return EXIT_SUCCESS;
}

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [options] <elf-file>\n", prog_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d    Disassemble code sections\n");
    fprintf(stderr, "  -h    Display ELF header information\n");
    fprintf(stderr, "  -s    Display symbol table\n");
    fprintf(stderr, "  -r    Display relocation information\n");
    fprintf(stderr, "  -D    Display dynamic section\n");
    fprintf(stderr, "  -a    Display all information (default)\n");
}

void print_elf_header(Elf *elf) {
    GElf_Ehdr ehdr;
    
    if (gelf_getehdr(elf, &ehdr) == NULL) {
        fprintf(stderr, "Failed to get ELF header: %s\n", elf_errmsg(-1));
        return;
    }
    
    printf("ELF Header:\n");
    printf("  Magic:   ");
    for (int i = 0; i < EI_NIDENT; i++) {
        printf("%02x ", ehdr.e_ident[i]);
    }
    printf("\n");
    
    printf("  Class:                             %s\n", 
           ehdr.e_ident[EI_CLASS] == ELFCLASS32 ? "ELF32" : 
           ehdr.e_ident[EI_CLASS] == ELFCLASS64 ? "ELF64" : "Invalid");
    
    printf("  Data:                              %s\n", 
           ehdr.e_ident[EI_DATA] == ELFDATA2LSB ? "2's complement, little endian" : 
           ehdr.e_ident[EI_DATA] == ELFDATA2MSB ? "2's complement, big endian" : "Invalid");
    
    printf("  Version:                           %d%s\n", 
           ehdr.e_ident[EI_VERSION], 
           ehdr.e_ident[EI_VERSION] == EV_CURRENT ? " (current)" : "");
    
    printf("  OS/ABI:                            %s\n", 
           ehdr.e_ident[EI_OSABI] == ELFOSABI_SYSV ? "UNIX - System V" :
           ehdr.e_ident[EI_OSABI] == ELFOSABI_LINUX ? "Linux" : "Other");
    
    printf("  ABI Version:                       %d\n", ehdr.e_ident[EI_ABIVERSION]);
    
    printf("  Type:                              %s\n", 
           ehdr.e_type == ET_REL ? "REL (Relocatable file)" :
           ehdr.e_type == ET_EXEC ? "EXEC (Executable file)" :
           ehdr.e_type == ET_DYN ? "DYN (Shared object file)" :
           ehdr.e_type == ET_CORE ? "CORE (Core file)" : "Unknown");
    
    printf("  Machine:                           %s\n", 
           ehdr.e_machine == EM_386 ? "Intel 80386" :
           ehdr.e_machine == EM_X86_64 ? "AMD x86-64" :
           ehdr.e_machine == EM_ARM ? "ARM" :
           ehdr.e_machine == EM_AARCH64 ? "ARM AARCH64" :
           ehdr.e_machine == EM_MIPS ? "MIPS" : "Other");
    
    printf("  Version:                           0x%x\n", ehdr.e_version);
    printf("  Entry point address:               0x%lx\n", ehdr.e_entry);
    printf("  Start of program headers:          %ld (bytes into file)\n", ehdr.e_phoff);
    printf("  Start of section headers:          %ld (bytes into file)\n", ehdr.e_shoff);
    printf("  Flags:                             0x%x\n", ehdr.e_flags);
    printf("  Size of this header:               %d (bytes)\n", ehdr.e_ehsize);
    printf("  Size of program headers:           %d (bytes)\n", ehdr.e_phentsize);
    printf("  Number of program headers:         %d\n", ehdr.e_phnum);
    printf("  Size of section headers:           %d (bytes)\n", ehdr.e_shentsize);
    printf("  Number of section headers:         %d\n", ehdr.e_shnum);
    printf("  Section header string table index: %d\n", ehdr.e_shstrndx);
    printf("\n");
}

void print_program_headers(Elf *elf) {
    GElf_Phdr phdr;
    size_t phnum;
    int i;
    
    if (elf_getphdrnum(elf, &phnum) != 0) {
        fprintf(stderr, "Failed to get program header count: %s\n", elf_errmsg(-1));
        return;
    }
    
    printf("There are %d program headers, starting at offset 0x%lx\n\n", (int)phnum, phnum);
    
    printf("Program Headers:\n");
    printf("  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align\n");
    
    for (i = 0; i < phnum; i++) {
        if (gelf_getphdr(elf, i, &phdr) != &phdr) {
            fprintf(stderr, "Failed to get program header %d: %s\n", i, elf_errmsg(-1));
            continue;
        }
        
        printf("  ");
        switch (phdr.p_type) {
            case PT_NULL: printf("NULL           "); break;
            case PT_LOAD: printf("LOAD           "); break;
            case PT_DYNAMIC: printf("DYNAMIC        "); break;
            case PT_INTERP: printf("INTERP         "); break;
            case PT_NOTE: printf("NOTE           "); break;
            case PT_SHLIB: printf("SHLIB          "); break;
            case PT_PHDR: printf("PHDR           "); break;
            case PT_TLS: printf("TLS            "); break;
            case PT_GNU_EH_FRAME: printf("GNU_EH_FRAME  "); break;
            case PT_GNU_STACK: printf("GNU_STACK      "); break;
            case PT_GNU_RELRO: printf("GNU_RELRO      "); break;
            default: printf("0x%-12x ", phdr.p_type); break;
        }
        
        printf("0x%06lx ", phdr.p_offset);
        printf("0x%08lx ", phdr.p_vaddr);
        printf("0x%08lx ", phdr.p_paddr);
        printf("0x%05lx ", phdr.p_filesz);
        printf("0x%05lx ", phdr.p_memsz);
        
        printf("%c%c%c ", 
               phdr.p_flags & PF_R ? 'R' : ' ',
               phdr.p_flags & PF_W ? 'W' : ' ',
               phdr.p_flags & PF_X ? 'E' : ' ');
        
        printf("0x%lx\n", phdr.p_align);
    }
    printf("\n");
}

void print_section_headers(Elf *elf) {
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;
    char *name;
    
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        fprintf(stderr, "Failed to get section header string table index: %s\n", elf_errmsg(-1));
        return;
    }
    
    printf("Section Headers:\n");
    printf("  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al\n");
    
    int i = 0;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            fprintf(stderr, "Failed to get section header %d: %s\n", i, elf_errmsg(-1));
            continue;
        }
        
        name = elf_strptr(elf, shstrndx, shdr.sh_name);
        if (name == NULL) {
            fprintf(stderr, "Failed to get section name %d: %s\n", i, elf_errmsg(-1));
            continue;
        }
        
        printf("  [%2d] %-17s ", i, name);
        
        switch (shdr.sh_type) {
            case SHT_NULL: printf("NULL            "); break;
            case SHT_PROGBITS: printf("PROGBITS        "); break;
            case SHT_SYMTAB: printf("SYMTAB          "); break;
            case SHT_STRTAB: printf("STRTAB          "); break;
            case SHT_RELA: printf("RELA            "); break;
            case SHT_HASH: printf("HASH            "); break;
            case SHT_DYNAMIC: printf("DYNAMIC         "); break;
            case SHT_NOTE: printf("NOTE            "); break;
            case SHT_NOBITS: printf("NOBITS          "); break;
            case SHT_REL: printf("REL             "); break;
            case SHT_SHLIB: printf("SHLIB           "); break;
            case SHT_DYNSYM: printf("DYNSYM          "); break;
            case SHT_INIT_ARRAY: printf("INIT_ARRAY      "); break;
            case SHT_FINI_ARRAY: printf("FINI_ARRAY      "); break;
            case SHT_PREINIT_ARRAY: printf("PREINIT_ARRAY   "); break;
            case SHT_GROUP: printf("GROUP           "); break;
            case SHT_SYMTAB_SHNDX: printf("SYMTAB_SHNDX    "); break;
            case SHT_GNU_HASH: printf("GNU_HASH        "); break;
            case SHT_GNU_LIBLIST: printf("GNU_LIBLIST     "); break;
            case SHT_GNU_verdef: printf("GNU_verdef      "); break;
            case SHT_GNU_verneed: printf("GNU_verneed     "); break;
            case SHT_GNU_versym: printf("GNU_versym      "); break;
            default: printf("0x%-14x ", shdr.sh_type); break;
        }
        
        printf("0x%014lx ", shdr.sh_addr);
        printf("%06lx ", shdr.sh_offset);
        printf("%06lx ", shdr.sh_size);
        printf("%02lx ", shdr.sh_entsize);
        
        printf("%c%c%c ", 
               shdr.sh_flags & SHF_WRITE ? 'W' : ' ',
               shdr.sh_flags & SHF_ALLOC ? 'A' : ' ',
               shdr.sh_flags & SHF_EXECINSTR ? 'X' : ' ');
        
        printf("%2d ", shdr.sh_link);
        printf("%3d ", shdr.sh_info);
        printf("%2ld\n", shdr.sh_addralign);
        
        i++;
    }
    printf("\n");
}

void print_symbols(Elf *elf) {
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    Elf_Data *data;
    size_t shstrndx, num_symbols;
    GElf_Sym sym;
    char *name;
    int i, is_dynsym = 0;
    
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        fprintf(stderr, "Failed to get section header string table index: %s\n", elf_errmsg(-1));
        return;
    }
    
    // Find symbol tables
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            fprintf(stderr, "Failed to get section header: %s\n", elf_errmsg(-1));
            continue;
        }
        
        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
            is_dynsym = (shdr.sh_type == SHT_DYNSYM);
            
            data = elf_getdata(scn, NULL);
            if (data == NULL) {
                fprintf(stderr, "Failed to get section data: %s\n", elf_errmsg(-1));
                continue;
            }
            
            num_symbols = shdr.sh_size / shdr.sh_entsize;
            
            printf("\nSymbol table '%s' contains %zu entries:\n", 
                   elf_strptr(elf, shstrndx, shdr.sh_name), num_symbols);
            printf("   Num:    Value          Size Type    Bind   Vis      Ndx Name\n");
            
            for (i = 0; i < num_symbols; i++) {
                if (gelf_getsym(data, i, &sym) != &sym) {
                    fprintf(stderr, "Failed to get symbol %d: %s\n", i, elf_errmsg(-1));
                    continue;
                }
                
                name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (name == NULL) {
                    fprintf(stderr, "Failed to get symbol name %d: %s\n", i, elf_errmsg(-1));
                    continue;
                }
                
                printf("%6d: %016lx %5lu ", i, sym.st_value, sym.st_size);
                
                // Print symbol type
                switch (GELF_ST_TYPE(sym.st_info)) {
                    case STT_NOTYPE: printf("NOTYPE  "); break;
                    case STT_OBJECT: printf("OBJECT  "); break;
                    case STT_FUNC: printf("FUNC    "); break;
                    case STT_SECTION: printf("SECTION "); break;
                    case STT_FILE: printf("FILE    "); break;
                    case STT_COMMON: printf("COMMON  "); break;
                    case STT_TLS: printf("TLS     "); break;
                    default: printf("0x%-6x ", GELF_ST_TYPE(sym.st_info)); break;
                }
                
                // Print symbol binding
                switch (GELF_ST_BIND(sym.st_info)) {
                    case STB_LOCAL: printf("LOCAL  "); break;
                    case STB_GLOBAL: printf("GLOBAL "); break;
                    case STB_WEAK: printf("WEAK   "); break;
                    default: printf("0x%-6x ", GELF_ST_BIND(sym.st_info)); break;
                }
                
                // Print symbol visibility
                switch (GELF_ST_VISIBILITY(sym.st_other)) {
                    case STV_DEFAULT: printf("DEFAULT  "); break;
                    case STV_INTERNAL: printf("INTERNAL "); break;
                    case STV_HIDDEN: printf("HIDDEN   "); break;
                    case STV_PROTECTED: printf("PROTECTED"); break;
                    default: printf("0x%-8x ", GELF_ST_VISIBILITY(sym.st_other)); break;
                }
                
                // Print section index or special name
                if (sym.st_shndx == SHN_UNDEF) {
                    printf(" UND");
                } else if (sym.st_shndx == SHN_ABS) {
                    printf(" ABS");
                } else if (sym.st_shndx == SHN_COMMON) {
                    printf(" COM");
                } else {
                    printf("%4d", sym.st_shndx);
                }
                
                printf(" %s\n", name);
            }
        }
    }
}

void print_relocations(Elf *elf) {
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    Elf_Data *data;
    size_t shstrndx, num_relocs;
    GElf_Rela rela;
    GElf_Rel rel;
    char *name;
    int i, is_rela = 0;
    
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        fprintf(stderr, "Failed to get section header string table index: %s\n", elf_errmsg(-1));
        return;
    }
    
    // Find relocation tables
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            fprintf(stderr, "Failed to get section header: %s\n", elf_errmsg(-1));
            continue;
        }
        
        if (shdr.sh_type == SHT_REL || shdr.sh_type == SHT_RELA) {
            is_rela = (shdr.sh_type == SHT_RELA);
            
            data = elf_getdata(scn, NULL);
            if (data == NULL) {
                fprintf(stderr, "Failed to get section data: %s\n", elf_errmsg(-1));
                continue;
            }
            
            num_relocs = shdr.sh_size / shdr.sh_entsize;
            
            printf("\nRelocation section '%s' at offset 0x%lx contains %zu entries:\n", 
                   elf_strptr(elf, shstrndx, shdr.sh_name), shdr.sh_offset, num_relocs);
            
            if (is_rela) {
                printf("  Offset          Info           Type           Sym. Value    Sym. Name + Addend\n");
                
                for (i = 0; i < num_relocs; i++) {
                    if (gelf_getrela(data, i, &rela) != &rela) {
                        fprintf(stderr, "Failed to get relocation %d: %s\n", i, elf_errmsg(-1));
                        continue;
                    }
                    
                    printf("  %016lx %016lx ", rela.r_offset, rela.r_info);
                    
                    // Print relocation type (simplified for x86/x64)
                    switch (GELF_R_TYPE(rela.r_info)) {
                        case R_X86_64_NONE: printf("R_X86_64_NONE   "); break;
                        case R_X86_64_64: printf("R_X86_64_64     "); break;
                        case R_X86_64_PC32: printf("R_X86_64_PC32   "); break;
                        case R_X86_64_GOT32: printf("R_X86_64_GOT32  "); break;
                        case R_X86_64_PLT32: printf("R_X86_64_PLT32  "); break;
                        case R_X86_64_COPY: printf("R_X86_64_COPY   "); break;
                        case R_X86_64_GLOB_DAT: printf("R_X86_64_GLOB_DA"); break;
                        case R_X86_64_JUMP_SLOT: printf("R_X86_64_JUMP_SL"); break;
                        case R_X86_64_RELATIVE: printf("R_X86_64_RELATIV"); break;
                        case R_X86_64_GOTPCREL: printf("R_X86_64_GOTPCRE"); break;
                        case R_X86_64_32: printf("R_X86_64_32     "); break;
                        case R_X86_64_32S: printf("R_X86_64_32S    "); break;
                        default: printf("0x%-14lx ", GELF_R_TYPE(rela.r_info)); break;
                    }
                    
                    // Get symbol name and value
                    Elf_Scn *sym_scn = elf_getscn(elf, shdr.sh_link);
                    if (sym_scn == NULL) {
                        fprintf(stderr, "Failed to get symbol section: %s\n", elf_errmsg(-1));
                        continue;
                    }
                    
                    GElf_Shdr sym_shdr;
                    if (gelf_getshdr(sym_scn, &sym_shdr) != &sym_shdr) {
                        fprintf(stderr, "Failed to get symbol section header: %s\n", elf_errmsg(-1));
                        continue;
                    }
                    
                    Elf_Data *sym_data = elf_getdata(sym_scn, NULL);
                    if (sym_data == NULL) {
                        fprintf(stderr, "Failed to get symbol section data: %s\n", elf_errmsg(-1));
                        continue;
                    }
                    
                    GElf_Sym sym;
                    if (gelf_getsym(sym_data, GELF_R_SYM(rela.r_info), &sym) != &sym) {
                        fprintf(stderr, "Failed to get symbol: %s\n", elf_errmsg(-1));
                        continue;
                    }
                    
                    printf("0x%016lx ", sym.st_value);
                    
                    name = elf_strptr(elf, sym_shdr.sh_link, sym.st_name);
                    if (name == NULL) {
                        printf("(no name) + 0x%lx\n", rela.r_addend);
                        continue;
                    }
                    
                    printf("%s + 0x%lx\n", name, rela.r_addend);
                }
            } else {
                printf("  Offset          Info           Type           Sym. Value    Sym. Name\n");
                
                for (i = 0; i < num_relocs; i++) {
                    if (gelf_getrel(data, i, &rel) != &rel) {
                        fprintf(stderr, "Failed to get relocation %d: %s\n", i, elf_errmsg(-1));
                        continue;
                    }
                    
                    printf("  %016lx %016lx ", rel.r_offset, rel.r_info);
                    
                    // Print relocation type (simplified for x86/x64)
                    switch (GELF_R_TYPE(rel.r_info)) {
                        case R_X86_64_NONE: printf("R_X86_64_NONE   "); break;
                        case R_X86_64_64: printf("R_X86_64_64     "); break;
                        case R_X86_64_PC32: printf("R_X86_64_PC32   "); break;
                        case R_X86_64_GOT32: printf("R_X86_64_GOT32  "); break;
                        case R_X86_64_PLT32: printf("R_X86_64_PLT32  "); break;
                        case R_X86_64_COPY: printf("R_X86_64_COPY   "); break;
                        case R_X86_64_GLOB_DAT: printf("R_X86_64_GLOB_DA"); break;
                        case R_X86_64_JUMP_SLOT: printf("R_X86_64_JUMP_SL"); break;
                        case R_X86_64_RELATIVE: printf("R_X86_64_RELATIV"); break;
                        case R_X86_64_GOTPCREL: printf("R_X86_64_GOTPCRE"); break;
                        case R_X86_64_32: printf("R_X86_64_32     "); break;
                        case R_X86_64_32S: printf("R_X86_64_32S    "); break;
                        default: printf("0x%-14lx ", GELF_R_TYPE(rel.r_info)); break;
                    }
                    
                    // Get symbol name and value
                    Elf_Scn *sym_scn = elf_getscn(elf, shdr.sh_link);
                    if (sym_scn == NULL) {
                        fprintf(stderr, "Failed to get symbol section: %s\n", elf_errmsg(-1));
                        continue;
                    }
                    
                    GElf_Shdr sym_shdr;
                    if (gelf_getshdr(sym_scn, &sym_shdr) != &sym_shdr) {
                        fprintf(stderr, "Failed to get symbol section header: %s\n", elf_errmsg(-1));
                        continue;
                    }
                    
                    Elf_Data *sym_data = elf_getdata(sym_scn, NULL);
                    if (sym_data == NULL) {
                        fprintf(stderr, "Failed to get symbol section data: %s\n", elf_errmsg(-1));
                        continue;
                    }
                    
                    GElf_Sym sym;
                    if (gelf_getsym(sym_data, GELF_R_SYM(rel.r_info), &sym) != &sym) {
                        fprintf(stderr, "Failed to get symbol: %s\n", elf_errmsg(-1));
                        continue;
                    }
                    
                    printf("0x%016lx ", sym.st_value);
                    
                    name = elf_strptr(elf, sym_shdr.sh_link, sym.st_name);
                    if (name == NULL) {
                        printf("(no name)\n");
                        continue;
                    }
                    
                    printf("%s\n", name);
                }
            }
        }
    }
}

void print_dynamic_section(Elf *elf) {
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    Elf_Data *data;
    size_t shstrndx, num_entries;
    GElf_Dyn dyn;
    char *name;
    int i;
    
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        fprintf(stderr, "Failed to get section header string table index: %s\n", elf_errmsg(-1));
        return;
    }
    
    // Find dynamic section
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            fprintf(stderr, "Failed to get section header: %s\n", elf_errmsg(-1));
            continue;
        }
        
        if (shdr.sh_type == SHT_DYNAMIC) {
            data = elf_getdata(scn, NULL);
            if (data == NULL) {
                fprintf(stderr, "Failed to get section data: %s\n", elf_errmsg(-1));
                continue;
            }
            
            num_entries = shdr.sh_size / shdr.sh_entsize;
            
            printf("\nDynamic section at offset 0x%lx contains %zu entries:\n", 
                   shdr.sh_offset, num_entries);
            printf("  Tag        Type                         Name/Value\n");
            
            for (i = 0; i < num_entries; i++) {
                if (gelf_getdyn(data, i, &dyn) != &dyn) {
                    fprintf(stderr, "Failed to get dynamic entry %d: %s\n", i, elf_errmsg(-1));
                    continue;
                }
                
                printf("  0x%08lx ", dyn.d_tag);
                
                // Print dynamic entry type
                switch (dyn.d_tag) {
                    case DT_NULL: printf("DT_NULL                       "); break;
                    case DT_NEEDED: printf("DT_NEEDED                     "); break;
                    case DT_PLTRELSZ: printf("DT_PLTRELSZ                   "); break;
                    case DT_PLTGOT: printf("DT_PLTGOT                     "); break;
                    case DT_HASH: printf("DT_HASH                       "); break;
                    case DT_STRTAB: printf("DT_STRTAB                     "); break;
                    case DT_SYMTAB: printf("DT_SYMTAB                     "); break;
                    case DT_RELA: printf("DT_RELA                       "); break;
                    case DT_RELASZ: printf("DT_RELASZ                     "); break;
                    case DT_RELAENT: printf("DT_RELAENT                    "); break;
                    case DT_STRSZ: printf("DT_STRSZ                      "); break;
                    case DT_SYMENT: printf("DT_SYMENT                     "); break;
                    case DT_INIT: printf("DT_INIT                       "); break;
                    case DT_FINI: printf("DT_FINI                       "); break;
                    case DT_SONAME: printf("DT_SONAME                     "); break;
                    case DT_RPATH: printf("DT_RPATH                      "); break;
                    case DT_SYMBOLIC: printf("DT_SYMBOLIC                   "); break;
                    case DT_REL: printf("DT_REL                        "); break;
                    case DT_RELSZ: printf("DT_RELSZ                      "); break;
                    case DT_RELENT: printf("DT_RELENT                     "); break;
                    case DT_PLTREL: printf("DT_PLTREL                     "); break;
                    case DT_DEBUG: printf("DT_DEBUG                      "); break;
                    case DT_TEXTREL: printf("DT_TEXTREL                    "); break;
                    case DT_JMPREL: printf("DT_JMPREL                     "); break;
                    case DT_BIND_NOW: printf("DT_BIND_NOW                   "); break;
                    case DT_INIT_ARRAY: printf("DT_INIT_ARRAY                 "); break;
                    case DT_FINI_ARRAY: printf("DT_FINI_ARRAY                 "); break;
                    case DT_INIT_ARRAYSZ: printf("DT_INIT_ARRAYSZ               "); break;
                    case DT_FINI_ARRAYSZ: printf("DT_FINI_ARRAYSZ               "); break;
                    case DT_RUNPATH: printf("DT_RUNPATH                    "); break;
                    case DT_FLAGS: printf("DT_FLAGS                      "); break;
                    case DT_PREINIT_ARRAY: printf("DT_PREINIT_ARRAY              "); break;
                    case DT_PREINIT_ARRAYSZ: printf("DT_PREINIT_ARRAYSZ            "); break;
                    case DT_GNU_HASH: printf("DT_GNU_HASH                   "); break;
                    case DT_VERSYM: printf("DT_VERSYM                     "); break;
                    case DT_RELACOUNT: printf("DT_RELACOUNT                  "); break;
                    case DT_RELCOUNT: printf("DT_RELCOUNT                   "); break;
                    case DT_FLAGS_1: printf("DT_FLAGS_1                    "); break;
                    case DT_VERDEF: printf("DT_VERDEF                     "); break;
                    case DT_VERDEFNUM: printf("DT_VERDEFNUM                  "); break;
                    case DT_VERNEED: printf("DT_VERNEED                    "); break;
                    case DT_VERNEEDNUM: printf("DT_VERNEEDNUM                 "); break;
                    default: printf("0x%-27lx ", dyn.d_tag); break;
                }
                
                // Print name or value
                if (dyn.d_tag == DT_NEEDED || dyn.d_tag == DT_SONAME || 
                    dyn.d_tag == DT_RPATH || dyn.d_tag == DT_RUNPATH) {
                    name = elf_strptr(elf, shdr.sh_link, dyn.d_un.d_val);
                    if (name == NULL) {
                        printf("(no name)\n");
                        continue;
                    }
                    printf("%s\n", name);
                } else if (dyn.d_tag == DT_INIT || dyn.d_tag == DT_FINI || 
                          dyn.d_tag == DT_HASH || dyn.d_tag == DT_STRTAB || 
                          dyn.d_tag == DT_SYMTAB || dyn.d_tag == DT_RELA || 
                          dyn.d_tag == DT_REL || dyn.d_tag == DT_JMPREL || 
                          dyn.d_tag == DT_INIT_ARRAY || dyn.d_tag == DT_FINI_ARRAY || 
                          dyn.d_tag == DT_GNU_HASH || dyn.d_tag == DT_VERSYM || 
                          dyn.d_tag == DT_VERDEF || dyn.d_tag == DT_VERNEED) {
                    printf("0x%lx\n", dyn.d_un.d_ptr);
                } else {
                    printf("%ld\n", dyn.d_un.d_val);
                }
            }
        }
    }
}

void disassemble_code(Elf *elf, const char *section_name) {
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    Elf_Data *data = NULL;
    size_t shstrndx;
    csh handle;
    cs_insn *insns = NULL;
    size_t count;
    GElf_Ehdr ehdr;
    cs_mode mode = 0;
    cs_arch arch;
    int found_section = 0;
    
    // Get ELF header
    if (gelf_getehdr(elf, &ehdr) == NULL) {
        fprintf(stderr, "Failed to get ELF header: %s\n", elf_errmsg(-1));
        return;
    }
    
    // Get section header string table index
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        fprintf(stderr, "Failed to get section header string table index: %s\n", elf_errmsg(-1));
        return;
    }
    
    // Determine architecture
    switch (ehdr.e_machine) {
        case EM_386:
            arch = CS_ARCH_X86;
            mode = CS_MODE_32;
            break;
        case EM_X86_64:
            arch = CS_ARCH_X86;
            mode = CS_MODE_64;
            break;
        case EM_ARM:
            arch = CS_ARCH_ARM;
            mode = (ehdr.e_ident[EI_DATA] == ELFDATA2LSB) ? CS_MODE_ARM : CS_MODE_ARM + CS_MODE_BIG_ENDIAN;
            break;
        case EM_AARCH64:
            arch = CS_ARCH_ARM64;
            mode = (ehdr.e_ident[EI_DATA] == ELFDATA2LSB) ? CS_MODE_LITTLE_ENDIAN : CS_MODE_BIG_ENDIAN;
            break;
        case EM_MIPS:
        case EM_MIPS_RS3_LE:
        case EM_MIPS_X:
            arch = CS_ARCH_MIPS;
            mode = (ehdr.e_ident[EI_CLASS] == ELFCLASS32) ? CS_MODE_MIPS32 : CS_MODE_MIPS64;
            mode |= (ehdr.e_ident[EI_DATA] == ELFDATA2LSB) ? CS_MODE_LITTLE_ENDIAN : CS_MODE_BIG_ENDIAN;
            break;
        case EM_PPC:
            arch = CS_ARCH_PPC;
            mode = CS_MODE_32 + CS_MODE_BIG_ENDIAN;
            break;
        case EM_PPC64:
            arch = CS_ARCH_PPC;
            mode = CS_MODE_64 + CS_MODE_BIG_ENDIAN;
            break;
        case EM_SPARC:
        case EM_SPARC32PLUS:
        case EM_SPARCV9:
            arch = CS_ARCH_SPARC;
            mode = CS_MODE_V9 + CS_MODE_BIG_ENDIAN;
            break;
        default:
            fprintf(stderr, "Unsupported architecture: %d\n", ehdr.e_machine);
            return;
    }
    
    // Initialize Capstone
    if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone: %s\n", cs_strerror(cs_errno(handle)));
        return;
    }
    
    // Enable detail mode
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    // Find the specified section
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            fprintf(stderr, "Failed to get section header: %s\n", elf_errmsg(-1));
            continue;
        }
        
        char *name = elf_strptr(elf, shstrndx, shdr.sh_name);
        if (name == NULL) {
            fprintf(stderr, "Failed to get section name: %s\n", elf_errmsg(-1));
            continue;
        }
        
        if (strcmp(name, section_name) == 0 && shdr.sh_type == SHT_PROGBITS && 
            (shdr.sh_flags & SHF_EXECINSTR)) {
            found_section = 1;
            data = elf_getdata(scn, NULL);
            if (data == NULL || data->d_size == 0) {
                fprintf(stderr, "Failed to get section data for %s: %s\n", section_name, elf_errmsg(-1));
                cs_close(&handle);
                return;
            }
            
            printf("\nDisassembly of section %s:\n", section_name);
            printf("0x%016lx <%s>:\n", shdr.sh_addr, section_name);
            
            // Disassemble the code
            count = cs_disasm(handle, (uint8_t *)data->d_buf, data->d_size, shdr.sh_addr, 0, &insns);
            if (count > 0) {
                for (size_t j = 0; j < count; j++) {
                    printf("   %016lx: ", insns[j].address);
                    
                    // Print instruction bytes
                    for (int k = 0; k < insns[j].size; k++) {
                        printf("%02x ", insns[j].bytes[k]);
                    }
                    
                    // Pad with spaces for alignment
                    for (int k = insns[j].size; k < 16; k++) {
                        printf("   ");
                    }
                    
                    // Print instruction mnemonic and operands
                    printf("%-10s %s\n", insns[j].mnemonic, insns[j].op_str);
                }
                
                cs_free(insns, count);
            } else {
                fprintf(stderr, "Failed to disassemble code in section %s: %s\n", 
                        section_name, cs_strerror(cs_errno(handle)));
            }
            
            break;
        }
    }
    
    if (!found_section) {
        fprintf(stderr, "Section %s not found or not executable\n", section_name);
    }
    
    // Close Capstone
    cs_close(&handle);
}