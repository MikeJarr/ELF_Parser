#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <elf.h>
#include <stdbool.h>

bool is_elf_64_file(FILE* fp)
{
	char e_ident[EI_NIDENT];
	fread(e_ident, EI_NIDENT, 1, fp);
	if(0 != strncmp(e_ident, "\177ELF", 4))
	{
		printf("Not an elf file (wrong magic)");
		return false;
	}
	
	if(2 != e_ident[EI_CLASS])	
	{
		printf("Not a 64-bit file (I can't be bothered with that)");
		return false;
	}

	return true;
}

void read_elf_header(FILE* fp, Elf64_Ehdr* e_header)
{
	fseek(fp, 0, SEEK_SET);
	fread(e_header, sizeof(Elf64_Ehdr), 1, fp);

	unsigned char* char_cast = (unsigned char*)e_header;
	printf("Elf header: \n");
	for(int i = 0; i < sizeof(Elf64_Ehdr); i++)
	{
		printf("%02x ", char_cast[i]);
	}
	printf("\n");

}
void read_sh_table(FILE* fp, Elf64_Ehdr* e_header, Elf64_Shdr* sh_table)
{
	Elf64_Off e_shoff = e_header->e_shoff;	
	fseek(fp, e_shoff, SEEK_SET);
	size_t num_bytes = e_header->e_shnum * e_header->e_shentsize;
	fread(sh_table, num_bytes, 1, fp); 

	return;
}

char* read_section(FILE* fp, Elf64_Shdr* section_header)
{
	Elf64_Off offset = section_header->sh_offset;	
	size_t section_size = section_header->sh_size;
	char* section = malloc(section_size);
	fseek(fp, offset, SEEK_SET);
	fread(section, section_size, 1, fp);	

	return section;
}

void print_string_table(char* string_table, size_t length)
{
	for(int i = 1; i < length; i++)
	{
		if(string_table[i-1] == 0)
		{
			printf("%s\n", &string_table[i]);
		}
	}
}

void process_relocations
	(
	FILE* fp,
	Elf64_Shdr* sh_table,
	Elf64_Rela* rela_table,
	Elf64_Shdr* rel_hdr,
	char* dynstr
	)
{
	
	size_t sym_tab_idx = rel_hdr->sh_link;
	printf("sym tab idx = %i\n", sym_tab_idx);
	size_t sec_to_rel_idx = rel_hdr->sh_info;

	Elf64_Sym* sym_tab = (Elf64_Sym*) read_section(fp, &sh_table[sym_tab_idx]);
	char* sec_to_rel = read_section(fp, &sh_table[sec_to_rel_idx]);

	size_t num_rels = rel_hdr->sh_size / rel_hdr->sh_entsize;	

	printf("num_rels = %i\n", num_rels);

	for(int i = 0; i < num_rels; i++)
	{
		Elf64_Rela* relocation = &rela_table[i];
		size_t offset = relocation->r_offset;
		size_t sym_idx = ELF64_R_SYM(relocation->r_info);
		size_t reloc_type = ELF64_R_TYPE(relocation->r_info);

		Elf64_Sym* symbol = &sym_tab[sym_idx];
		Elf64_Word sym_name_idx = symbol->st_name;
		char* sym_name = &dynstr[sym_name_idx];
		printf("Current symbol name: %s\n", sym_name);

	}	
	
	free(sym_tab);
	free(sec_to_rel);

}

void process_sections(FILE* fp, Elf64_Shdr* sh_table, Elf64_Ehdr* e_header)
{
	char* sh_string_table = read_section(fp, &sh_table[e_header->e_shstrndx]);

	size_t num_sections = e_header->e_shnum;

	char* dynstr;

	for(size_t i = 0; i < num_sections; i++)
	{
		char* cur_section = read_section(fp, &sh_table[i]);	
		size_t name_index = sh_table[i].sh_name;
		char* sec_name = &sh_string_table[name_index];

		if (!strcmp(sec_name, ".dynstr"))
		{
			dynstr = cur_section;
			break;
		}
		
		free(cur_section);
	}


	for(size_t i = 0; i < num_sections; i++)
	{
		char* cur_section = read_section(fp, &sh_table[i]);	
		size_t name_index = sh_table[i].sh_name;
		//printf("Processing section %s\n", &sh_string_table[name_index]);

		switch(sh_table[i].sh_type)
		{
			case SHT_STRTAB:
				//print_string_table(cur_section, sh_table[i].sh_size);
				break;
			case SHT_RELA:
					
				Elf64_Rela* rela_table = (Elf64_Rela*)cur_section;
				process_relocations(fp, sh_table, rela_table, &sh_table[i], dynstr);
				break;
			default:
				//printf("Section not yet implemented\n");
				break;
		}
		//printf("\n");
		free(cur_section);	
	}	
	free(sh_string_table);
	free(dynstr);
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("Provide a filename");
        return 1;
    }

    FILE* fp = fopen(argv[1], "r");
    if (NULL == fp)
    {
		printf("File \"%s\" doesn't exist", argv[1]);    
		return 1;
    }

	if(false == is_elf_64_file(fp))
	{
		return 1;
	}	

	Elf64_Ehdr e_header; // No need to malloc because we know the size.
						 // This way e_header lives on the stack.
	read_elf_header(fp, &e_header);

	Elf64_Shdr* sh_table = malloc(e_header.e_shnum * e_header.e_shentsize);
	read_sh_table(fp, &e_header, sh_table);

	process_sections(fp, sh_table, &e_header);


	// MIKE MAKE SURE YOU FREE
	free(sh_table);
	return 0;
}

