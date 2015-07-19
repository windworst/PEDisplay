#include <stdio.h>
#include <time.h>
#include <windows.h>
#include <winnt.h>

void indent(int n)
{
  while(n --> 0) putchar(' '),putchar(' ');
}

const char* windowsSubsystem(WORD subsystem)
{
  static WORD subsystemTypeList[]= {
    IMAGE_SUBSYSTEM_UNKNOWN,
    IMAGE_SUBSYSTEM_NATIVE,
    IMAGE_SUBSYSTEM_WINDOWS_GUI,
    IMAGE_SUBSYSTEM_WINDOWS_CUI,
    IMAGE_SUBSYSTEM_OS2_CUI,
    IMAGE_SUBSYSTEM_POSIX_CUI,
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS,
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI,
    IMAGE_SUBSYSTEM_EFI_APPLICATION,
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER,
    IMAGE_SUBSYSTEM_EFI_ROM,
    IMAGE_SUBSYSTEM_XBOX,
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION
  };
  static const char *subsystemList[]= {
    "IMAGE_SUBSYSTEM_UNKNOWN",
    "IMAGE_SUBSYSTEM_NATIVE",
    "IMAGE_SUBSYSTEM_WINDOWS_GUI",
    "IMAGE_SUBSYSTEM_WINDOWS_CUI",
    "IMAGE_SUBSYSTEM_OS2_CUI",
    "IMAGE_SUBSYSTEM_POSIX_CUI",
    "IMAGE_SUBSYSTEM_NATIVE_WINDOWS",
    "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
    "IMAGE_SUBSYSTEM_EFI_APPLICATION",
    "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
    "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
    "IMAGE_SUBSYSTEM_EFI_ROM",
    "IMAGE_SUBSYSTEM_XBOX",
    "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"
  };
  int i;
  for(i=0;i<sizeof(subsystemTypeList)/sizeof(*subsystemTypeList) && i<sizeof(subsystemList)/sizeof(*subsystemList); ++i)
  {
    if(subsystem == subsystemTypeList[i])
    {
      return subsystemList[i];
    }
  }
  return "subsystem type undefined";
}

const char* dataDirectoryField(int fieldIndex)
{
  static const char* fieldName[] = {
    "Export Table", "Import Table", "Resource Table", "Exception Table",
    "Certificate Table", "BaseRelocation Table", "Debug", "Architecure",
    "Global Ptr", "TLS Table", "Load Config Table", "Bound Import",
    "IAT", "Delay Import Descriptor", "CLR Runtime Header", "Reserved"
  };
  if(0<= fieldIndex && fieldIndex < (sizeof(fieldName)/sizeof(*fieldName)) )
  {
    return fieldName[fieldIndex];
  }
  return "Undefined";
}

void outputImageDosHeader(PIMAGE_DOS_HEADER pImageDosHeader, int indentLevel)
{
  indent(indentLevel),printf("IMAGE_DOS_HEADER (SIZE: %d)\n",sizeof(*pImageDosHeader));
  indent(indentLevel+1),printf("Magic: %04XH (require %04XH)\n",
      pImageDosHeader->e_magic,
      IMAGE_DOS_SIGNATURE);
  printf("\n");
}

void outputImageNtHeaders(PIMAGE_NT_HEADERS pImageNtHeader, int indentLevel)
{
  indent(indentLevel),printf("IMAGE_NT_HEADER (SIZE: %d)\n", sizeof(*pImageNtHeader));
  indent(indentLevel+1),printf("SIGNATURE: %04XH (require %04XH)\n", (unsigned int)(&pImageNtHeader->Signature), IMAGE_NT_SIGNATURE);
  printf("\n");
}

void outputImageFileHeader(PIMAGE_FILE_HEADER pImageFileHeader, int indentLevel)
{
  indent(indentLevel),printf("IMAGE_FILE_HEADER (SIZE: %d)\n",sizeof(*pImageFileHeader));
  indent(indentLevel+1),printf("Machine: %04XH\n",pImageFileHeader->Machine);
  indent(indentLevel+1),printf("NumberOfSections: %d\n",pImageFileHeader->NumberOfSections);

  char time_output[100]={0};
  strftime(time_output, sizeof(time_output), "%B-%d-%Y %H:%M:%S %A %Z",
      localtime((const time_t*)&pImageFileHeader->TimeDateStamp));
  indent(indentLevel+1),printf("TimeDateStamp: %ld (%s)\n", (time_t)pImageFileHeader->TimeDateStamp, time_output);
  indent(indentLevel+1),printf("PointerToSymbolTable: %lXH\n", pImageFileHeader->PointerToSymbolTable);
  indent(indentLevel+1),printf("NumberOfSymbols: %ld\n", pImageFileHeader->NumberOfSymbols);
  indent(indentLevel+1),printf("SizeOfOptionalHeader: %d\n", pImageFileHeader->SizeOfOptionalHeader);
  printf("\n");
}

void outputImageOptionalHeader(PIMAGE_OPTIONAL_HEADER pImageOptionalHeader, int indentLevel)
{
  indent(indentLevel),printf("OPTIONAL_HEADER (SIZE: %d)\n", sizeof(*pImageOptionalHeader));
  indent(indentLevel+1),printf("Magic: %04XH\n", pImageOptionalHeader->Magic);
  indent(indentLevel+1),printf("LinkVersion: %d.%d\n",
      pImageOptionalHeader->MajorLinkerVersion,
      pImageOptionalHeader->MinorLinkerVersion);
  indent(indentLevel+1),printf(".text size: %ld\n", pImageOptionalHeader->SizeOfCode);
  indent(indentLevel+1),printf(".data size: %ld\n", pImageOptionalHeader->SizeOfInitializedData);
  indent(indentLevel+1),printf(".bss size: %ld\n", pImageOptionalHeader->SizeOfUninitializedData);
  printf("\n");
  indent(indentLevel+1),printf("image size: %ld\n", pImageOptionalHeader->SizeOfImage);
  indent(indentLevel+1),printf("headers size: %ld\n", pImageOptionalHeader->SizeOfHeaders);
  indent(indentLevel+1),printf("ImageBase: %lXH\n", pImageOptionalHeader->ImageBase);

  indent(indentLevel+1),printf("EntryPoint: %lXH\n", pImageOptionalHeader->AddressOfEntryPoint);
  indent(indentLevel+1),printf("BaseOfCode: %lXH\n", pImageOptionalHeader->BaseOfCode);
  indent(indentLevel+1),printf("BaseOfData: %lXH\n", pImageOptionalHeader->BaseOfData);
  indent(indentLevel+1),printf("SectionAlignment: %lXH\n", pImageOptionalHeader->SectionAlignment);
  indent(indentLevel+1),printf("FileAlignment: %lXH\n", pImageOptionalHeader->FileAlignment);
  printf("\n");
  indent(indentLevel+1),printf("OS Version: %d.%d\n",
      pImageOptionalHeader->MajorOperatingSystemVersion,
      pImageOptionalHeader->MinorOperatingSystemVersion);
  indent(indentLevel+1),printf("Image Version: %d.%d\n",
      pImageOptionalHeader->MajorImageVersion,
      pImageOptionalHeader->MinorImageVersion);
  indent(indentLevel+1),printf("SubSytem Version: %d.%d\n",
      pImageOptionalHeader->MajorSubsystemVersion,
      pImageOptionalHeader->MinorSubsystemVersion);
  indent(indentLevel+1),printf("CheckSum: %04lXH\n", pImageOptionalHeader->CheckSum);
  indent(indentLevel+1),printf("Subsystem: %d (Type: %s)\n", pImageOptionalHeader->Subsystem, windowsSubsystem(pImageOptionalHeader->Subsystem));
  indent(indentLevel+1),printf("\n");
  indent(indentLevel+1),printf("SizeOfStackReserve: %ld\n", pImageOptionalHeader->SizeOfStackReserve);
  indent(indentLevel+1),printf("SizeOfStackCommit: %ld\n", pImageOptionalHeader->SizeOfStackCommit);
  indent(indentLevel+1),printf("SizeOfHeapReserve: %ld\n", pImageOptionalHeader->SizeOfHeapReserve);
  indent(indentLevel+1),printf("SizeOfHeapCommit: %ld\n", pImageOptionalHeader->SizeOfHeapCommit);
  indent(indentLevel+1),printf("NumberOfRvaAndSizes: %ld\n", pImageOptionalHeader->NumberOfRvaAndSizes);

  {
    printf("\n");
    indent(indentLevel+1),printf("DataDirectory:\n");
    indent(indentLevel+2),printf("   VA         SIZE       DESCRIPT\n");
    indent(indentLevel+2),printf("--------------------------------------\n");
    int i;
    for(i=0;i<pImageOptionalHeader->NumberOfRvaAndSizes;++i)
    {
      PIMAGE_DATA_DIRECTORY p_image_data_directory = pImageOptionalHeader->DataDirectory + i;
      indent(indentLevel+2),printf("%08lxH  %08lxH   %s\n", p_image_data_directory->VirtualAddress, p_image_data_directory->Size, dataDirectoryField(i));
    }
  }
  printf("\n");
}

void outputImageSectionHeaders(PIMAGE_SECTION_HEADER pImageSectionHeaders, int headerCount, int indentLevel)
{
  indent(indentLevel),printf("SECTION_TABLE:\n");
  indent(indentLevel+1),
    printf("%-5s%-8s    %-8s    %-8s   %-8s   %-8s    %-8s %-8s %-8s %-8s %-8s\n\n",
      "No", "Name", "[V addr", "V size]", "[R addr", "R size]", "[reloc", "num]", "[linenum", "num]", "Flag");
  indent(indentLevel+1),
    printf("-----------------------------------------------------------------------------------------------------------\n");
  int i;
  for(i=0; i<headerCount; ++i)
  {
    PIMAGE_SECTION_HEADER pImageSectionHeader = pImageSectionHeaders+i;
    indent(indentLevel+1),
    printf("%-5d",i+1),
    printf("%-*.*s  ",IMAGE_SIZEOF_SHORT_NAME, IMAGE_SIZEOF_SHORT_NAME, pImageSectionHeader->Name),
    printf("%8lXH  ", pImageSectionHeader->VirtualAddress),
    printf("%8lXH  ", pImageSectionHeader->Misc.VirtualSize),
    printf("%8lXH  ", pImageSectionHeader->PointerToRawData),
    printf("%8lXH  ", pImageSectionHeader->SizeOfRawData),
    printf("%8lXH  ", pImageSectionHeader->PointerToRelocations),
    printf("%4XH   ", pImageSectionHeader->NumberOfRelocations),
    printf("%8lXH ", pImageSectionHeader->PointerToLinenumbers),
    printf("%4XH    ", pImageSectionHeader->NumberOfLinenumbers),
    printf("%8lXH  ", pImageSectionHeader->Characteristics),
    printf("\n");
  }
}

void loadPeFile(FILE* file)
{
  //DOS HEAD
  IMAGE_DOS_HEADER imageDosHeader;
  fread(&imageDosHeader, sizeof(imageDosHeader), 1, file);

  //NT_HEADER
  IMAGE_NT_HEADERS imageNtHeader;
  fseek(file, imageDosHeader.e_lfanew, SEEK_SET);
  fread(&imageNtHeader, sizeof(imageNtHeader), 1, file);

  //OUTPUT
  outputImageDosHeader(&imageDosHeader, 0);
  outputImageNtHeaders(&imageNtHeader, 0);
  outputImageFileHeader(&imageNtHeader.FileHeader, 1);
  outputImageOptionalHeader(&imageNtHeader.OptionalHeader, 1);


  //SECTION_TABLE
  PIMAGE_SECTION_HEADER image_section_header_list =
    (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER)*imageNtHeader.FileHeader.NumberOfSections);
  fread(image_section_header_list, sizeof(IMAGE_SECTION_HEADER), imageNtHeader.FileHeader.NumberOfSections, file);
  outputImageSectionHeaders(image_section_header_list, imageNtHeader.FileHeader.NumberOfSections, 0);
  free(image_section_header_list);

}

void peDisplay(const char* file_path)
{
  FILE* file = fopen(file_path,"rb");
  if(file==NULL)
  {
    fprintf(stderr,"open file %s failed\n",file_path);
    return;
  }
  loadPeFile(file);
  fclose(file);
}

int main(int argc, char** argv)
{
  if(argc < 2)
  {
    fprintf(stderr,"usage: peDisplay.exe <pe file>\n");
    return 0;
  }
  peDisplay(argv[1]);
  return 0;
}
