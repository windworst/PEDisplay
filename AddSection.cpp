#include "PE.h"

#define BUFF_LEN 1048576
void cpFile(FILE* in,FILE* out)
{
  char buff[BUFF_LEN];
  int nread = sizeof(buff);
  while( nread == sizeof(buff) )
  {
    nread = fread(buff,1,nread,in);
    fwrite(buff,1,nread,out);
  }
}

DWORD alignment(DWORD value, DWORD align)
{
  return (value + align - 1) / align * align;
}

void addSectionToExecuteFile(PE& pe, FILE* in, FILE* out, const BYTE* sectionData, DWORD sectionDataLength)
{
  //get file size
  fseek(in,0,SEEK_END);
  DWORD fileSize = ftell(in);
  fseek(in,pe.getImageNtHeader()->OptionalHeader.SizeOfHeaders,SEEK_SET);

  //get pe head grow size
  DWORD headerGrowLength = 0;
  DWORD numberOfSections = pe.getImageNtHeader()->FileHeader.NumberOfSections;
  {
    DWORD sectionTableOffset = ((BYTE*)pe.getImageSectionHeaderTable()) - pe.peHeaderData.data();
    DWORD sectionTableTailOffset = sectionTableOffset + sizeof(IMAGE_SECTION_HEADER) * (numberOfSections + 1);
    while(sectionTableTailOffset >= pe.getImageNtHeader()->OptionalHeader.SizeOfHeaders + headerGrowLength)
    {
      headerGrowLength += pe.getImageNtHeader()->OptionalHeader.FileAlignment;
    }
  }

  //set section header
  DWORD AddSectionOffset = 0;
  {
    pe.getImageNtHeader()->OptionalHeader.SizeOfHeaders += headerGrowLength;
    pe.peHeaderData.resize(pe.getImageNtHeader()->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* sectionHeader = pe.getImageSectionHeaderTable();
    DWORD i;
    for(i=0; i<numberOfSections; ++i)
    {
      sectionHeader[i].PointerToRawData += headerGrowLength;
      DWORD sectionTailOffset = sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize;
      if ( AddSectionOffset < sectionTailOffset)
      {
        AddSectionOffset = sectionTailOffset;
      }
    }

    //SectionAlignment
    AddSectionOffset = alignment(AddSectionOffset, pe.getImageNtHeader()->OptionalHeader.SectionAlignment);
  }

  //set own section header
  DWORD jmpToOEPInstructionLength = 5;
  DWORD VirtualSize = sectionDataLength + jmpToOEPInstructionLength;
  DWORD pointToRawData = alignment( fileSize + headerGrowLength, pe.getImageNtHeader()->OptionalHeader.FileAlignment);
  {
    IMAGE_SECTION_HEADER* sectionHeader = pe.getImageSectionHeaderTable();
    IMAGE_SECTION_HEADER* addSectionHeader = sectionHeader + numberOfSections;
    strcpy((char*)addSectionHeader->Name, ".xbw");
    addSectionHeader->Misc.VirtualSize = VirtualSize;
    addSectionHeader->VirtualAddress = AddSectionOffset;
    addSectionHeader->SizeOfRawData = sectionDataLength + jmpToOEPInstructionLength;
    addSectionHeader->PointerToRawData = pointToRawData;
    addSectionHeader->PointerToLinenumbers = 0;
    addSectionHeader->NumberOfRelocations = 0;
    addSectionHeader->NumberOfLinenumbers = 0;
    addSectionHeader->Characteristics = 0X60500060;
  }

  //modify PE header value
  DWORD oep = pe.getImageNtHeader()->OptionalHeader.AddressOfEntryPoint;
  pe.getImageNtHeader()->OptionalHeader.AddressOfEntryPoint = AddSectionOffset;  //modify oep
  ++pe.getImageNtHeader()->FileHeader.NumberOfSections;
  pe.getImageNtHeader()->OptionalHeader.SizeOfImage = AddSectionOffset + alignment(sectionDataLength + jmpToOEPInstructionLength, pe.getImageNtHeader()->OptionalHeader.SectionAlignment);

  //write Pe Header
  fwrite(pe.peHeaderData.data(), 1, pe.peHeaderData.size(), out);

  //wirte section data
  cpFile(in,out);

  //file alignment
  fseek(out, pointToRawData, SEEK_SET );

  //write own section data
  if(sectionData!=NULL && sectionDataLength>0)
  {
    fwrite(sectionData, 1, sectionDataLength, out);
  }

  //jmp to oep
  fwrite("\xe9",1,1,out);
  DWORD jmpAddr = oep - AddSectionOffset - jmpToOEPInstructionLength;
  fwrite(&jmpAddr, sizeof(jmpAddr), 1, out);

  fflush(out);
}

void addSection(const char* inFile, const char* outFile)
{
  FILE* in = fopen(inFile,"rb");
  if(in == NULL)
  {
    fprintf(stderr,"read file %s error\n", inFile);
    return;
  }
  FILE* out = fopen(outFile,"wb");
  if(out == NULL)
  {
    fprintf(stderr,"write file %s error\n", outFile);
    fclose(in);
    return;
  }
  PE pe(in);
  int status = pe.status();
  if(status == PE::SUCCESS)
  {
    addSectionToExecuteFile(pe,in,out,NULL, 0);
  }
  else if(status == PE::READ_FAILED )
  {
    fprintf(stderr,"read file %s failed\n",inFile);
  }
  else
  {
    fprintf(stderr, "PE struct error\n");
  }
  fclose(in);
  fclose(out);
}

int main(int argc, char** argv)
{
  if(argc < 3)
  {
    fprintf(stderr,"usage: addSection.exe <pe file> <out file>\n");
    return 0;
  }
  addSection(argv[1],argv[2]);
  return 0;
}
