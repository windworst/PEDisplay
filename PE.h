#pragma once

#include <windows.h>
#include <winnt.h>
#include <stdio.h>

#include <vector>
using std::vector;

class PE
{
public:
  vector<BYTE> peHeaderData;
  enum LOAD_STATUS{ SUCCESS=0,READ_FAILED,PE_ERROR };
  PE(const char* path)
  {
    initPePointer();
    loadStatus = READ_FAILED;
    FILE* f = fopen(path, "rb");
    if(f!=NULL)
    {
      loadStatus = loadPeFile(f);
      fclose(f);
    }
  }
  PE(FILE* file)
  {
    initPePointer();
    loadStatus = READ_FAILED;
    if(file!=NULL)
    {
      loadStatus = loadPeFile(file);
    }
  }
  int status()
  {
    return loadStatus;
  }

  IMAGE_DOS_HEADER* getImageDosHeader()
  {
    return (IMAGE_DOS_HEADER*)peHeaderData.data();
  }

  IMAGE_NT_HEADERS* getImageNtHeader()
  {
    return (IMAGE_NT_HEADERS*)(peHeaderData.data() + imageNtHeaderOffset);
  }

  IMAGE_SECTION_HEADER* getImageSectionHeaderTable()
  {
    return (IMAGE_SECTION_HEADER*)(peHeaderData.data() + imageSectionHeaderTableOffset);
  }

private:
  DWORD imageNtHeaderOffset;
  DWORD imageSectionHeaderTableOffset;
  int loadStatus;
  void initPePointer()
  {
    imageNtHeaderOffset = 0;
    imageSectionHeaderTableOffset = 0;
  }
  int loadPeFile(FILE* file)
  {
    initPePointer();
    //DOS HEAD
    IMAGE_DOS_HEADER imageDosHeader;
    int nread = fread(&imageDosHeader, sizeof(imageDosHeader), 1, file);
    if(nread <=0 )
    {
      return PE_ERROR;
    }

    //NT_HEADER
    IMAGE_NT_HEADERS imageNtHeader;
    fseek(file, imageDosHeader.e_lfanew, SEEK_SET);
    nread = fread(&imageNtHeader, sizeof(imageNtHeader), 1, file);
    if(nread <=0 )
    {
      return PE_ERROR;
    }

    //Read PE Header
    rewind(file);
    peHeaderData.resize(imageNtHeader.OptionalHeader.SizeOfHeaders);
    nread = fread(peHeaderData.data(),peHeaderData.size(), 1, file);
    if(nread <=0 )
    {
      return PE_ERROR;
    }
    imageNtHeaderOffset = imageDosHeader.e_lfanew;
    imageSectionHeaderTableOffset =  ( imageNtHeaderOffset + 4 + sizeof(imageNtHeader.FileHeader) + imageNtHeader.FileHeader.SizeOfOptionalHeader);
    return SUCCESS;
  }
};
