#pragma once

#include <windows.h>
#include <winnt.h>
#include <stdio.h>

#include <vector>
using std::vector;

class PE
{
public:
  int loadStatus;
  enum LOAD_STATUS{ SUCCESS=0,READ_FAILED,PE_ERROR };
  PE(const char* path)
  {
    loadStatus = READ_FAILED;
    FILE* f = fopen(path, "rb");
    if(f!=NULL)
    {
      loadStatus = loadPeFile(f);
      fclose(f);
    }
  }
  int status()
  {
    return loadStatus;
  }
  const IMAGE_DOS_HEADER* getImageDosHeader() const
  {
    return &imageDosHeader;
  }
  const IMAGE_NT_HEADERS* getImageNtHeader() const
  {
    return &imageNtHeader;
  }
  int getSectionCount() const
  {
    return imageSectionHeaderList.size();
  }
  const IMAGE_SECTION_HEADER* getSectionList() const
  {
    return imageSectionHeaderList.data();
  }
private:
  PE(const PE&);

  IMAGE_DOS_HEADER imageDosHeader;
  IMAGE_NT_HEADERS imageNtHeader;
  vector<IMAGE_SECTION_HEADER> imageSectionHeaderList;
  int loadPeFile(FILE* file)
  {
    //DOS HEAD
    int nread = fread(&imageDosHeader, sizeof(imageDosHeader), 1, file);
    if(nread <=0 )
    {
      return PE_ERROR;
    }

    //NT_HEADER
    fseek(file, imageDosHeader.e_lfanew, SEEK_SET);
    nread = fread(&imageNtHeader, sizeof(imageNtHeader), 1, file);
    if(nread <=0 )
    {
      return PE_ERROR;
    }

    //SECTION_TABLE
    imageSectionHeaderList.resize(imageNtHeader.FileHeader.NumberOfSections);
    nread = fread(imageSectionHeaderList.data(), sizeof(IMAGE_SECTION_HEADER),
        imageNtHeader.FileHeader.NumberOfSections, file);
    if(nread<=0)
    {
      return PE_ERROR;
    }
    return SUCCESS;
  }
};
