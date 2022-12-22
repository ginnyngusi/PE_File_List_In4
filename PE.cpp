#include <windows.h>
#include <stdio.h>
#include<iostream>
#include<winnt.h>
using namespace std;

// return rva of section
DWORD ConvertRvaToOffsetOnDisk(DWORD rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt)
{
	size_t i = 0;
	PIMAGE_SECTION_HEADER pSeh;
	if (rva == 0)
	{
		return (rva);
	}
	pSeh = psh;
	for (i = 0; i < pnt->FileHeader.NumberOfSections; i++)
	{
		if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress +
			pSeh->Misc.VirtualSize)
		{
			break;
		}
		pSeh++;
	}
	return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
}


BOOL IsPeFile(LPVOID lpFileBase) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return false;
	else
	{
		PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((LPBYTE)lpFileBase + pDosHeader->e_lfanew);
		if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
			return false;
		else
			return true;
	}

}

VOID AnalyzeFileInfo(LPVOID lpFileBase) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((LPBYTE)lpFileBase + pDosHeader->e_lfanew);

	cout << "======= Start Image Information ======= " << endl;

	printf("[+] Entry point: %08X\n", pNTHeader->OptionalHeader.AddressOfEntryPoint);
	printf("[+] Checksum: %08X\n", pNTHeader->OptionalHeader.CheckSum);
	printf("[+] Image start from %08X to %08X\n", pNTHeader->OptionalHeader.ImageBase, pNTHeader->OptionalHeader.ImageBase + pNTHeader->OptionalHeader.SizeOfImage);
	printf("[+] Image base address: %08X \n", pNTHeader->OptionalHeader.ImageBase);
	printf("[+] FileAlignment: %08X\n", pNTHeader->OptionalHeader.FileAlignment);
	printf("[+] FileSize : %08X\n", pNTHeader->OptionalHeader.SizeOfImage);


	cout << "======= End Image Information =======" << endl << endl;
}


VOID AnalyzeFileSection(LPVOID lpFileBase) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((LPBYTE)lpFileBase + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);
	WORD numberOfSecton = pNTHeader->FileHeader.NumberOfSections;
	cout << "======= Start Image Section ======= " << endl;
	do 
	{
		printf("%s\t%15X\t%15X\t%22X\t%19X\t%15X\n", pSectionHeader[numberOfSecton-1].Name
			, pSectionHeader[numberOfSecton-1].Misc.VirtualSize
			, pSectionHeader[numberOfSecton-1].VirtualAddress
			, pSectionHeader[numberOfSecton-1].SizeOfRawData
			, pSectionHeader[numberOfSecton-1].PointerToRawData
			, pSectionHeader[numberOfSecton-1].Characteristics);
		numberOfSecton--;
	} 
	while (numberOfSecton > 0);

	cout << "======= End Image Section ======= " << endl << endl;
}

VOID AnalyzeImportTable(LPVOID lpFileBase) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((LPBYTE)lpFileBase + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);
	cout << "======= Start Image IMAGE_DIRECTORY_ENTRY_IMPORT ======= " << endl;
	if (pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0)/*if size of the table is 0 - Import Table does not exist */
	{
		PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpFileBase + ConvertRvaToOffsetOnDisk(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pSectionHeader, pNTHeader));
		LPSTR libname[256];
		WORD i = 0;

		do
		{
			libname[i] = (PCHAR)((DWORD_PTR)lpFileBase + ConvertRvaToOffsetOnDisk(pIID->Name, pSectionHeader, pNTHeader));
			printf("\t%s\n", libname[i]);
			pIID++; 
			i++;

		} while (pIID->Name != NULL);
	}
	else
	{
		cout << "Could not found VirtualAddress of IMAGE_DIRECTORY_ENTRY_IMPORT" << endl;
	}
	cout << "======= End Image IMAGE_DIRECTORY_ENTRY_IMPORT ======= " << endl << endl;
}

VOID AnalyzeExportTable(LPVOID lpFileBase) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((LPBYTE)lpFileBase + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);
	cout << "======= Start Image IMAGE_DIRECTORY_ENTRY_EXPORT ======= " << endl;
	if (pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0)
	{
		PIMAGE_EXPORT_DIRECTORY pIED= (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)lpFileBase + ConvertRvaToOffsetOnDisk(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, pSectionHeader, pNTHeader));
		LPSTR libname[256];
		WORD i = 0;

		do
		{
			libname[i] = (PCHAR)((DWORD_PTR)lpFileBase + ConvertRvaToOffsetOnDisk(pIED->Name, pSectionHeader, pNTHeader));
			printf("\t%s\n", libname[i]);
			pIED++;
			i++;

		} while (pIED->Name != NULL);
	}
	else
	{
		cout << "Could not found VirtualAddress of IMAGE_DIRECTORY_ENTRY_EXPORT" << endl;
	}
	cout << "======= End Image IMAGE_DIRECTORY_ENTRY_EXPORT ======= " << endl << endl;
}

void AnalizePE(LPCSTR filename)
{
	HANDLE hFile = nullptr;
	HANDLE hFileMapping = nullptr;
	LPVOID lpFileBase = nullptr;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNTHeader;
	PIMAGE_FILE_HEADER pFileHeader;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;

	cout << "[+] Let analyze this file -> " << filename << endl;
		hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == nullptr)
			throw "Could not open file !";
		else {
			hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
			if (hFileMapping == nullptr) 
				throw "Could not map file to view 1 !";
			else
			{
				lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
				if(lpFileBase == nullptr)
					throw "Could not map file to view 2 !";
				else
				{
					if(!IsPeFile(lpFileBase))
						throw "This is not PE file";
					else
					{
						AnalyzeFileInfo(lpFileBase);
						AnalyzeFileSection(lpFileBase);
						AnalyzeImportTable(lpFileBase);
						AnalyzeExportTable(lpFileBase);
					}
				}
			}
		}

}

int main(int argc, char* argv[])
{
	try
	{
		if (argc < 2)
		{
			cout << "Give me you link to PE file !";
			return 0;
		}
		AnalizePE(argv[1]);
	}
	catch (LPCSTR exp) {
		cout << "[!] Error while running, error code: " << GetLastError() << " - Error decription: " << exp << endl;
	}
	return 0;
}
