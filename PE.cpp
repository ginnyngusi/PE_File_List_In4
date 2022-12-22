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
		// convert từ addr ảo về addr trên disk
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
	// Lấy vùng nhớ đã map và trỏ về struct DOS header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
	
	// Đảm bảo file đã map là file DOS
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return false;
	else
	{
		// Trỏ tới NT header ở vị trí + e_lfanew để có thông tin của file PE
		PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((LPBYTE)lpFileBase + pDosHeader->e_lfanew);
		// Kiểm tra PE header để chắc chắn là file EXE
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

	// Thông tin cần lấy của câu 1 nằm trong struct NT header
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
	// Lấy section đầu tiên từ struct NT header
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);
	
	// Lấy tổng section có trong NT header
	WORD numberOfSecton = pNTHeader->FileHeader.NumberOfSections;
	cout << "======= Start Image Section ======= " << endl;
	do 
	{
		// Lặp qua các section và in info cho câu 2
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
	
	// Nếu không có vitualAddr IMAGE_DIRECTORY_ENTRY_IMPORT không có import table
	if (pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0)
	{
		
		// CỘng địa chỉ từ DOS header và địa chỉ trên disk để lấy table import
		PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpFileBase + ConvertRvaToOffsetOnDisk(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pSectionHeader, pNTHeader));
		LPSTR libname[256];
		WORD i = 0;

		// Lặp qua dos header và lấy thông tin câu 3
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
	
	// Nếu không có vitualAddr IMAGE_DIRECTORY_ENTRY_EXPORT không có import table
	if (pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0)
	{
		// CỘng địa chỉ từ DOS header và địa chỉ trên disk để lấy table ẽport
		PIMAGE_EXPORT_DIRECTORY pIED= (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)lpFileBase + ConvertRvaToOffsetOnDisk(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, pSectionHeader, pNTHeader));
		LPSTR libname[256];
		WORD i = 0;
		
		// Lặp qua dos header và lấy thông tin câu 3
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

	cout << "[+] Let analyze this file -> " << filename << endl;
		// Mở file
		hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == nullptr)
			throw "Could not open file !";
		else {
			// Map file vào memory
			hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
			if (hFileMapping == nullptr) 
				throw "Could not map file to view 1 !";
			else
			{
				// Tạo page view để đọc file
				lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
				if(lpFileBase == nullptr)
					throw "Could not map file to view 2 !";
				else
				{
					// Kiểm tra file có đúng file PE hay không
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
		// Kiểm tra có nhập đường dẫn file vào hay không.
		if (argc < 2)
		{
			cout << "Give me you link to PE file !";
			return 0;
		}
		// Bắt đầu quá trình analyze file.
		AnalizePE(argv[1]);
	}
	catch (LPCSTR exp) {
		cout << "[!] Error while running, error code: " << GetLastError() << " - Error decription: " << exp << endl;
	}
	return 0;
}
