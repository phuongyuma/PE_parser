#include <cstdint>
#include "Windows.h"
#include <iostream>
#include <cstring>

LPVOID RvaToVa(LPVOID lpBase, DWORD dwRva) {
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + pDosHeader->e_lfanew);
		PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

		for (unsigned int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) {
			DWORD dwSectionStartRva = pSectionHeader->VirtualAddress;
			DWORD dwSectionEndRva = dwSectionStartRva + std::max(pSectionHeader->SizeOfRawData, pSectionHeader->Misc.VirtualSize);
			if (dwRva >= dwSectionStartRva && dwRva < dwSectionEndRva) {
				DWORD dwDelta = pSectionHeader->VirtualAddress - pSectionHeader->PointerToRawData;
				return (LPVOID)((BYTE*)lpBase + dwRva - dwDelta);
			}
		}
		return NULL;
	}
int main(int argc, char* argv[]) {

	HANDLE file;
	DWORD fileSize;
	DWORD bytesRead;
	LPVOID fileData;
	PIMAGE_DOS_HEADER dosHeader = {};
	PIMAGE_NT_HEADERS imageNTHeaders = {};
	PIMAGE_SECTION_HEADER sectionHeader = {};
	PIMAGE_SECTION_HEADER importSection = {};

	//PIMAGE_THUNK_DATA thunkData = {};
	DWORD thunk;
	DWORD rawOffset;

	//convert RVA to VA
	
	// open file
	file = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("Could not read file");
		return 1;
	};
	// allocate heap
	fileSize = GetFileSize(file, NULL);
	fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
	
	// read file bytes to memory
	ReadFile(file, fileData, fileSize, &bytesRead, NULL);

	// IMAGE_DOS_HEADER
	dosHeader = (PIMAGE_DOS_HEADER)fileData;

	// IMAGE_NT_HEADERS
	imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)(fileData) + dosHeader->e_lfanew); //fix
	printf("\n******* NT HEADERS *******\n");
	printf("Signature: 0x%x\n", imageNTHeaders->Signature);
	printf("AddressOfEntryPoint: 0x%x\n", imageNTHeaders->OptionalHeader.AddressOfEntryPoint);
	printf("CheckSum: 0x%x\n", imageNTHeaders->OptionalHeader.CheckSum);
	printf("ImageBase: 0x%x\n", imageNTHeaders->OptionalHeader.ImageBase);
	printf("SizeOfImage: 0x%x\n", imageNTHeaders->OptionalHeader.SizeOfImage);
	printf("FileAlignment: 0x%x\n", imageNTHeaders->OptionalHeader.FileAlignment);
	printf("SectionAlignment: 0x%x\n", imageNTHeaders->OptionalHeader.SectionAlignment);


	// DATA_DIRECTORIES
	printf("\n******* DATA DIRECTORIES *******\n");
	// Why the parameter of DataDirectory is not true
	printf("\tExport Directory Address: 0x%x; Size: 0x%x\n", imageNTHeaders->OptionalHeader.DataDirectory[-2].VirtualAddress, imageNTHeaders->OptionalHeader.DataDirectory[-2].Size);
	printf("\tImport Directory Address: 0x%x; Size: 0x%x\n", imageNTHeaders->OptionalHeader.DataDirectory[-1].VirtualAddress, imageNTHeaders->OptionalHeader.DataDirectory[-1].Size);

	// IMAGE_SECTION_HEADER
	sectionHeader = IMAGE_FIRST_SECTION(imageNTHeaders);
	printf("\n******* SECTION HEADERS *******\n");
	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
		printf("\n\nSection Info (%d of %d)\n", i + 1, imageNTHeaders->FileHeader.NumberOfSections);
		printf("Name: %s\n", sectionHeader[i].Name);
		printf("Characteristics: 0x%x\n", sectionHeader[i].Characteristics);
		printf("RawAddress: 0x%x\n", sectionHeader[i].PointerToRawData);
		printf("RawSize: 0x%x\n", sectionHeader[i].SizeOfRawData);
		printf("VirtualAddress: 0x%x\n", sectionHeader[i].VirtualAddress);
		printf("VirtualSize: 0x%x\n", sectionHeader[i].Misc.VirtualSize);
	}

	
	printf("\n******* DLL IMPORTS *******\n");	
	// list dll imports
	PIMAGE_DATA_DIRECTORY importDirectory = &imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)RvaToVa(fileData, importDirectory->VirtualAddress);
	for (int i = 0; importDescriptor[i].Name != 0; i++) {
		printf("DLL Name: %s\n", (char*)RvaToVa(fileData, importDescriptor[i].Name));
		PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)RvaToVa(fileData, importDescriptor[i].FirstThunk);
		for (int j = 0; thunkData[j].u1.AddressOfData != 0; j++) {
			printf("\tFunction Name: %s\n", (char*)RvaToVa(fileData, thunkData[j].u1.AddressOfData + 2));
		}
	}
	//list dll exports
	printf("\n******* DLL EXPORTS *******\n");
	PIMAGE_DATA_DIRECTORY exportDirectory = &imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY exportDirectoryA = (PIMAGE_EXPORT_DIRECTORY)RvaToVa(fileData, exportDirectory->VirtualAddress);
	DWORD* nameArray = (DWORD*)RvaToVa(fileData, exportDirectoryA->AddressOfNames);
	WORD* ordinalArray = (WORD*)RvaToVa(fileData, exportDirectoryA->AddressOfNameOrdinals);
	DWORD* functionArray = (DWORD*)RvaToVa(fileData, exportDirectoryA->AddressOfFunctions);
	for (int i = 0; i < exportDirectoryA->NumberOfNames; i++) {
		printf("Function Name: %s\n", (char*)RvaToVa(fileData, nameArray[i]));
	}
	



    return 0;
	
}