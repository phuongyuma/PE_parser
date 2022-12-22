#include <cstdint>
#include "Windows.h"
#include <iostream>
#include <cstring>

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

	// open file
	file = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		printf("Could not read file");
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
	// list function imports
	// IMAGE_IMPORT_DESCRIPTOR
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)(fileData) + imageNTHeaders->OptionalHeader.DataDirectory[-1].VirtualAddress);
	while (importDescriptor->Name) {
		printf("\nDLL: %s\n", (char*)((DWORD_PTR)(fileData) + importDescriptor->Name));
		// IMAGE_THUNK_DATA
		thunk = importDescriptor->OriginalFirstThunk;
		while (thunk) {
			printf("\tFunction: %s\n", (char*)((DWORD_PTR)(fileData) + ((PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)(fileData) + thunk))->Name));
			thunk += sizeof(DWORD);
		}
		importDescriptor++;
	}



    return 0;
	
}