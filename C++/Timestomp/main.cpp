#include <iostream>
#include <windows.h>
#include "helpers.h"
#include "typedefs.h"
#include "ntstatus.h"

using namespace std;

int help_usage() {
	char help[] = "Usage: program.exe <TARGET_FILE_PATH> <SRC_FILE_PATH>";
	cout << help; 
	return EXIT_SUCCESS;
}


int wmain(int argc, wchar_t* argv[]) {

	if (argc < 3) {
		help_usage();
		return EXIT_SUCCESS;
	}

	wchar_t *target_file = argv[2];
	wchar_t *src_file = argv[1];

	NTSTATUS status = NULL;

	fnNtQueryInformationFile pNtQueryInformationFile = (fnNtQueryInformationFile)_GetNtApiAddress(strNtQueryInformationFile);
	if (pNtQueryInformationFile == NULL) return -ENOSYS;
	
	fnNtSetInformationFile pNtSetInformationFile = (fnNtSetInformationFile)_GetNtApiAddress(strNtSetInformationFile);
	if (pNtSetInformationFile == NULL) return -ENOSYS;
	
	cout << "#- QueryInfo \t" << pNtQueryInformationFile << endl;
	cout << "#- SetInfo \t" << pNtSetInformationFile << endl;

	FILE_BASIC_INFORMATION target_fbi, src_fbi = {};
	IO_STATUS_BLOCK iosb = {};

	// ====== SOURCE FILE ======
	HANDLE h_src_file = CreateFile(src_file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h_src_file == INVALID_HANDLE_VALUE) {
		cout << "*- File handle cant be obtained" << "\t ERROR: " << GetLastError() << endl;
		return EXIT_FAILURE;
	}

	cout << "+- Src file handle \t" << h_src_file << endl;

	status = pNtQueryInformationFile(h_src_file, &iosb, &src_fbi, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation);
	if (status != STATUS_SUCCESS) {
		cout << "/- Query source file info failed" << "\t ERROR: " << GetLastError() << endl;
		CloseHandle(h_src_file);
		return EXIT_FAILURE;
	}

	cout << "+- Query source file info success \t" << status << endl;

	// ====== DESTINATION FILE ======
	HANDLE h_target_file = CreateFile(target_file, (GENERIC_READ | GENERIC_WRITE | FILE_WRITE_ATTRIBUTES), FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h_target_file == INVALID_HANDLE_VALUE) {
		cout << "*- File handle cant be obtained" << "\t ERROR: " << GetLastError() << endl;
		return EXIT_FAILURE;
	}

	cout << "+- Dst file handle \t" << h_target_file << endl;

	status = pNtQueryInformationFile(h_target_file, &iosb, &target_fbi, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation);
	if (status != STATUS_SUCCESS) {
		cout << "/- Query destination file info failed" << "\t ERROR: " << GetLastError() << endl;
		CloseHandle(h_target_file);
		return EXIT_FAILURE;
	}

	cout << "+- Query destination file info success \t" << status << endl;

	// ===== UPDATE ATTRIBUTES =====
	target_fbi.ChangeTime = src_fbi.ChangeTime;
	target_fbi.CreationTime = src_fbi.CreationTime;
	target_fbi.LastAccessTime = src_fbi.LastAccessTime;
	target_fbi.LastWriteTime = src_fbi.LastWriteTime;

	status = pNtSetInformationFile(h_target_file, &iosb, &target_fbi, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation);
	if (status != STATUS_SUCCESS) {
		cout << "/- Set destination file info failed" << "\t ERROR: " << GetLastError() << endl;
		CloseHandle(h_target_file);
		return EXIT_FAILURE;
	}

	cout << "+- Set destination file info success \t" << status << endl;
	cout << "File modified !" << endl;

	CloseHandle(h_target_file);
	CloseHandle(h_src_file);

	return EXIT_SUCCESS;
}