#include <iostream>
#include <tchar.h>
#include <windows.h>

using namespace std;

BOOLEAN isNTFS(wstring lpRootPathName) {
	BOOL result = FALSE;

	wchar_t FSname[2048];
	BOOL volInfo = FALSE;

	DWORD lpFileSystemFlags;
	wchar_t lpFileSystemNameBuffer;

	volInfo = GetVolumeInformationW(
		&lpRootPathName[0],
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		FSname,
		sizeof(FSname));

	if (volInfo == FALSE) {
		wprintf(_T("Failed to get disk volume information \t ERROR: %d\n"), GetLastError());
		return FALSE;
	}

	if (_wcsicmp(FSname, L"NTFS") == 0) {
		result = TRUE;
	}

	return result;
}

int wmain(int argc, wchar_t *argv[]) {

	if (argc < 3) {
		wprintf(_T("Usage: tool.exe <FILE_PATH> <ADS_NAME> <CONTENT>\n"));
		wprintf(_T("Usage: tool.exe .\\file.txt ads \"HELLO MY FRIEND\"\n"));
		return 0;
	}

	char content[] = "Hello World\n";
	wstring wcontent = (wstring&)content;
	DWORD written = 0;

	wstring file = argv[1];
	wstring ads = argv[2];
	wprintf(_T("Checking file [ %ws ]\n"), &file[0]);


	BOOLEAN isNtfs = FALSE;
	isNtfs = isNTFS(_T("C:\\"));
	
	if (isNtfs != TRUE) {
		wprintf(_T("Volume is not NTFS\n"));
		return EXIT_FAILURE;
	}

	WIN32_FIND_STREAM_DATA stream_data{};

	HANDLE hfirstStream = FindFirstStreamW(&file[0], FindStreamInfoStandard, &stream_data, 0);
	if (hfirstStream == INVALID_HANDLE_VALUE) {
		wprintf(_T("First handle stream search failed\n\t ERROR: %d\n"), GetLastError());
		FindClose(hfirstStream);
		return EXIT_FAILURE;
	}
	wprintf(_T("First stream success \t[ %p ]\n"), hfirstStream);

	while (FindNextStreamW(hfirstStream, &stream_data)) {
		wprintf(_T("\t- Stream Name: %ws \n\t- Stream Size: %d \n"), stream_data.cStreamName, stream_data.StreamSize);
	}
	
	if (_wcsicmp(stream_data.cStreamName, _T("::$DATA")) == 0) {
		wprintf(_T("Empty alternate data stream for [ %ws ]\n"), &file[0]);
		wprintf(_T("Creating alternate data stream\n"));
	}

	wstring file_ads = file + _T(":") + ads;
	wprintf(_T("ADS: %ws"), &file_ads[0]);

	getchar();

	HANDLE h_create_file = CreateFileW(&file_ads[0], (GENERIC_READ | GENERIC_WRITE), 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h_create_file == INVALID_HANDLE_VALUE) {
		CloseHandle(h_create_file);
		return EXIT_FAILURE;
	}
	if (WriteFile(h_create_file, &content, sizeof(content), &written, NULL)) {
		wprintf(_T("File contents written\n"));
	}
	else {
		wprintf(_T("Cannot write contents to file\n"));
		CloseHandle(h_create_file);
		return EXIT_FAILURE;
	}

	char data_read[2048];
	DWORD read = 0;

	// set the pointer to the start of the file so we can read all of its contents
	SetFilePointer(h_create_file, NULL, NULL, FILE_BEGIN);

	if (ReadFile(h_create_file, data_read, sizeof(content), &read, NULL)) {
		printf("Data: \n\t%s", data_read);
	}


	CloseHandle(h_create_file);

	return 0;
}