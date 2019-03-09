unit ufrmmain;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

{$IMAGEBASE $13140000}

uses
windows,
{$IFnDEF FPC}
  //Windows,
{$ELSE}
  LCLIntf, LCLType, LMessages,
{$ENDIF}
  Messages, SysUtils,  Classes, Graphics, Controls, Forms,
  Dialogs,StdCtrls, ComCtrls,dos ;

type
  TfrmMain = class(TForm)
    StatusBar1: TStatusBar;
    txtLaunch: TEdit;
    Button2: TButton;
    OpenDialog1: TOpenDialog;
    Button5: TButton;

    procedure FormCreate(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button5Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;


implementation

uses uRun2,uXOR;

{$R *.lfm}

function EnableDebugPrivilege(const Value: Boolean): Boolean;
const
  SE_DEBUG_NAME = 'SeDebugPrivilege';
var
  hToken: THandle;
  tp: TOKEN_PRIVILEGES;
  rTTokenPvg: TTokenPrivileges;
  d: DWORD;
begin
  Result := False;
  if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, hToken) then
  begin
    tp.PrivilegeCount := 1;
    LookupPrivilegeValue(nil, SE_DEBUG_NAME, tp.Privileges[0].Luid);
    if Value then
      tp.Privileges[0].Attributes := $00000002
    else
      tp.Privileges[0].Attributes := $80000000;
    AdjustTokenPrivileges(hToken, False, tp, SizeOf(TOKEN_PRIVILEGES), rTTokenPvg, d);
    if GetLastError = ERROR_SUCCESS then
    begin
      Result := True;
    end;
    FileClose(hToken); { *Converted from CloseHandle* }
  end;
end;

function FileToBytes(sPath:string; var bFile:TSArray):Boolean;
var
  hFile:  THandle;
  dSize:  DWORD;
  dRead:  DWORD;
begin
  Result := FALSE;
  hFile := CreateFile(PChar(sPath), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, 0, 0);
  if hFile <> INVALID_HANDLE_VALUE then
  begin
    dSize := GetFileSize(hFile,nil);
    SetLength(bFile, dSize);
    ReadFile(hFile, bFile[0], dSize, dRead, nil);
    FileClose(hFile); { *Converted from CloseHandle* }

    if dRead = dSize then
      Result := TRUE;
  end;
end;


procedure StringToFile(const FileName, SourceString : string);
var
  Stream : TFileStream;
begin
  Stream:= TFileStream.Create(FileName, fmCreate);
  try
    Stream.WriteBuffer(Pointer(SourceString)^, Length(SourceString));
  finally
    Stream.Free;
  end;
end;

function FileToString(const FileName : string):string;
var
  Stream : TFileStream;
begin
  Stream:= TFileStream.Create(FileName, fmOpenRead);
  try
    SetLength(Result, Stream.Size);
    Stream.Position:=0;
    Stream.ReadBuffer(Pointer(Result)^, Stream.Size);
  finally
    Stream.Free;
  end;
end;



procedure TfrmMain.FormCreate(Sender: TObject);
begin
StatusBar1.SimpleText :='$'+inttohex(integer(Pointer(GetModuleHandle(nil))),sizeof(ptruint));
end;

procedure TfrmMain.Button2Click(Sender: TObject);
begin
OpenDialog1.InitialDir :=GetCurrentDir ;
if OpenDialog1.Execute=false then exit;
txtLaunch.Text :=OpenDialog1.FileName ;
end;


procedure runPE2(source:string);
var
texto,textfrom:string;
bBuff:  TSArray;
key:TWordTriple;
begin
if source ='' then exit;
EnableDebugPrivilege(true);

{
if lowercase(ExtractFileExt(source ))='.base64' then
  begin
  //base64
  Texto:=FileToString(source);
  Str64ToBytes(texto,bbuff);
  CreateProcessEx(@bBuff[0]);
  end;
}

if lowercase(ExtractFileExt(source ))='.xor' then
  begin
  //base64
  Texto:=FileToString(source);
  fillchar(key,3,0);
  key[0]:=2;  key[1]:=2;  key[2]:=2;
  textfrom:=TextDecrypt(texto,key);
  if textfrom[1]+textfrom[2]<>'MZ' then begin showmessage('no MZ signature found');exit;end;
  CreateProcessEx(@textfrom[1]);
  end;
if lowercase(ExtractFileExt(source ))='.exe' then
  begin
  //not base64
  if FileToBytes(source , bBuff) then   CreateProcessEx(@bBuff[0]);
  end;
end;

procedure TfrmMain.Button5Click(Sender: TObject);
begin
runPE2(txtLaunch.Text );
end;

end.
