program Project3;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

uses
{$IFnDEF FPC}
{$ELSE}
  Interfaces,
{$ENDIF}
  Forms,
  ufrmmain in 'ufrmmain.pas' {Form1},
  uRun2 in 'uRun2.pas',
  uXOR in 'uXOR.pas';

{.$R *.res}
//{$R uac.res}

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TfrmMain, frmMain);
  Application.Run;
end.
