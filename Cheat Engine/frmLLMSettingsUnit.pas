{$mode delphi}
unit frmLLMSettingsUnit;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  StdCtrls, Buttons, ExtCtrls, IniFiles, LuaInternet, LuaAI;

type
  TLLMSettingsForm = class(TForm)
    grpConnection: TGroupBox;
    lblEndpoint: TLabel;
    edtEndpoint: TEdit;
    lblAPIKey: TLabel;
    edtAPIKey: TEdit;
    lblModel: TLabel;
    edtModel: TEdit;
    grpParameters: TGroupBox;
    lblMaxTokens: TLabel;
    edtMaxTokens: TEdit;
    lblTemperature: TLabel;
    edtTemperature: TEdit;
    pnlButtons: TPanel;
    btnTest: TButton;
    btnOK: TButton;
    btnCancel: TButton;
    lblStatus: TLabel;
    pnlStatus: TPanel;
    procedure FormShow(Sender: TObject);
    procedure btnTestClick(Sender: TObject);
    procedure btnOKClick(Sender: TObject);
    procedure btnCancelClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure edtEndpointChange(Sender: TObject);
    procedure edtAPIKeyChange(Sender: TObject);
    procedure edtModelChange(Sender: TObject);
    procedure edtMaxTokensChange(Sender: TObject);
    procedure edtTemperatureChange(Sender: TObject);
  private
    FOriginalKey: string;
    FOriginalBaseUrl: string;
    FOriginalModel: string;
    FOriginalMaxTokens: integer;
    FOriginalTemperature: double;
    procedure updateStatus(const msg: string; isError: boolean);
  public
    constructor Create(AOwner: TComponent); override;
  end;

function CreateLLMSettingsForm: TLLMSettingsForm;

implementation

{$R frmLLMSettingsUnit.lfm}

function CreateLLMSettingsForm: TLLMSettingsForm;
begin
  Result := TLLMSettingsForm.Create(Application);
end;

{ TLLMSettingsForm }

constructor TLLMSettingsForm.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  FOriginalKey := '';
  FOriginalBaseUrl := '';
  FOriginalModel := '';
  FOriginalMaxTokens := 0;
  FOriginalTemperature := 0;
end;

procedure TLLMSettingsForm.FormCreate(Sender: TObject);
begin
  lblStatus.Font.Color := clGray;
end;

procedure TLLMSettingsForm.updateStatus(const msg: string; isError: boolean);
begin
  lblStatus.Caption := msg;
  if isError then
    lblStatus.Font.Color := clRed
  else
    lblStatus.Font.Color := clGreen;
end;

procedure TLLMSettingsForm.FormShow(Sender: TObject);
begin
  { Load current settings }
  edtEndpoint.Text := g_apiBaseUrl;
  edtAPIKey.Text := g_apiKey;
  edtModel.Text := g_apiModel;
  edtMaxTokens.Text := IntToStr(g_apiMaxTokens);
  edtTemperature.Text := Format('%.2f', [g_apiTemperature]);

  { Save originals }
  FOriginalKey := g_apiKey;
  FOriginalBaseUrl := g_apiBaseUrl;
  FOriginalModel := g_apiModel;
  FOriginalMaxTokens := g_apiMaxTokens;
  FOriginalTemperature := g_apiTemperature;

  updateStatus('', False);
end;

procedure TLLMSettingsForm.btnTestClick(Sender: TObject);
var
  http: TWinInternet;
  memStream: TMemoryStream;
  response: AnsiString;
  testUrl: string;
  apiKey: string;
  postResult: boolean;
begin
  testUrl := edtEndpoint.Text;
  apiKey := edtAPIKey.Text;

  if testUrl = '' then
  begin
    updateStatus('Please enter an endpoint URL', True);
    Exit;
  end;

  { Auto-append /chat/completions if URL looks like a base path }
  if (Pos('/v1', LowerCase(testUrl)) > 0) and
     (Pos('/chat/completions', LowerCase(testUrl)) = 0) then
    testUrl := testUrl + '/chat/completions';

  updateStatus('Testing connection...', False);
  Application.ProcessMessages;

 http := TWinInternet.Create('');
  try
   http.Header := 'Content-Type: application/json' + #13#10;
    if apiKey <> '' then
      http.Header := http.Header + 'Authorization: Bearer ' + apiKey + #13#10;

    memStream := TMemoryStream.Create;
    try
      try
        postResult := http.postURL(testUrl, '{"model":"test","max_tokens":1}', memStream);
        if postResult then
        begin
          memStream.Position := 0;
          SetLength(response, memStream.Size);
          if memStream.Size > 0 then
            memStream.Read(PAnsiChar(response)^, memStream.Size);
          { Check if response contains typical error fields }
          if Pos('error', LowerCase(response)) > 0 then
          begin
            updateStatus('Connected but API returned error: ' + Copy(response, 1, 150), True);
          end
          else
          begin
            updateStatus('OK - Connected successfully', False);
          end;
        end
        else
        begin
          updateStatus('Connection failed - check URL and key', True);
        end;
      except
        on E: Exception do
        begin
          updateStatus('Connection error: ' + E.Message, True);
        end;
      end;
    finally
      memStream.Free;
    end;
  finally
    http.Free;
  end;
end;

procedure TLLMSettingsForm.btnOKClick(Sender: TObject);
var
  maxTokens: integer;
  temperature: double;
  e: EConvertError;
begin
  { Validate inputs }
  if not TryStrToInt(edtMaxTokens.Text, maxTokens) then
  begin
    ShowMessage('Max Tokens must be a valid integer');
    Exit;
  end;

  if not TryStrToFloat(edtTemperature.Text, temperature) then
  begin
    ShowMessage('Temperature must be a valid number');
    Exit;
  end;

  { Apply settings }
  g_apiBaseUrl := edtEndpoint.Text;
  g_apiKey := edtAPIKey.Text;
  g_apiModel := edtModel.Text;
  g_apiMaxTokens := maxTokens;
  g_apiTemperature := temperature;

  { Save to INI }
  saveLLMSettings;

  ModalResult := mrOk;
end;

procedure TLLMSettingsForm.btnCancelClick(Sender: TObject);
begin
  ModalResult := mrCancel;
end;

procedure TLLMSettingsForm.edtEndpointChange(Sender: TObject);
begin
  FOriginalBaseUrl := g_apiBaseUrl;
end;

procedure TLLMSettingsForm.edtAPIKeyChange(Sender: TObject);
begin
  FOriginalKey := g_apiKey;
end;

procedure TLLMSettingsForm.edtModelChange(Sender: TObject);
begin
  FOriginalModel := g_apiModel;
end;

procedure TLLMSettingsForm.edtMaxTokensChange(Sender: TObject);
begin
  FOriginalMaxTokens := g_apiMaxTokens;
end;

procedure TLLMSettingsForm.edtTemperatureChange(Sender: TObject);
begin
  FOriginalTemperature := g_apiTemperature;
end;

end.
