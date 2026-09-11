# Windows Security & Maintenance Tool

Ferramenta interativa em PowerShell para segurança, auditoria e manutenção
rápida do Windows. O script usa cmdlets nativos do sistema e foi pensado para
ser executado localmente com privilégios de Administrador.

## Funcionalidades

- Executa `QuickScan` e `FullScan` pelo Microsoft Defender.
- Atualiza as definições de vírus usando `Update-MpSignature`.
- Lista detecções registradas pelo Defender com `Get-MpThreatDetection`.
- Limpa o conteúdo de diretórios temporários e caches selecionados.
- Esvazia a lixeira das unidades locais após confirmação explícita.
- Exibe conexões TCP, endpoints UDP, portas, estado, PID e processo associado
  em uma tabela para auditoria rápida.

## Requisitos

- Windows 10 ou Windows 11.
- Windows PowerShell 5.1 ou PowerShell 7+.
- Microsoft Defender ativo para as funções de proteção e atualização.
- Uma conta com privilégios de Administrador.
- As funções de rede dependem da disponibilidade dos cmdlets
  `Get-NetTCPConnection` e `Get-NetUDPEndpoint`.

> O script não instala módulos nem altera políticas do Windows. Alguns
> cmdlets podem não existir em edições específicas do sistema; nesse caso a
> opção correspondente informa o problema e retorna ao menu.

## Como executar

1. Baixe ou clone este repositório no computador Windows.
2. Abra o menu Iniciar, procure por **PowerShell** e selecione
   **Executar como administrador**.
3. Se necessário, permita a execução de scripts apenas para a sessão atual:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```

4. Entre na pasta do projeto e execute:

   ```powershell
   .\WindowsSecurityMaintenance.ps1
   ```

5. Escolha uma opção no menu e pressione **ENTER**. Use `0` para sair.

## Segurança e comportamento da limpeza

- O script encerra imediatamente se não estiver rodando como Administrador.
- A limpeza exige que o usuário digite exatamente `LIMPAR`.
- Somente o conteúdo dos diretórios temporários/cache listados é processado;
  as próprias pastas não são removidas.
- Arquivos bloqueados, inacessíveis ou sem permissão são ignorados e
  contabilizados na tabela.
- A varredura do Defender pode continuar em segundo plano após o comando ser
  enviado; o tempo total depende do tamanho e do estado do sistema.
- Antes de usar a limpeza em ambiente corporativo, valide a ação na política
  de manutenção da organização.

## Licença

Distribuído sob a licença MIT. Consulte o arquivo `LICENSE` para os termos.