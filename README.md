# 🔍 Splunk SIEM Lab — Detecção Avançada, Threat Hunting e Automação

## Objetivo

Expandir o lab anterior com cenários avançados de detecção cobrindo correlação de eventos, escalada de privilégios, persistência, tuning de alertas, dashboard operacional de SOC, threat hunting baseado em MITRE ATT&CK e automação de resposta a incidentes — tudo no Splunk Enterprise local sem VMs adicionais.

---

## Ambiente

| Componente | Detalhe |
|---|---|
| SIEM | Splunk Enterprise (licença Free — 500 MB/dia) |
| Host | Windows 10/11 local (sem VM) |
| Logs ingeridos | Security, System, Application (WinEventLog) |
| Index | `main` |
| Sourcetype | `wineventlog:security` |

---

## Fase 1 — Correlação: Brute Force Bem-Sucedido (Nível 2)

### Descrição
Detecção do cenário mais perigoso de brute force: o atacante erra várias vezes e **consegue autenticar**. Exige correlacionar Event IDs 4625 e 4624 dentro de uma janela de tempo.

### Simulação
5 tentativas com senha incorreta seguidas de 1 logon bem-sucedido na tela de login do Windows.

### Query SPL

```spl
index=main sourcetype="wineventlog:security" (EventCode=4624 OR EventCode=4625) earliest=-60m
| eval Evento=if(EventCode=4624, "Logon_OK", "Logon_FAIL")
| stats count(eval(Evento="Logon_FAIL")) as Falhas,
        count(eval(Evento="Logon_OK")) as Sucessos
        by ComputerName
| where Falhas >= 3 AND Sucessos >= 1
| eval Risco="ALTO - Possível Brute Force Bem-Sucedido"
| table ComputerName, Falhas, Sucessos, Risco
```

### Resultado
`LAPTOP-UOEULUPQ` — 7 Falhas, 28 Sucessos — **ALTO - Possível Brute Force Bem-Sucedido**

### Observação técnica
O campo `Nome_da_Conta` nos eventos 4625 vem vazio no Windows PT-BR. A correlação foi adaptada para usar `ComputerName` como chave.

### Alerta
- **Nome:** `Brute Force Bem-Sucedido - Logon Após Multiplas Falhas`
- **Trigger:** Number of Results > 0
- **Severity:** High

---

## Fase 2 — Escalada de Privilégios e Criação de Usuário (Nível 2)

### Descrição
Detecção de criação de conta local e adição imediata ao grupo Administrators — padrão clássico de persistência pós-comprometimento.

### Event IDs

| ID | Evento |
|---|---|
| 4720 | Conta de usuário criada |
| 4728 | Usuário adicionado a grupo global privilegiado |
| 4732 | Usuário adicionado a grupo local privilegiado |

### Simulação

```cmd
net user atacante Senha@123 /add
net localgroup Administrators atacante /add
net user atacante /delete
```

### Query de Correlação SPL

```spl
index=main sourcetype="wineventlog:security" (EventCode=4720 OR EventCode=4732 OR EventCode=4728) earliest=-1h
| stats values(EventCode) as EventIDs, dc(EventCode) as TiposDistintos, count by ComputerName
| eval Risco=case(
    TiposDistintos>=3, "CRITICO - Criação + Adição a grupo detectadas",
    TiposDistintos=2, "ALTO - Dois tipos de eventos de privilégio",
    true(), "MEDIO - Evento isolado"
  )
| table ComputerName, EventIDs, TiposDistintos, count, Risco
| sort -TiposDistintos
```

### Resultado
`LAPTOP-UOEULUPQ` — EventIDs: 4720, 4728, 4732 — TiposDistintos: 3 — **CRITICO**

### Mapeamento MITRE ATT&CK
- **T1136.001** — Create Account: Local Account
- **T1098** — Account Manipulation

### Alertas
- `Criação de Usuário Detectada` — dispara em qualquer 4720
- `CRITICO - Escalada de Privilegios Detectada` — dispara em correlação

---

## Fase 3 — Persistência via Tarefas Agendadas (Nível 2/3)

### Descrição
Detecção de criação de tarefa agendada com nome genérico mascarando processo malicioso — técnica de persistência e mascaramento combinadas.

### Event IDs

| ID | Evento |
|---|---|
| 4698 | Tarefa agendada criada |
| 4702 | Tarefa agendada modificada |

### Configuração necessária
Habilitar auditoria via GUID (subcategoria "Outros Eventos de Acesso a Objetos"):

```powershell
auditpol /set /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
```

### Simulação

```cmd
schtasks /create /tn "WindowsUpdate_Helper" /tr "C:\Windows\System32\cmd.exe /c whoami" /sc onlogon /ru SYSTEM
schtasks /delete /tn "WindowsUpdate_Helper" /f
```

### Query de Detecção por Mascaramento

```spl
index=main sourcetype="wineventlog:security" EventCode=4698
| eval Suspeito=if(match(Nome_da_Tarefa, "(?i)(update|helper|service|svchost|windows)"), "VERIFICAR - Nome genérico", "OK")
| table _time, Nome_da_Tarefa, Suspeito, Nome_do_Assunto, ComputerName
| sort -_time
```

### Resultado
`\WindowsUpdate_Helper` — **VERIFICAR - Nome genérico**

### Mapeamento MITRE ATT&CK
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1036** — Masquerading

### Alerta
- `Persistência - Tarefa Agendada com Nome Suspeito`
- **Severity:** High

---

## Fase 4 — Tuning de Alertas: Redução de Falsos Positivos (Nível 3)

### Descrição
Refinar a regra de detecção de Process Creation para eliminar ruído de processos legítimos, focando apenas em comportamento genuinamente suspeito.

### Processo de tuning
Redução progressiva de eventos via whitelist:
- 656 eventos iniciais → 269 após primeira whitelist → 174 após segunda → 25 após abordagem por pasta

### Técnica aplicada — Filtro por pasta de origem

```spl
index=main sourcetype="wineventlog:security" EventCode=4688
| where NOT match(Nome_do_Novo_Processo, "(?i)D:\\\\SPLUNK\\\\")
| where NOT match(Nome_do_Novo_Processo, "(?i)C:\\\\Program Files\\\\BraveSoftware\\\\")
| where NOT match(Nome_do_Novo_Processo, "(?i)C:\\\\Program Files\\\\Adobe\\\\")
| where NOT match(Nome_do_Novo_Processo, "(?i)C:\\\\Program Files \\(x86\\)\\\\")
| where NOT match(Nome_do_Novo_Processo, "(?i)C:\\\\Program Files\\\\WindowsApps\\\\")
| where NOT Nome_do_Novo_Processo IN (
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\conhost.exe",
    "C:\\Windows\\System32\\RuntimeBroker.exe",
    "C:\\Windows\\System32\\dllhost.exe",
    "C:\\Windows\\System32\\SearchFilterHost.exe",
    "C:\\Windows\\System32\\SearchProtocolHost.exe",
    "C:\\Windows\\System32\\smss.exe",
    "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"
  )
| search Nome_do_Novo_Processo="*whoami*" OR Nome_do_Novo_Processo="*net.exe*"
  OR Nome_do_Novo_Processo="*ipconfig*" OR Nome_do_Novo_Processo="*tasklist*"
  OR Nome_do_Novo_Processo="*systeminfo*" OR Nome_do_Novo_Processo="*cmd.exe*"
  OR Nome_do_Novo_Processo="*powershell*"
| table _time, Nome_do_Novo_Processo, Linha_de_Comando_do_Processo, Nome_da_Conta
| sort -_time
```

### Lição aprendida
Nem todo falso positivo é óbvio — `cmd.exe` chamado pelo Adobe Acrobat para comunicação com extensão do Chrome parece suspeito mas é legítimo. A investigação de contexto é essencial antes de concluir.

### Alerta
- `Process Creation - Execução Suspeita Detectada (Tunado)`
- **Severity:** Medium

---

## Fase 5 — Dashboard Operacional de SOC (Nível 4)

### Descrição
Dashboard `SOC - Visão Operacional` com 4 painéis para uso no início do turno do analista.

### Painel 1 — Volume de Eventos por Hora (Line Chart)

```spl
index=main sourcetype="wineventlog:security"
| timechart span=1h count by EventCode
```

### Painel 2 — Falhas de Logon por Hora (Column Chart)

```spl
index=main sourcetype="wineventlog:security" EventCode=4625
| timechart span=1h count
```

### Painel 3 — Top 10 Processos Criados (Bar Chart)

```spl
index=main sourcetype="wineventlog:security" EventCode=4688
| stats count by Nome_do_Novo_Processo
| sort -count
| head 10
```

### Painel 4 — Alertas Disparados (Table)

```spl
index=_audit action=alert_fired
| table _time, savedsearch_name, result_count
| sort -_time
```

---

## Fase 6 — Threat Hunting com MITRE ATT&CK (Nível 5)

### Descrição
Postura proativa: buscar ativamente evidências de TTPs conhecidas nos logs sem aguardar alertas.

**Hipótese:** "Existe uso de LOLBins ou técnicas de evasão na máquina?"

### Hunt 1 — LOLBins (Living off the Land)

```spl
index=main sourcetype="wineventlog:security" EventCode=4688
| eval TTP=case(
    match(Nome_do_Novo_Processo, "(?i)certutil"), "T1140 - Deobfuscate/Decode",
    match(Nome_do_Novo_Processo, "(?i)wscript|cscript"), "T1059.005 - Visual Basic",
    match(Nome_do_Novo_Processo, "(?i)mshta"), "T1218.005 - Mshta",
    match(Nome_do_Novo_Processo, "(?i)regsvr32"), "T1218.010 - Regsvr32",
    match(Nome_do_Novo_Processo, "(?i)rundll32"), "T1218.011 - Rundll32",
    match(Nome_do_Novo_Processo, "(?i)\\\\powershell\\.exe"), "T1059.001 - PowerShell",
    match(Nome_do_Novo_Processo, "(?i)msiexec"), "T1218.007 - Msiexec",
    match(Nome_do_Novo_Processo, "(?i)wmic"), "T1047 - WMI",
    true(), null()
  )
| where isnotnull(TTP)
| table _time, Nome_do_Novo_Processo, Linha_de_Comando_do_Processo, TTP, Nome_da_Conta
| sort -_time
```

**Resultado:** `rundll32` e `powershell` detectados — ambos com contexto legítimo (processos do Windows).

### Hunt 2 — PowerShell Encodado (T1059.001)

**Simulação:**
```cmd
powershell -EncodedCommand aQBwAGMAbwBuAGYAaQBnAA==
```
(Base64 de `ipconfig` — simula ofuscação de payload)

**Detecção:**
```spl
index=main sourcetype="wineventlog:security" EventCode=4688
| search Nome_do_Novo_Processo="*powershell*"
| search Linha_de_Comando_do_Processo="*-enc*" OR Linha_de_Comando_do_Processo="*-EncodedCommand*"
| table _time, Nome_do_Novo_Processo, Linha_de_Comando_do_Processo, Nome_da_Conta
| eval TTP="T1059.001 - PowerShell Encodado"
```

**Resultado:** Detectado — payload `aQBwAGMAbwBuAGYAaQBnAA==` visível no log, executado pelo usuário Ruan.

### Hunt 3 — Enumeração de Rede (T1135)

**Simulação:**
```cmd
net view
net share
```

**Detecção:**
```spl
index=main sourcetype="wineventlog:security" EventCode=4688
| search Nome_do_Novo_Processo="*net.exe*"
| search Linha_de_Comando_do_Processo="*view*" OR Linha_de_Comando_do_Processo="*share*"
| table _time, Nome_do_Novo_Processo, Linha_de_Comando_do_Processo, Nome_da_Conta
| eval TTP="T1135 - Network Share Discovery"
```

**Resultado:** 4 eventos detectados — `net view` e `net share` pelo usuário Ruan.

---

## Fase 7 — Automação de Resposta a Incidentes (Nível 6)

### Descrição
Configuração de ações automáticas executadas pelo Splunk quando um alerta dispara, simulando um fluxo básico de SOAR.

### Ação 1 — Script PowerShell de Contenção Simulada

**Script:** `D:\SPLUNK\bin\scripts\resposta_incidente.ps1`
```powershell
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$logPath = "C:\SplunkAlerts\triggered_alerts.log"
Add-Content -Path $logPath -Value "$timestamp - ALERTA DISPARADO: Atividade suspeita detectada no host $env:COMPUTERNAME"
```

**Wrapper bat:** `D:\SPLUNK\bin\scripts\resposta_incidente.bat`
```batch
@echo off
powershell.exe -ExecutionPolicy Bypass -File "D:\SPLUNK\bin\scripts\resposta_incidente.ps1"
```

**Resultado:** Script executou automaticamente nos ciclos de 1 minuto:
```
2026-05-24 22:20:01 - ALERTA DISPARADO: Atividade suspeita detectada no host LAPTOP-UOEULUPQ
2026-05-24 22:21:01 - ALERTA DISPARADO: Atividade suspeita detectada no host LAPTOP-UOEULUPQ
```

### Ação 2 — Webhook para Notificação Externa

Configurado via **Add Actions → Webhook** no alerta de Brute Force. O Splunk envia automaticamente um POST JSON com os dados do alerta para o endpoint configurado.

**Payload recebido:**
```json
{
  "search_name": "Brute Force Bem-Sucedido - Logon Após Multiplas Falhas",
  "app": "search",
  "owner": "lab",
  "result": {
    "ComputerName": "LAPTOP-UOEULUPQ",
    "Falhas": "7",
    "Sucessos": "32"
  }
}
```

**Em produção:** O webhook seria o endpoint de um SOAR (Shuffle, Splunk SOAR), sistema de ticketing (ServiceNow, Jira) ou canal de comunicação do SOC.

---

## Mapeamento MITRE ATT&CK Completo

| Técnica | ID | Fase |
|---|---|---|
| Brute Force | T1110 | Fase 1 |
| Create Account: Local Account | T1136.001 | Fase 2 |
| Account Manipulation | T1098 | Fase 2 |
| Scheduled Task/Job | T1053.005 | Fase 3 |
| Masquerading | T1036 | Fase 3 |
| PowerShell | T1059.001 | Fase 6 |
| Mshta / Rundll32 / Regsvr32 | T1218 | Fase 6 |
| Network Share Discovery | T1135 | Fase 6 |
| Deobfuscate/Decode | T1140 | Fase 6 |

---

## Alertas Configurados

| Nome | Trigger | Severity |
|---|---|---|
| Brute Force Bem-Sucedido - Logon Após Multiplas Falhas | Results > 0 | High |
| CRITICO - Escalada de Privilegios Detectada | Results > 0 | Critical |
| Persistência - Tarefa Agendada com Nome Suspeito | Results > 0 | High |
| Process Creation - Execução Suspeita Detectada (Tunado) | Results > 0 | Medium |
| Threat Hunt - PowerShell Encodado Detectado | Results > 0 | High |
| Threat Hunt - Enumeração de Rede Detectada | Results > 0 | Medium |

---

## SPL — Comandos Utilizados

| Comando | Função |
|---|---|
| `eval` + `if()` | Classificação condicional de eventos |
| `stats count(eval(...))` | Contagem condicional dentro de stats |
| `dc()` | Distinct count — conta valores únicos |
| `values()` | Lista todos os valores de um campo |
| `match()` | Regex matching em campos |
| `timechart` | Agregação temporal para gráficos |
| `mvcount()` | Conta elementos de campo multivalor |
| `isnotnull()` | Filtra campos com valor preenchido |

---

## Lições Aprendidas

- Correlação entre Event IDs diferentes exige adaptar a chave de join ao ambiente — no Windows PT-BR o `Nome_da_Conta` pode vir vazio em eventos 4625, exigindo uso de `ComputerName`.
- Tuning de alertas é iterativo — não existe whitelist perfeita na primeira tentativa. O processo de redução progressiva (656 → 25 eventos) é o método correto.
- Threat Hunting produz dois resultados válidos: encontrar evidência de comprometimento OU confirmar ausência de uma TTP específica.
- Automação via script requer wrapper `.bat` no Splunk — scripts PowerShell não são executados diretamente pelo mecanismo de alertas.

---

## Evidências

Screenshots em `Lab-SIEM-Splunk-2/`

## Referências

- [Splunk SPL Documentation](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Windows Security Event IDs](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
