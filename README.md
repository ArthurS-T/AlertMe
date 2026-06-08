# 🛡️ AlertMe - Sistema de Verificação de Links Maliciosos

O **AlertMe** é uma plataforma inteligente desenvolvida para proteger usuários contra ameaças virtuais, como campanhas de *phishing*, distribuição de *malware* e roubo de credenciais. Através da integração de APIs de segurança global e inteligência artificial, o sistema analisa URLs em tempo real, bloqueia links maliciosos e gera relatórios didáticos detalhando a ameaça encontrada.

---

## 🎯 Funcionalidades Principais

* **Análise em Tempo Real (VirusTotal API v3):** Submissão e consulta automatizada de URLs utilizando um ecossistema de mais de 70 motores de antivírus globais.
* **Mecanismo Inteligente de Polling:** O backend aguarda dinamicamente o processamento na nuvem por até 30 segundos se a URL estiver em fila de análise, evitando falsos negativos.
* **Explicação Didática com IA (Google Gemini API):** Caso um link seja detectado como ameaça, o modelo generativo processa as estatísticas e gera uma explicação clara, em tópicos, sobre o perigo real para o usuário.
* **Cache e Histórico (PostgreSQL):** Links já analisados são salvos em um banco de dados relacional. Consultas repetidas são respondidas instantaneamente, economizando requisições de API.

---

## 🛠️ Tecnologias Utilizadas

O ecossistema do projeto foi construído utilizando práticas modernas de desenvolvimento de software:

### Backend
* **Java 21** (Linguagem base utilizando os recursos mais recentes como *Records*)
* **Spring Boot 3.x** (Framework robusto para criação de APIs RESTful)
* **Spring Data JPA / Hibernate** (Abstração da camada de persistência de dados)
* **RestTemplate** (Comunicação síncrona com APIs externas)

### Banco de Dados
* **PostgreSQL** (Banco relacional de alta confiabilidade para produção e desenvolvimento)

### APIs Externas
* **VirusTotal API v3** (Detecção de vírus, trojans, phishing e malwares)
* **Google Gemini AI SDK/API** (Geração natural e interpretação de relatórios de risco)

---

## 🏗️ Arquitetura do Sistema

O fluxo de processamento segue a seguinte lógica de negócio:

```text
[Usuário/Front] ➡️ Envia URL ➡️ [LinkController]
                                       ⬇️
[LinkRepository] ⬅️ Verifica se já existe no Banco?
  ├── (Sim) ➡️ Retorna o resultado salvo imediatamente (Cache)
  └── (Não) ➡️ [VirusTotalService] ➡️ Realiza Polling na API
                      ⬇️
            Possui 2 ou mais detecções?
              ├── (Não) ➡️ Link Seguro ✅
              └── (Sim) ➡️ [GeminiService] ➡️ Gera explicação em texto ➡️ Salva no Banco ➡️ Retorna Bloqueio ❌
```
👤 Autor
Arthur S. - Desenvolvedor e Idealizador do Projeto - ArthurS-T
