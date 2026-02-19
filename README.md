<img src="https://raw.githubusercontent.com/scalabrinig/cdProjetoAplicadoIV/d093146488f56dfcf0ef286bcee8efe0e71b9c76/figuras/mackenzie_logo.jpg" width="50%"/>

# Projeto Aplicado - IV

### Ciência de Dados
### Mackenzie - 2026/1

#### Professor: Gustavo Scalabrini Sampaio

##### Projeto: ChronoSec: Detecção Comportamental e Séries Temporais para Segurança de Login (UEBA) em Eventos Google

---

Alunos:

- 10441670 - João Silveira Campos Netto
- 10442968 - Alex Luiz Rabelo

---

## Introdução

Processos de autenticação geram sinais ricos para segurança: falhas repetidas, desafios de MFA, mudanças de localização e padrões de horário. Em cenários de credenciais comprometidas, ataques automatizados e abuso de sessão, esses sinais costumam aparecer como anomalias temporais e comportamentais — muitas vezes antes de um incidente maior.

Este projeto propõe um produto analítico, implementado em Jupyter Notebooks, para explorar dados de login (anonimizados) provenientes da plataforma Google e aplicar técnicas de Séries Temporais e UEBA (User and Entity Behavior Analytics) para identificar desvios relevantes, como “Impossible Travel”, picos de frequência, sequências incomuns de eventos e mudanças no padrão de horário. A proposta combina regras explicáveis e modelos de aprendizado de máquina, com foco em reprodutibilidade e comunicação clara para um cliente (SOC/IAM).

UEBA é uma abordagem consolidada para detectar comportamentos anormais de usuários e entidades usando análises comportamentais e ML.
Analise de séries temporais para Cyber Security login process.

---

# **Objetivo**

Este trabalho tem como objetivo desenvolver um produto analítico baseado em séries temporais para detectar e explicar comportamentos anômalos em processos de login (eventos de autenticação) a partir de dados anonimizados da plataforma Google enriquecidos com geolocalização. A pretensão central é transformar registros brutos de autenticação em informação acionável para Cyber Security, permitindo identificar rapidamente padrões compatíveis com abuso de credenciais, automação maliciosa e tentativas de acesso indevido, com foco em priorização operacional e redução de ruído na investigação.

Como metas, o projeto busca:
1. modelar o comportamento típico de usuários e domínios ao longo do tempo (baseline) e medir desvios relevantes;
2. implementar mecanismos de detecção para cinco dimensões complementares do problema: frequência/velocidade de tentativas (Velocity Checks), viagens impossíveis (Impossible Travel), sequências incomuns de eventos de autenticação via cadeias de Markov, mudanças no padrão de horário por entropia temporal, e aprendizado de comportamento por modelos LSTM;
3. consolidar essas evidências em um score de risco por evento acompanhado de justificativas interpretáveis, para apoiar triagem e tomada de decisão;
4. entregar um experimento executável e reproduzível em Jupyter Notebooks, incluindo pipeline de preparação de dados, extração de features, treinamento/avaliação de modelos e geração de relatórios com estudos de caso.

Ao final, espera-se disponibilizar uma solução que demonstre, de forma mensurável, a capacidade de identificar anomalias comportamentais e explicar por que um evento foi considerado suspeito, além de apresentar uma proposta extensionista alinhada às ODS 9 e 12 por meio da publicação do método e de materiais reprodutíveis (incluindo um dataset compatível com o esquema de dados), contribuindo para a comunidade interessada em segurança de identidade e análise temporal.

---

# Helpers

Os *helpers* são aplicativos desenvolvidos para realizar a tratativa inicial e a adequação dos dados antes do uso no projeto principal. Eles podem ser entendidos como componentes de *pre-flight*: etapas fundamentais que preparam, ajustam e validam os dados para que estejam consistentes e aptos ao processamento.

Para este estudo de caso, foi necessário desenvolver *helpers* específicos, pois, sem essas rotinas de preparação (pseudonimização e enriquecimento, entre outras), não haveria dados em condições adequadas para suportar as análises e os objetivos do projeto.

## Pseudonimização

Este projeto foi desenvolvido a partir de bases reais, coletadas e analisadas em condições reais de operação. No entanto, devido à sensibilidade das informações envolvidas, foram implementados processos de pseudonimização e enriquecimento dos dados utilizados no projeto, com o objetivo de preservar a privacidade e reduzir riscos de exposição.

Para mais detalhes sobre o processo de pseudonimização adotado, consulte o código em: [Pseudonymize Data](https://github.com/joaonetto/projetoAplicado-IV/blob/main/Helpers/01-Pseudonymize/README.md).

Também é importante destacar a diferença entre anonimização e pseudonimização, e o motivo de utilizarmos esta última:

- **Anonimização**: processo irreversível; após a transformação, não é possível rastrear ou recuperar o dado original.
- **Pseudonimização**: processo reversível; o dado é transformado, mas existe uma tabela de referência (tabela verdade) que permite retornar ao valor original quando houver necessidade e autorização adequada.

Para o sucesso deste projeto, foi definido o uso de **pseudonimização** a fim de manter a **rastreabilidade** de usuário e domínio e, quando necessário, identificar quais usuários reais teriam sido afetados, preservando a confidencialidade durante o desenvolvimento e a avaliação acadêmica.

Em um cenário real de operações de **Cyber Security**, esses dados normalmente não precisariam ser modificados, pois o objetivo final seria analisar cada entrada de log (em streaming) e apresentar os achados à equipe de **Blue Team** para tomada de decisão imediata sobre a conta do usuário e o ambiente.

Nesse contexto, é importante destacar que uma conta comprometida pode, em questão de minutos, ser utilizada para escalonamento de privilégios, movimentação lateral e acesso a áreas restritas, ampliando rapidamente o impacto do incidente e colocando em risco informações sensíveis e, potencialmente, toda a corporação.

## Enriquecimento de dados

Os dados de logs são especialmente ricos para análises de **séries temporais**, pois registram cada instante em que um usuário tenta acessar o método de autenticação do Google. Vale destacar que esse processo também contempla aplicativos integrados via **SSO** (*Single Sign-On*).

Assim, sempre que um usuário acessa o e-mail ou utiliza plataformas federadas, um registro é gerado e armazenado nos logs do Google, e isso ocorre para todos os **usuários**, em todas as **autenticações**.

Diversas informações estão presentes nesses registros, mas algumas são essenciais para os objetivos deste projeto, como:
- e-mail do usuário;
- domínio do usuário;
- evento que originou o log (ex.: login sucesso/falha, logout, entre outros);
- tipo de autenticação (se ocorreu via Google ou por outra plataforma);
- endereço IP de origem do acesso;
- entre outros.

Entretanto, nesse tipo de log disponibilizado pelo Google, **não há geo-localização nativa** do usuário. Para obter essa informação diretamente pela plataforma, seria necessário um licenciamento diferenciado e outros pacotes de serviço. Ainda assim, para este projeto, a **geo-localização é fundamental** para aplicar conceitos como **“Impossible Travel”**, pois a posição geográfica (ou o raio de conexão habitual) permite identificar acessos fora do padrão esperado e gerar alertas de segurança.

Para enriquecer os dados com geo-posicionamento, foram utilizadas duas soluções externas:

- [Max Mind - GeoLite](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)
- [IP Geolocation AP](https://ipgeolocation.io/)

Enquanto a **MaxMind** oferece uma base atualizada para *download* e consumo local, o **IP Geolocation** opera por *API*. Vale ressaltar que, no plano free, o IP Geolocation **limita o uso a 1.000 requisições por dia**.

Para resolver o enriquecimento com geo-posicionamento (latitude e longitude), foi desenvolvido o aplicativo [Enrich Data - IP](https://github.com/joaonetto/projetoAplicado-IV/blob/main/Helpers/02-EnrichData/README.md), que utiliza o **IP** do usuário para consultar tanto a base da **MaxMind** quanto a **IP Geolocation API**.

Devido ao limite diário de requisições do **IP Geolocation**, optamos por utilizá-lo como *fallback*, ou seja, apenas quando a localização não é identificada pela base da **MaxMind**.

---

## Estrutura do projeto

A estrutura de diretórios deste projeto foi organizada para facilitar o entendimento, o uso e, principalmente, a reprodutibilidade dos experimentos.

Os principais diretórios são:
- **Data**: contém os arquivos .csv com os dados de entrada do projeto;
- **Helpers**: reúne os aplicativos auxiliares responsáveis pela pseudonimização e pelo enriquecimento dos dados;
- **GeoLocation**: armazena a base .mmdb da MaxMind utilizada para geolocalização por IP;
- **Etapas**: contém o sequenciamento das etapas do projeto, permitindo acompanhar a evolução do trabalho e reproduzir cada fase de forma organizada.

---

## Cronograma de entregas:

- [Etapa 1](https://github.com/joaonetto/projetoAplicado-IV/blob/main/Etapas/01/etapa_1.ipynb): Definição do projeto e equipe (01/03)
    - Em desenvolvimento
- Etapa 2: Referencial Teórico e Cronograma (29/03)
- Etapa 3: Implementação Parcial (26/04)
- Etapa 4: Implementação e Entrega Final (31/05)

---

## Licença

Este projeto está sobre a licença [Apache Version 2.0](https://github.com/joaonetto/projetoAplicado-IV/blob/main/LICENSE)
