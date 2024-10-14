# Monitoramento de Cotações de Moedas

O objetivo do projeto é criar um serviço backend que monitore a cotação do dólar e outras moedas em tempo real, armazenando as informações em um banco de dados e fornecendo uma API RESTful para que os usuários possam consultar as cotações, receber notificações sobre variações significativas e visualizar um histórico de preços.

## Tecnologias Utilizadas e Dependências do Projeto:

![Python](https://img.shields.io/badge/Python-14354C?style=for-the-badge&logo=python&logoColor=white)

**Versão 3.12**
- Utilizado para desenvolver todo o backend da aplicação, incluindo views, models e a lógica principal.

### Bibliotecas Utilizadas
- **Schedule**: Para agendar tarefas de monitoramento de cotações a cada 30 minutos.
- **SendGrid**: Para enviar notificações por email aos usuários quando a cotação do dólar atingir um valor especificado.
- **Google Auth**: Para implementar autenticação OAuth2, permitindo que os usuários se autentiquem usando suas credenciais do Google.
- **Cryptography**: Para criptografar tokens sensíveis, como refresh tokens.
- **Requests**: Para fazer chamadas HTTP a APIs externas que fornecem informações de cotação.

**Flask 3.0**
- Um microframework para Python que facilita o desenvolvimento de aplicações web, oferecendo uma estrutura leve e extensível.

### Extensões Utilizadas:

- **Flask-RESTful**: Para simplificar a criação de APIs RESTful. Permite definir recursos e rotas de maneira organizada, facilitando a implementação de endpoints.
- **Flask-SQLAlchemy**: Para integração com o SQLAlchemy, facilitando a manipulação de bancos de dados através de uma interface de objeto-relacional. Ele simplifica a definição de modelos, consultas e transações.

## Estrutura do Projeto

O Projeto foi construindo seguindo recomendações de boas práticas de estruturação de projetos que utilizam o Flask par criação de aplicações web.

|- `app/`: Diretório com os arquivos utilizados para estruturação do Flask.
    |- `run.py`: Arquivo de inicialização da aplicação.
    |- `auth.py`: Administra funções de autenticação.
    |- `models.py`: Criação da base de dados, tabelas, e seus relacionamentos.
    |- `views.py`: Views de API da aplicação.
    |- `utils.py`: Configuração de utilitários da aplicação (SendGrid, Cryptography, Schedule)
    |- `client_secret.json`: Dados que referenciam a API de OAuth2 do Google (ID do Cliente). Necessário para o `Flow`.
|- `.env`: Variáveis de ambiente do projeto.


## Instalação e Configuração


## Descrição e Usabilidade


## Próximas Atualizações


## Suporte


## Licença
