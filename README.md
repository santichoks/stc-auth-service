<h1>stc-auth-service</h1>
<h2>Introduction</h2>
<ul>This project was created with the purpose of studying authentication and authorization within microservices, with a specific focus on the API Gateway. </ul>
<p align="center">
  <img src="./other/arch.png">
</p>
<h2>Project Structure</h2>

```text
stc-auth-service/
├── 🗂️config/
├──── 📄config.go
├── 🗂️controllers/
├──── 📄auth_test.go
├──── 📄auth.go
├── 🗂️middleware/
├──── 📄auth.go
├── 🗂️models/
├──── 📄auth.go
├── 🗂️pkgs/
├──── 🗂️databasePkg/
├────── 📄mongo.go
├────── 📄redis.go
├──── 🗂️jwtPkg/
├────── 📄jwt.go
├──── 🗂️responsePkg/
├────── 📄response.go
├──── 🗂️validationPkg/
├────── 📄validation.go
├── 🗂️repositories/
├──── 📄mongo_mock.go
├──── 📄mongo.go
├──── 📄redis_mock.go
├──── 📄redis.go
├── 🗂️router/
├──── 📄auth.go
├── 🗂️services/
├──── 📄auth_mock.go
├──── 📄auth_test.go
├──── 📄auth.go
├── 📄main.go
```
<h2>Getting started</h2>
<ul>
<li>
  <h4>Installation</h4>  
  
  Clone and install Go packages.
  ```
  $ git clone https://github.com/santichoks/stc-auth-service.git
  $ cd stc-auth-service
  $ go get ./...
  ```
</li>
<li>
  <h4>Setting Environment</h4>
  
  Create an `.env` file in the application root directory.
  ```env
  ACCESS_ORIGINS = <ACCESS_ORIGINS>
  SERVICE_LISTS = <SERVICE_LISTS>
  MONGO_HOST = <MONGODB_HOST>
  MONGO_USERNAME = <MONGO_USERNAME>
  MONGO_PASSWORD = <MONGO_PASSWORD>
  REDIS_HOST = <REDIS_HOST>
  REDIS_PASSWORD = <REDIS_PASSWORD>
  SMTP_HOST = <SMTP_HOST>
  SMTP_PORT = <SMTP_PORT>
  SENDER_EMAIL = <SENDER_EMAIL>
  SENDER_PASSWORD = <SENDER_PASSWORD>
  RESET_PASSWORD_TOKEN_DURATION = <RESET_PASSWORD_TOKEN_DURATION>
  JWT_ACCESS_TOKEN_SECRET = <JWT_ACCESS_TOKEN_SECRET>
  JWT_ACCESS_TOKEN_DURATION = <JWT_ACCESS_TOKEN_DURATION>
  JWT_REFRESH_TOKEN_SECRET = <JWT_REFRESH_TOKEN_SECRET>
  JWT_REFRESH_TOKEN_DURATION = <JWT_REFRESH_TOKEN_DURATION>
  ```
  For example
  ```env
  ACCESS_ORIGINS = http://localhost:3000
  SERVICE_LISTS = [{ "host": "https://pokeapi.co", "alias": "/pokeapi" }, ...]
  MONGO_HOST = mongodb://localhost:27017
  MONGO_USERNAME = root
  MONGO_PASSWORD = @123456
  REDIS_HOST = localhost:6379
  REDIS_PASSWORD = @123456 
  SMTP_HOST = smtp.gmail.com # <----------- https://www.prolateral.com/help/kb/smtp/415-list-of-smtp-servers.html
  SMTP_PORT = 587 # <----------- https://www.prolateral.com/help/kb/smtp/415-list-of-smtp-servers.html
  SENDER_EMAIL = example@gmail.com
  SENDER_PASSWORD = example-sender-password
  RESET_PASSWORD_TOKEN_DURATION = 900 # <----------- 900 seconds is 15 minutes
  JWT_ACCESS_TOKEN_SECRET = example-jwt-access-token-secret
  JWT_ACCESS_TOKEN_DURATION = 86400 # <----------- 86400 seconds is 1 day
  JWT_REFRESH_TOKEN_SECRET = example-jwt-refresh-token-secret
  JWT_REFRESH_TOKEN_DURATION = 2592000 # <----------- 2592000 seconds is 30 days
  ```
</li>
<li>
  <h4>Docker Compose for MongoDB and Redis</h4>
  
  You can create `docker-compose.yml` and run cmd `docker-compose up` to install mongodb and redis.
  ```yml
  version: '3.8'
  name: database
  services:
    mongodb:
      image: mongo
      container_name: mongo-auth-database
      ports:
        - <MONGODB_PORT>:27017 
      environment:
        MONGO_INITDB_ROOT_USERNAME: <MONGO_USERNAME>
        MONGO_INITDB_ROOT_PASSWORD: <MONGO_PASSWORD>
    redis:
      image: redis
      container_name: redis-auth-database
      ports:
        - <REDIS_PORT>:6379
      command: redis-server --requirepass <REDIS_PASSWORD>
  ```
  For example
  ```yml
  version: '3.8'
  name: database
  services:
    mongodb:
      image: mongo
      container_name: mongo-auth-database
      ports:
        - 27017:27017 
      environment:
        MONGO_INITDB_ROOT_USERNAME: root
        MONGO_INITDB_ROOT_PASSWORD: @123456
    redis:
      image: redis
      container_name: redis-auth-database
      ports:
        - 6379:6379
      command: redis-server --requirepass @123456
  ```
</li>
<li>
  <h4>Let's Start</h4>

  ```
  go run .
  ```
</li>
</ul>

<h2>Authentication API</h2>
<ul>
<li>
  <h4>Health Check</h4>

  |Endpoint|Method|Example|
  |:-:|:-:|-|
  |`/healthz`|GET|`http://localhost:8080/healthz`|

  Example Response
  ```json
  {
    "statusCode": 200,
    "message": "healthy"
  }
  ```
</li>
<li>
  <h4>Sign Up</h4>
  
  |Endpoint|Method|Example|
  |:-:|:-:|-|
  |`/signup`|POST|`http://localhost:8080/signup`|

  Example Request
  ```json
  {
    "firstName": "santichok",
    "lastName": "sangarun",
    "email": "admin@stc.com",
    "password": "12345678"
  }
  ```
  Example Response : `accessToke` and `refreshToken` in cookie.
  ```json
  {
    "statusCode": 200,
    "message": "successfully"
  }
  ```
  <p align="center">
    <img src="./other/cookie.png">
  </p>
</li>
<li>
  <h4>Login</h4>

  |Endpoint|Method|Example|
  |:-:|:-:|-|
  |`/login`|POST|`http://localhost:8080/login`|

  Example Request
  ```json
  {
      "email": "admin@stc.com",
      "password": "12345678"
  }
  ```
  Example Response : `accessToke` and `refreshToken` in cookie.
  ```json
  {
      "statusCode": 200,
      "message": "successfully"
  }
  ```
  <p align="center">
    <img src="./other/cookie.png">
  </p>
</li>
<li>
  <h4>Logout</h4>
  
  |Endpoint|Method|Example|
  |:-:|:-:|-|
  |`/logout`|POST|`http://localhost:8080/logout`|
  
  Example Response : `accessToke` and `refreshToken` in black list (redis).
  ```json
  {
      "statusCode": 200,
      "message": "successfully"
  }
  ```
  <p align="center">
    <img src="./other/blacklist.png">
  </p>
</li>
<li>
  <h4>Reset-Password</h4>
  
  |Endpoint|Method|Example|
  |:-:|:-:|-|
  |`/reset-password`|POST|`http://localhost:8080/reset-password`|

  Example Request
  ```json
  {
      "email": "myexample@gmail.com"
  }
  ```
  Example Response
  ```json
  {
      "statusCode": 200,
      "message": "successfully"
  }
  ```

  <kbd>
    <img src="./other/email.png" style="border: 2px solid  gray;">
  </kbd>
</li>
<li>
  <h4>Change-Password <strong>(2 Ways)</strong></h4>
  
  <strong>1st</strong> : When logging in, update your password by supplying the old one and specifying the new password.
  
  |Endpoint|Method|Example|
  |:-:|:-:|-|
  |`/change-password`|POST|`http://localhost:8080/change-password`|

  Example Request
  ```json
  {
      "oldPassword": "123456789"
      "newPassword": "987654321"
  }
  ```
  Example Response
  ```json
  {
      "statusCode": 200,
      "message": "successfully"
  }
  ```

  <strong>2nd</strong> : Reset your password using the token you received in an email.
  
  |Endpoint|Method|Example|
  |:-:|:-:|-|
  |`/change-password`|POST|`http://localhost:8080/change-password?token=xxxxxxxxxxxxx`|

  Example Request
  ```json
  {
      "newPassword": "987654321"
  }
  ```
  Example Response
  ```json
  {
      "statusCode": 200,
      "message": "successfully"
  }
  ```
</li>
</ul>

<h2>API Gateway</h2>
<ul>
<li>
  <h4>Overview</h4>
  
  The API Gateway is like a middleman between your users and different services. It's a central hub that helps send requests to different services using specific aliases. This makes it easier to keep service details hidden and lets you smoothly connect with many backend services. In this example, suppose that the target service is the [Pokémon API](https://pokeapi.co/).
</li>
<li>
  <h4>Configuration in .env file</h4>
  
  In your `.env` file, you can define a list of services with their corresponding hosts and aliases using the `SERVICE_LISTS` variable. Each service should be represented as a JSON object with `host` and `alias` keys.

  ```env
  SERVICE_LISTS=[{ "host": "https://pokeapi.co", "alias": "/pokeapi" }]
  ```

  `host` : The base URL of the target service.
  
  `alias` : The alias used by the API Gateway to identify the target service.
</li>
<li>
  <h4>Request Structure</h4>
  
  Clients can make requests to the API Gateway using the following URL structure
  ```
  http://localhost:8080/gateway/<SERVICE_ALIAS>/<SERVICE_ENDPOINT>
  ```

`<SERVICE_ALIAS>`: The alias specified for the desired service.

`<SERVICE_ENDPOINT>`: The path specific to the service.
</li>





<li>
  <h4>Usage</h4>
  
  |Endpoint|Method|Example|
  |:-:|:-:|-|
  |`/gateway/<SERVICE_ALIAS>/<SERVICE_ENDPOINT>`|ANY|`http://localhost:8080/gateway/pokeapi/api/v2/pokemon`|

  `/gateway` is the base path for the API Gateway.
  
  `/pokeapi` is the alias specified for the PokeAPI service.
  
  `/api/v2/pokemon/` is the specific route for retrieving Pokémon information.

  Example Request

  ```
  GET http://localhost:8080/gateway/pokeapi/api/v2/pokemon/
  ```
  
  Example Response
  ```json
  {
      "count": 1302,
      "next": "https://pokeapi.co/api/v2/pokemon/?offset=20&limit=20",
      "previous": null,
      "results": [
          {
              "name": "bulbasaur",
              "url": "https://pokeapi.co/api/v2/pokemon/1/"
          },
          {
              "name": "ivysaur",
              "url": "https://pokeapi.co/api/v2/pokemon/2/"
          },
          {
              "name": "venusaur",
              "url": "https://pokeapi.co/api/v2/pokemon/3/"
          },
          ...
          ...
          ...
      ]
  }
  ```
</li>
<li>
  <h4>Internal Processing</h4>
  
  ```mermaid
  sequenceDiagram
    participant C as Client
    participant G as API Gateway
    participant S as Service

    rect rgb(204, 255, 204)
    autonumber 1
    C->>G: GET /gateway/pokeapi/api/v2/pokemon
    note over C, G: Valid Access Token
    note over C, G: Valid Refresh Token
    G->>S: GET /api/v2/pokemon
    note over G: Authorized
    S->>G: 200 OK & JSON Response
    G->>C: 200 OK & JSON Response
    end

    rect rgb(204, 255, 204)
    autonumber 1
    C->>G: GET /gateway/pokeapi/api/v2/pokemon
    note over C, G: Invalid Access Token
    note over C, G: Valid Refresh Token
    G->>S: GET /api/v2/pokemon
    note over G: Generate New Access Token and Refresh Token
    S->>G: 200 OK & JSON Response
    G->>C: 200 OK & JSON Response
    note over C, G: New Access and Refresh Tokens
    end

    rect rgb(255, 153, 153)
    autonumber 1
    C->>G: GET /gateway/pokeapi/api/v2/pokemon
    note over C, G: Invalid Access Token
    note over C, G: Invalid Refresh Token
    G->>C: 401 Unauthorized
    note over G: Unauthorized
    end
  ```

  After authorization, the API Gateway utilizes the information provided in the `SERVICE_LISTS` environment variable to route requests.
  
  <p>1. Identifies the alias /pokeapi in the request path.</p>
  
  <p>2. Replaces the host portion with the corresponding host value from the environment variables.</p>
  
  <p>3. Removes the /gateway segment from the path.</p>
  
  <p>4. Adds the remaining path api/v2/pokemon/ to the modified host.</p>
  
  <p>5. Finally, forwards the request to the next service, resulting in the target URL:</p>
  
  
  ```
  GET https://pokeapi.co/api/v2/pokemon
  ```
</li>
</ul>
