# SCA Dashboard Node

Software Composition Analysis con Node.js.

## Requisitos

- Node.js 18 o superior

## Ejecutar

```bash
npm install
```

Opcional, para usar Snyk como proveedor real:

```bash
export SNYK_TOKEN=tu_token_de_snyk
```

```bash
npm start
```

Abrir en el navegador:

```text
http://localhost:3000
```

## Ejecutar con Docker

```bash
docker compose up --build
```

Con Snyk:

```bash
export SNYK_TOKEN=tu_token_de_snyk
docker compose up --build
```
