# User Service (Node.js + Express + MySQL)

## Endpoints
- `GET /health` — service health.
- `POST /signup` — { email, password, name }.
- `POST /login` — { email, password } → { token }.
- `GET /me` — Authorization: Bearer <token>.

## Local dev (without docker)
1. Install deps: `npm i`
2. Export env vars for DB and JWT, or create a `.env` loader (not included).
3. Run: `npm start`

## Tests
```
npm test
```

- `POST /reset-password` — { email, newPassword }.
- `PUT /profile` — { name } (JWT required).
