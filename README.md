# ProPlan WebApp mit Benutzerverwaltung

Python-WebApp mit Benutzerverwaltung und Rollen:
- **admin**
- **projektleiter**
- **bearbeiter**

## Features
- Login, Logout, Registrierung
- Rollenbasierte Zugriffssteuerung
- Benutzerverwaltung für `admin` und `projektleiter`
- Bootstrap 5 Layout mit:
  - Header
  - linker Spalte
  - rechter Spalte
  - Content-Bereich

## Lokal starten (Port 5050)

```bash
PORT=5050 python app.py
```

Danach: `http://localhost:5050`

### Standard-Admin
- Benutzername: `admin`
- Passwort: `admin123`

## Docker (Port 5050)

```bash
docker compose up -d --build
```

Danach: `http://<server-ip>:5050`

## Synology Deployment (updatesicher mit Volume)
1. Lege auf der Synology einen persistenten Ordner an, z. B.:
   - `/volume1/docker/proplan/db`
2. In `docker-compose.yml` ist dieses Volume bereits als Bind-Mount auf `/data` vorgesehen.
3. Die SQLite-Datenbank liegt im Container unter `/data/proplan.sqlite` und bleibt bei Container-Updates erhalten.
4. Updates durchführen:
   ```bash
   docker compose pull
   docker compose up -d --build
   ```

## Tests

```bash
python -m unittest discover -s tests -v
```
