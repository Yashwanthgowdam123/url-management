# URL Inventory
Flask + SQLite. Public: view + add URLs. Admin login: edit + delete.
Data persists in Docker volume `url_inventory_data`; container uses `restart: always`.

## Local test
SECRET_KEY=x ADMIN_USER=admin ADMIN_PASSWORD=pass HOST_PORT=8080 docker compose up -d --build
