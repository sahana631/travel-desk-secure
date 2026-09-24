# Travel Desk

A straightforward Flask and SQLite travel desk for booking trips and organizing itinerary items.

## Run locally

```bash
SECRET_KEY="replace-with-a-long-random-value" python main.py
```

Then open the app over HTTPS. `SECRET_KEY` is required and must be supplied through the environment; it is never hardcoded by the application. The secure session-cookie setting means a plain `http://localhost` browser session will not persist unless you run it behind HTTPS.

The SQLite database is created automatically as `travel_desk_secure.db` on first run. Set `DATABASE_URL` to use a different database URL and `SECRET_KEY` to provide the Flask session key. For production, also set `RATELIMIT_STORAGE_URI` to a shared rate-limit backend instead of the default in-memory store.

## Included

- Create an account and log in
- Book, view, edit, and delete trips
- Add flights, hotels, activities, and other itinerary items
- View itinerary items in chronological order for each trip