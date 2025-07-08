CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  refresh_token TEXT NOT NULL,
  refresh_expire_dt_tm DATETIME NOT NULL,
  access_token TEXT NOT NULL,
  icon_url TEXT NOT NULL,
  subscribed BOOLEAN NOT NULL,
  subscription_dt_tm DATETIME NOT NULL,
  remaining_uploads INTEGER NOT NULL,
  upload_refresh_dt_tm DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS apikeys (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL UNIQUE,
  apikey TEXT NOT NULL UNIQUE,
  created_dt_tm DATETIME NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

-- CREATE TABLE IF NOT EXISTS ratelimit (
--   id INTEGER PRIMARY KEY,
--   user_id TEXT NOT NULL,
--   calls_remaining INTEGER NOT NULL,
--   reset_dt_tm TEXT NOT NULL
-- );
