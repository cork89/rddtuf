-- name: GetUser :one
SELECT * FROM users
WHERE id=? LIMIT 1;

-- name: GetUserByUsername :one
SELECT * FROM users
WHERE username=? LIMIT 1;

-- name: CreateUser :one
INSERT INTO users (
  username, refresh_token, refresh_expire_dt_tm, access_token, icon_url, subscribed, subscription_dt_tm, remaining_uploads, upload_refresh_dt_tm
) VALUES (
  ?, ?, ?, ?, ?, ?, ?, ?, ?
)
RETURNING *;

-- name: UpdateUser :one
UPDATE users
SET access_token = ?
WHERE id = ?
RETURNING *;

-- name: GetUserIdByApikey :one
SELECT user_id FROM apikeys
WHERE apikey=? LIMIT 1;

-- name: GetApikeyByUserId :one
SELECT * FROM apikeys
WHERE user_id=? LIMIT 1;

-- name: CreateApiKey :one
INSERT INTO apikeys (
  user_id, apikey, created_dt_tm
) VALUES (
  ?, ?, ?
)
RETURNING *;

-- name: UpdateApiKey :one
UPDATE apikeys
SET apikey = ?, created_dt_tm = ?
WHERE user_id = ?
RETURNING *;

-- name: DeleteApiKey :exec
DELETE FROM apikeys
WHERE user_id = ?;
