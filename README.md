# YUVI SDK — Alag Worker (JS + Cloudflare)

Main panel se **SDK alag** kar diya hai. Ye zip sirf SDK ke liye hai.

## Kya hai isme
- `POST /sdk/mundo/:panel_code` — AES-128-ECB (salt: `https://mundo.cp.cheat/v2/api/verify`), payload `S1|S2|S3_A|S3_B`
- `POST /sdk/bcore/:panel_code` — RC4+Base64 (key: `YuviMatrix_Secure_2026`), JSON `{sdk_key, pkg_name, app_name, device_id}`
- Dashboard: `/` `/sdk/generate` `/sdk/keys` `/sdk/server` `/sdk/hash`
- Sirf **uid=1 OWNER YUVI_001** dashboard khol sakta hai (PHP jaisa hi rule)

## Deploy
1. D1 banao `yuvi_sdk`, `schema.sql` execute karo
2. `wrangler.toml` me `database_id` + `JWT_SECRET` bharo
3. `worker.js` deploy (dashboard paste ya `npx wrangler deploy`)
4. `/setup` kholo — admin/Admin@123 banta hai
5. `/sdk/server` me endpoints milenge:
   - `https://xxx.workers.dev/sdk/mundo/YUVI_001`
   - `https://xxx.workers.dev/sdk/bcore/YUVI_001`

## Client parity (PHP se match)
- MUNDO key derive: `key[i] = salt[i%len] XOR (len+i)` (16 bytes), AES-128-ECB PKCS7, base64
- BCORE: RC4 + base64, CESU-8 fancy-label fix included
- Expiry: `created_at + duration_days`, maintenance via `sdk_server_status`
- Limits: `pkg_limit`, `app_limit`, auto-bind on first seen, block supported
