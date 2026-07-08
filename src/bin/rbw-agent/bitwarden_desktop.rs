// Client for the Bitwarden desktop app's browser-integration IPC interface.
// This is the same protocol the official browser extension uses for "unlock
// with biometrics": we ask the desktop app to unlock the account, it shows
// the OS biometric prompt, and on success it hands back the account's user
// key.
//
// The protocol is internal to Bitwarden and can change between desktop app
// releases.

use anyhow::Context as _;
use serde::Deserialize as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn user_id_from_access_token(access_token: &str) -> anyhow::Result<String> {
    #[derive(serde::Deserialize)]
    struct Claims {
        sub: String,
    }

    let payload = access_token
        .split('.')
        .nth(1)
        .context("access token is not a jwt")?;
    let payload = rbw::base64::decode_url_safe_no_pad(payload)
        .context("failed to decode jwt payload")?;
    let claims: Claims = serde_json::from_slice(&payload)
        .context("failed to parse jwt claims")?;
    Ok(claims.sub)
}

// the desktop app frames its ipc messages with a 4-byte native-endian
// length prefix (tokio's LengthDelimitedCodec configured as native_endian,
// max frame 1MiB)
const MAX_FRAME_LEN: u32 = 1024 * 1024;

// convert a CipherString into the EncStringObj format expected by the
// desktop app (matching the browser extension's serialization)
fn cipherstring_to_enc_obj(
    cs: &rbw::cipherstring::CipherString,
) -> anyhow::Result<EncStringObj> {
    match cs {
        rbw::cipherstring::CipherString::Symmetric {
            iv,
            ciphertext,
            mac,
        } => Ok(EncStringObj {
            encrypted_string: cs.to_string(),
            encryption_type: 2,
            data: rbw::base64::encode(ciphertext),
            iv: rbw::base64::encode(iv),
            mac: mac.as_ref().map(rbw::base64::encode),
        }),
        rbw::cipherstring::CipherString::Asymmetric { .. } => {
            Err(anyhow::anyhow!(
                "asymmetric cipherstring not supported for ipc"
            ))
        }
    }
}

async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(
    stream: &mut W,
    data: &[u8],
) -> anyhow::Result<()> {
    let len = u32::try_from(data.len()).context("ipc message too large")?;
    if len > MAX_FRAME_LEN {
        return Err(anyhow::anyhow!("ipc message too large ({len} bytes)"));
    }
    stream.write_all(&len.to_ne_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_frame<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
) -> anyhow::Result<Vec<u8>> {
    let mut len = [0; 4];
    stream.read_exact(&mut len).await?;
    let len = u32::from_ne_bytes(len);
    if len > MAX_FRAME_LEN {
        return Err(anyhow::anyhow!("oversized ipc frame ({len} bytes)"));
    }
    let mut buf = vec![0; usize::try_from(len)?];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

#[derive(serde::Serialize)]
struct SetupEncryption<'a> {
    command: &'static str,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "userId")]
    user_id: &'a str,
    #[serde(rename = "messageId")]
    message_id: u32,
}

#[derive(serde::Serialize)]
struct EncryptedWrapper<'a> {
    #[serde(rename = "appId")]
    app_id: &'a str,
    #[serde(rename = "messageId")]
    message_id: u32,
    message: EncStringObj,
}

// the desktop app expects the encrypted message as an object (matching
// the browser extension's EncString serialization), not a plain string.
// see: apps/browser/src/background/nativeMessaging.background.ts postMessage()
#[derive(serde::Serialize)]
struct EncStringObj {
    #[serde(rename = "encryptedString")]
    encrypted_string: String,
    #[serde(rename = "encryptionType")]
    encryption_type: u8,
    data: String,
    iv: String,
    mac: Option<String>,
}

#[derive(serde::Serialize)]
struct UnlockRequest<'a> {
    command: &'static str,
    #[serde(rename = "userId")]
    user_id: &'a str,
    #[serde(rename = "messageId")]
    message_id: u32,
    timestamp: u64,
}

// the desktop app expects all messages wrapped as
// { "appId": <client uuid>, "message": <inner message> }
#[derive(serde::Serialize)]
struct LegacyMessageWrapper<'a, T> {
    #[serde(rename = "appId")]
    app_id: &'a str,
    message: T,
}

// frames from the app are a mix of plaintext control messages and
// encrypted wrappers; parse leniently and pick out what we need
#[derive(serde::Deserialize)]
struct IncomingFrame {
    command: Option<String>,
    #[serde(rename = "sharedSecret")]
    shared_secret: Option<String>,
    #[serde(default, deserialize_with = "deserialize_enc_string")]
    message: Option<String>,
}

// the desktop app may send the encrypted message as either a plain
// string ("2.iv|ct|mac") or as an EncString object
// ({encryptedString, encryptionType, data, iv, mac}). extract the
// string form either way.
fn deserialize_enc_string<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<serde_json::Value> =
        Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s)),
        Some(serde_json::Value::Object(obj)) => {
            obj.get("encryptedString")
                .and_then(|v| v.as_str())
                .map(|s| Some(s.to_string()))
                .ok_or_else(|| {
                    serde::de::Error::custom(
                        "EncString object missing encryptedString field",
                    )
                })
        }
        _ => Err(serde::de::Error::custom(
            "expected message to be a string or EncString object",
        )),
    }
}

#[derive(serde::Deserialize)]
struct UnlockResponse {
    command: Option<String>,
    response: Option<serde_json::Value>,
    #[serde(rename = "userKeyB64")]
    user_key_b64: Option<String>,
}

pub async fn unlock_user_key(
    access_token: &str,
) -> anyhow::Result<rbw::locked::Keys> {
    let user_id = user_id_from_access_token(access_token)?;
    let mut stream = connect().await?;
    // the response only arrives once the user passes (or cancels) the os
    // biometric prompt, so allow plenty of time before giving up
    tokio::time::timeout(
        std::time::Duration::from_secs(120),
        unlock_on_stream(&mut stream, &user_id),
    )
    .await
    .context("timed out waiting for biometric unlock")?
}

fn candidate_socket_paths() -> Vec<std::path::PathBuf> {
    let Some(home) =
        std::env::var_os("HOME").map(std::path::PathBuf::from)
    else {
        return vec![];
    };
    let mut paths = vec![];
    if cfg!(target_os = "macos") {
        paths.push(home.join(
            "Library/Group Containers/LTZ2PFU5D6.com.bitwarden.desktop/s.bw",
        ));
        // non-sandboxed (e.g. homebrew) desktop app uses the rust cache
        // dir, which is ~/Library/Caches on macos
        paths.push(home.join("Library/Caches/com.bitwarden.desktop/s.bw"));
    }
    paths.push(home.join(".cache/com.bitwarden.desktop/s.bw"));
    // a flatpak-sandboxed desktop app can't use the path above, so it
    // creates its socket inside browser config dirs instead
    for path in [
        ".var/app/org.mozilla.firefox/.mozilla/native-messaging-hosts/.app.bw.socket",
        ".var/app/com.google.Chrome/config/google-chrome/NativeMessagingHosts/.app.bw.socket",
        ".var/app/org.chromium.Chromium/config/chromium/NativeMessagingHosts/.app.bw.socket",
        ".var/app/com.microsoft.Edge/config/microsoft-edge/NativeMessagingHosts/.app.bw.socket",
        ".mozilla/native-messaging-hosts/.app.bw.socket",
        ".config/google-chrome/NativeMessagingHosts/.app.bw.socket",
        ".config/chromium/NativeMessagingHosts/.app.bw.socket",
        ".config/microsoft-edge/NativeMessagingHosts/.app.bw.socket",
    ] {
        paths.push(home.join(path));
    }
    paths
}

async fn connect() -> anyhow::Result<tokio::net::UnixStream> {
    for path in candidate_socket_paths() {
        if let Ok(stream) = tokio::net::UnixStream::connect(&path).await {
            log::debug!(
                "connected to bitwarden desktop app at {}",
                path.display()
            );
            return Ok(stream);
        }
    }
    Err(anyhow::anyhow!(
        "couldn't find the bitwarden desktop app socket (is the app \
         running with browser integration enabled?)"
    ))
}

async fn unlock_on_stream<S>(
    stream: &mut S,
    user_id: &str,
) -> anyhow::Result<rbw::locked::Keys>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // items before statements, or clippy::items_after_statements fires
    use rsa::pkcs8::EncodePublicKey as _;
    use zeroize::Zeroize as _;

    // establish the encrypted channel: send an ephemeral rsa public key,
    // get back a 64-byte shared secret encrypted to it
    let mut rng = rand_8::rngs::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048)
        .context("failed to generate rsa key")?;

    let public_key_der = private_key
        .to_public_key()
        .to_public_key_der()
        .context("failed to encode rsa public key")?;

    let app_id = uuid::Uuid::new_v4().hyphenated().to_string();

    let setup_msg = serde_json::to_vec(&LegacyMessageWrapper {
        app_id: &app_id,
        message: SetupEncryption {
            command: "setupEncryption",
            public_key: rbw::base64::encode(
                public_key_der.as_bytes(),
            ),
            user_id,
            message_id: 0,
        },
    })?;
    log::debug!(
        "sending setupEncryption: appId={}, userId={}, payload={}",
        app_id,
        user_id,
        String::from_utf8_lossy(&setup_msg)
    );
    write_frame(stream, &setup_msg).await?;
    log::debug!("setupEncryption sent, waiting for response...");

    let shared_secret = loop {
        let frame = read_frame(stream).await?;
        log::debug!(
            "received ipc frame: {}",
            String::from_utf8_lossy(&frame)
        );
        let msg: IncomingFrame = serde_json::from_slice(&frame)?;
        if let Some(shared_secret) = msg.shared_secret {
            break shared_secret;
        }
        if msg.command.as_deref() == Some("wrongUserId") {
            return Err(anyhow::anyhow!(
                "bitwarden desktop app doesn't recognize this user \
                 id (is the same account logged in in the desktop \
                 app?)"
            ));
        }
        // the app can broadcast unrelated messages at any time; skip them
        log::debug!("skipping ipc message: {:?}", msg.command);
    };

    let shared_secret = rbw::base64::decode(&shared_secret)
        .map_err(|e| anyhow::anyhow!("invalid shared secret: {e}"))?;
    log::debug!("shared secret decoded ({} bytes), decrypting with RSA...", shared_secret.len());
    let mut shared_secret = private_key
        .decrypt(rsa::Oaep::new::<sha1::Sha1>(), &shared_secret)
        .context("failed to decrypt shared secret")?;
    log::debug!("shared secret decrypted, len={}", shared_secret.len());
    if shared_secret.len() != 64 {
        return Err(anyhow::anyhow!(
            "unexpected shared secret length {}",
            shared_secret.len()
        ));
    }
    let mut secret = rbw::locked::Vec::new();
    secret.extend(shared_secret.iter().copied());
    shared_secret.zeroize();
    let channel_keys = rbw::locked::Keys::new(secret);

    // ask the app to unlock; it shows the os biometric prompt and answers
    // with the account's user key
    let timestamp = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?;
    let mut inner = serde_json::to_vec(&UnlockRequest {
        command: "unlockWithBiometricsForUser",
        user_id,
        message_id: 1,
        timestamp,
    })?;
    log::debug!("encrypting unlock request, timestamp={timestamp}, user_id={user_id}");
    let encrypted = rbw::cipherstring::CipherString::encrypt_symmetric(
        &channel_keys,
        &inner,
    )?;
    inner.zeroize();
    let enc_obj = cipherstring_to_enc_obj(&encrypted)?;
    let unlock_msg = serde_json::to_vec(&EncryptedWrapper {
        app_id: &app_id,
        message_id: 1,
        message: enc_obj,
    })?;
    log::debug!("sending unlock request (appId={app_id}): {}", String::from_utf8_lossy(&unlock_msg));
    write_frame(stream, &unlock_msg).await?;
    log::debug!("unlock request sent, waiting for biometric response...");

    loop {
        let frame = read_frame(stream).await?;
        log::debug!("received response frame: {}", String::from_utf8_lossy(&frame));
        let msg: IncomingFrame = serde_json::from_slice(&frame)?;
        let Some(message) = msg.message else {
            if msg.command.as_deref()
                == Some("invalidateEncryption")
            {
                return Err(anyhow::anyhow!(
                    "bitwarden desktop app invalidated the \
                     encryption channel"
                ));
            }
            log::debug!("skipping ipc message: {:?}", msg.command);
            continue;
        };
        // the app can broadcast unrelated encrypted messages too (e.g.
        // other accounts' unlock notifications); anything that doesn't
        // decrypt and parse as our response is just skipped
        let Ok(cipherstring) =
            rbw::cipherstring::CipherString::new(&message)
        else {
            log::debug!("skipping ipc message: not a cipherstring");
            continue;
        };
        let Ok(mut plaintext) =
            cipherstring.decrypt_symmetric(&channel_keys, None)
        else {
            log::debug!("skipping ipc message: failed to decrypt");
            continue;
        };
        let response: Result<UnlockResponse, _> =
            serde_json::from_slice(&plaintext);
        plaintext.zeroize();
        let Ok(response) = response else {
            log::debug!("skipping ipc message: failed to parse");
            continue;
        };
        if response.command.as_deref()
            != Some("unlockWithBiometricsForUser")
        {
            log::debug!("skipping ipc message: {:?}", response.command);
            continue;
        }
        let Some(mut user_key_b64) = response.user_key_b64 else {
            return Err(anyhow::anyhow!(
                "bitwarden desktop app refused to unlock: {:?}",
                response.response
            ));
        };
        let user_key = rbw::base64::decode(&user_key_b64);
        user_key_b64.zeroize();
        let mut user_key =
            user_key.map_err(|e| anyhow::anyhow!("invalid user key: {e}"))?;
        if user_key.len() != 64 {
            let len = user_key.len();
            user_key.zeroize();
            return Err(anyhow::anyhow!("unexpected user key length {len}"));
        }
        let mut key = rbw::locked::Vec::new();
        key.extend(user_key.iter().copied());
        user_key.zeroize();
        return Ok(rbw::locked::Keys::new(key));
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt as _;

    #[test]
    fn user_id_from_access_token() {
        // only the payload matters; header and signature are not validated
        let token = format!(
            "x.{}.y",
            rbw::base64::encode_url_safe_no_pad(
                br#"{"sub":"11111111-2222-3333-4444-555555555555","email":"me@example.com"}"#
            )
        );
        assert_eq!(
            super::user_id_from_access_token(&token).unwrap(),
            "11111111-2222-3333-4444-555555555555"
        );
        assert!(super::user_id_from_access_token("garbage").is_err());

        // payload isn't valid base64url
        assert!(super::user_id_from_access_token("x.!!!.y").is_err());

        // payload is valid base64url but not json
        let token = format!(
            "x.{}.y",
            rbw::base64::encode_url_safe_no_pad(b"notjson")
        );
        assert!(super::user_id_from_access_token(&token).is_err());

        // valid json but missing the sub claim
        let token = format!(
            "x.{}.y",
            rbw::base64::encode_url_safe_no_pad(br#"{"email":"a@b.c"}"#)
        );
        assert!(super::user_id_from_access_token(&token).is_err());
    }

    #[tokio::test]
    async fn frame_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        super::write_frame(&mut a, b"{\"hello\":true}").await.unwrap();
        assert_eq!(
            super::read_frame(&mut b).await.unwrap(),
            b"{\"hello\":true}"
        );
    }

    #[tokio::test]
    async fn read_frame_rejects_oversized_length() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let oversized_len = 2 * 1024 * 1024_u32;
        a.write_all(&oversized_len.to_ne_bytes()).await.unwrap();
        assert!(super::read_frame(&mut b).await.is_err());
    }

    #[tokio::test]
    async fn write_frame_rejects_oversized_payload() {
        let (mut a, _b) = tokio::io::duplex(4096);
        let data = vec![0; 2 * 1024 * 1024];
        assert!(super::write_frame(&mut a, &data).await.is_err());
    }

    // server side of the handshake plus reading the client's unlock
    // request; returns the shared channel keys so the caller can send
    // whatever frames it wants (real response, broadcasts, ...) afterward
    async fn mock_handshake_and_unlock_request<S>(
        server: &mut S,
    ) -> rbw::locked::Keys
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use rsa::pkcs8::DecodePublicKey as _;

        // setupEncryption
        let frame = super::read_frame(server).await.unwrap();
        let msg: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(msg["message"]["command"], "setupEncryption");
        assert_eq!(msg["message"]["userId"], "some-user");
        assert!(msg["appId"].is_string());
        let client_pubkey = rsa::RsaPublicKey::from_public_key_der(
            &rbw::base64::decode(
                msg["message"]["publicKey"].as_str().unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

        let secret: Vec<u8> = (100..164).collect(); // 64 bytes
        let mut rng = rand_8::rngs::OsRng;
        let encrypted_secret = client_pubkey
            .encrypt(&mut rng, rsa::Oaep::new::<sha1::Sha1>(), &secret)
            .unwrap();
        super::write_frame(
            server,
            &serde_json::to_vec(&serde_json::json!({
                "command": "setupEncryption",
                "appId": "test-app",
                "messageId": -1,
                "sharedSecret": rbw::base64::encode(&encrypted_secret),
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        let mut locked = rbw::locked::Vec::new();
        locked.extend(secret.iter().copied());
        let keys = rbw::locked::Keys::new(locked);

        // unlock request
        let frame = super::read_frame(server).await.unwrap();
        let msg: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        // message is now an EncString object, not a plain string
        let enc_str = msg["message"]["encryptedString"]
            .as_str()
            .unwrap();
        let cipherstring =
            rbw::cipherstring::CipherString::new(enc_str).unwrap();
        let inner = cipherstring.decrypt_symmetric(&keys, None).unwrap();
        let inner: serde_json::Value =
            serde_json::from_slice(&inner).unwrap();
        assert_eq!(inner["command"], "unlockWithBiometricsForUser");
        assert_eq!(inner["userId"], "some-user");
        assert!(inner["timestamp"].is_u64());

        keys
    }

    // mock desktop app: performs the server side of the handshake, then
    // answers one unlock request with the given closure's response body
    async fn mock_desktop_server<S>(
        mut server: S,
        respond: impl FnOnce() -> serde_json::Value,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let keys = mock_handshake_and_unlock_request(&mut server).await;

        // encrypted response
        let response = serde_json::to_vec(&respond()).unwrap();
        let encrypted = rbw::cipherstring::CipherString::encrypt_symmetric(
            &keys, &response,
        )
        .unwrap();
        super::write_frame(
            &mut server,
            &serde_json::to_vec(&serde_json::json!({
                "appId": "test-app",
                "message": encrypted.to_string(),
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn handshake_and_unlock() {
        let (mut client, server) = tokio::io::duplex(1024 * 1024);
        let user_key: Vec<u8> = (0..64).collect();
        let expected = user_key.clone();
        let server_task = tokio::spawn(mock_desktop_server(server, move || {
            serde_json::json!({
                "command": "unlockWithBiometricsForUser",
                "response": true,
                "messageId": 1,
                "userKeyB64": rbw::base64::encode(&user_key),
            })
        }));

        let keys = super::unlock_on_stream(&mut client, "some-user")
            .await
            .unwrap();
        assert_eq!(keys.enc_key(), &expected[..32]);
        assert_eq!(keys.mac_key(), &expected[32..]);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn unlock_refused() {
        let (mut client, server) = tokio::io::duplex(1024 * 1024);
        let server_task = tokio::spawn(mock_desktop_server(server, || {
            serde_json::json!({
                "command": "unlockWithBiometricsForUser",
                "response": false,
                "messageId": 1,
            })
        }));

        assert!(super::unlock_on_stream(&mut client, "some-user")
            .await
            .is_err());
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn interleaved_broadcast_frames_are_skipped() {
        let (mut client, server) = tokio::io::duplex(1024 * 1024);
        let user_key: Vec<u8> = (0..64).collect();
        let expected = user_key.clone();
        let server_task = tokio::spawn(async move {
            let mut server = server;
            let keys =
                mock_handshake_and_unlock_request(&mut server).await;

            // (a) unrelated plaintext broadcast frame
            super::write_frame(
                &mut server,
                &serde_json::to_vec(&serde_json::json!({
                    "command": "status",
                }))
                .unwrap(),
            )
            .await
            .unwrap();

            // (b) unrelated encrypted broadcast frame (e.g. another
            // account's unlock notification)
            let broadcast = serde_json::to_vec(&serde_json::json!({
                "command": "status",
                "userId": "some-other-user",
            }))
            .unwrap();
            let encrypted_broadcast =
                rbw::cipherstring::CipherString::encrypt_symmetric(
                    &keys, &broadcast,
                )
                .unwrap();
            super::write_frame(
                &mut server,
                &serde_json::to_vec(&serde_json::json!({
                    "appId": "test-app",
                    "message": encrypted_broadcast.to_string(),
                }))
                .unwrap(),
            )
            .await
            .unwrap();

            // (c) the real encrypted unlock response
            let response = serde_json::to_vec(&serde_json::json!({
                "command": "unlockWithBiometricsForUser",
                "response": true,
                "messageId": 1,
                "userKeyB64": rbw::base64::encode(&user_key),
            }))
            .unwrap();
            let encrypted = rbw::cipherstring::CipherString::encrypt_symmetric(
                &keys, &response,
            )
            .unwrap();
            super::write_frame(
                &mut server,
                &serde_json::to_vec(&serde_json::json!({
                    "appId": "test-app",
                    "message": encrypted.to_string(),
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        });

        let keys = super::unlock_on_stream(&mut client, "some-user")
            .await
            .unwrap();
        assert_eq!(keys.enc_key(), &expected[..32]);
        assert_eq!(keys.mac_key(), &expected[32..]);
        server_task.await.unwrap();
    }
}
