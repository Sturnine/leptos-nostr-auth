#[cfg(not(feature = "ssr"))]
use crate::types::{NostrAuthError, PersistedSession};

/// Attempt to restore a full `AuthResult` from a `PersistedSession`.
///
/// Save/load/clear are handled by the `use_local_storage` hook in `NostrAuthProvider`.
///
/// Each method has different restore semantics:
/// - `Extension`: verify window.nostr still returns the same pubkey
/// - `Bunker`: re-establish WebSocket connection using stored bunker URI
/// - `Passkey`: call `navigator.credentials.get()` → PRF → rederive key
/// - `ReadOnly`: restore directly from hex pubkey (no re-auth needed)
#[cfg(not(feature = "ssr"))]
pub async fn restore_session(
    session: &PersistedSession,
    bunker_timeout_secs: u32,
) -> Result<crate::signers::AuthResult, NostrAuthError> {
    #[cfg(feature = "ssr")]
    {
        let _ = (session, bunker_timeout_secs);
        // Unreachable in practice — this is only called from inside an Effect (client-only).
        return Err(NostrAuthError::ExtensionNotFound);
    }

    #[cfg(not(feature = "ssr"))]
    {
        use crate::types::PersistedMethod;
        use nostr::PublicKey;

        let stored_pk = PublicKey::from_hex(&session.public_key_hex)
            .map_err(|e| NostrAuthError::InvalidPublicKey(e.to_string()))?;

        match session.method {
            PersistedMethod::Extension => {
                let handle = crate::signers::Nip07Handle::get_public_key().await?;
                if handle.public_key != stored_pk {
                    return Err(NostrAuthError::ExtensionRejected(
                        "Extension returned a different public key than the stored session".into(),
                    ));
                }
                Ok(crate::signers::AuthResult::Extension(handle))
            }
            PersistedMethod::Bunker => {
                let uri = session
                    .bunker_uri
                    .as_deref()
                    .ok_or_else(|| NostrAuthError::InvalidBunkerUri("no URI stored".into()))?;
                let client_secret_hex = session.bunker_client_secret_hex.as_deref().ok_or_else(
                    || NostrAuthError::InvalidBunkerUri("no session key stored".into()),
                )?;
                let session = crate::signers::BunkerSession::reconnect(
                    uri,
                    bunker_timeout_secs,
                    client_secret_hex,
                )
                .await?;
                if session.public_key != stored_pk {
                    return Err(NostrAuthError::BunkerConnectionFailed(
                        "Bunker returned a different public key than the stored session".into(),
                    ));
                }
                Ok(crate::signers::AuthResult::Bunker(Box::new(session)))
            }
            PersistedMethod::Passkey => {
                let cred_id_b64 = session.passkey_credential_id.as_deref().ok_or_else(|| {
                    NostrAuthError::PasskeyFailed("no credential ID stored".into())
                })?;
                let cred_id = base64::Engine::decode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    cred_id_b64,
                )
                .map_err(|e| NostrAuthError::PasskeyFailed(e.to_string()))?;
                let ps = crate::signers::PasskeySession::authenticate(Some(cred_id)).await?;
                if ps.public_key != stored_pk {
                    return Err(NostrAuthError::PasskeyFailed(
                        "Passkey derived a different public key than the stored session".into(),
                    ));
                }
                Ok(crate::signers::AuthResult::Passkey(ps))
            }
            PersistedMethod::ReadOnly => Ok(crate::signers::AuthResult::ReadOnly(
                crate::signers::ReadOnlyHandle {
                    public_key: stored_pk,
                },
            )),
        }
    }
}
