#[cfg(not(feature = "ssr"))]
use nostr::event::Event;
use nostr::event::UnsignedEvent;
use nostr::key::PublicKey;

use crate::types::NostrAuthError;

/// NIP-46 lists `sign_event` params without `pubkey`, so an absent one is filled in. A `pubkey` or
/// `id` the session could not sign is refused here, so nothing reaches a signer.
///
/// Fixed texts: `serde_json` messages quote values.
pub(super) fn prepare(
    event_json: &str,
    session: PublicKey,
) -> Result<UnsignedEvent, NostrAuthError> {
    let mut value: serde_json::Value = serde_json::from_str(event_json).map_err(|e| {
        NostrAuthError::Serialization(format!(
            "event is not valid JSON at line {}, column {}",
            e.line(),
            e.column()
        ))
    })?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| NostrAuthError::Serialization("event must be a JSON object".into()))?;
    object
        .entry("pubkey")
        .or_insert_with(|| session.to_hex().into());
    let unsigned: UnsignedEvent = serde_json::from_value(value).map_err(|_error| {
        NostrAuthError::Serialization("event fields are missing or have the wrong type".into())
    })?;
    if unsigned.pubkey != session {
        return Err(NostrAuthError::SigningFailed(
            "event pubkey differs from the session key".into(),
        ));
    }
    if unsigned.id.is_some_and(|id| id != unsigned.compute_id()) {
        return Err(NostrAuthError::SigningFailed(
            "event id does not match its fields".into(),
        ));
    }
    Ok(unsigned)
}

/// Returns the verified value's JSON, never the signer's bytes, so extra fields cannot leave the
/// crate. Each failure has its own text because without them a removed field check would fall
/// through to the id check and go unnoticed.
#[cfg(not(feature = "ssr"))]
pub(super) fn checked_event(
    request: &UnsignedEvent,
    session: PublicKey,
    returned: &str,
) -> Result<String, NostrAuthError> {
    let failed = |text: &str| Err(NostrAuthError::SigningFailed(text.to_owned()));
    let Ok(event) = Event::from_json(returned) else {
        return failed("signer returned an invalid event");
    };
    if super::check_on_curve(&event.pubkey).is_err() {
        return failed("signer returned an invalid event");
    }
    // First, so a switched account reports the typed error even when other fields differ too.
    if event.pubkey != session {
        return Err(NostrAuthError::SignerKeyMismatch);
    }
    if event.kind != request.kind {
        return failed("signer changed the event kind");
    }
    if event.tags != request.tags {
        return failed("signer changed the event tags");
    }
    if event.content != request.content {
        return failed("signer changed the event content");
    }
    if event.created_at != request.created_at {
        return failed("signer changed the event created_at");
    }
    // The fields already equal the request's, so this is also the id recomputation.
    if event.id != request.compute_id() {
        return failed("signer returned a wrong event id");
    }
    if !event.verify_signature() {
        return failed("signer returned an invalid signature");
    }
    Ok(event.as_json())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod tests {
    use super::*;
    use crate::signers::signer_traits::tests::{ready, unsigned};
    use crate::signers::{PasskeySession, RawKeySession};
    use crate::types::AuthResult;
    use nostr::key::Keys;

    const PUBKEY_TEXT: &str = "Signing failed: event pubkey differs from the session key";
    const ID_TEXT: &str = "Signing failed: event id does not match its fields";

    fn absent() -> &'static str {
        r#"{"kind":1,"content":"hi","tags":[["t","x"]],"created_at":1700000000}"#
    }

    fn with_key(key: PublicKey) -> String {
        format!(
            r#"{{"pubkey":"{}","kind":1,"content":"hi","tags":[],"created_at":1700000000}}"#,
            key.to_hex()
        )
    }

    fn local(keys: &Keys) -> [AuthResult; 2] {
        [
            AuthResult::Ncryptsec(RawKeySession::for_tests(keys.clone())),
            AuthResult::Passkey(PasskeySession::for_tests(keys.clone(), vec![1])),
        ]
    }

    #[test]
    fn serialization_errors_quote_no_input() {
        let key = Keys::generate().public_key();
        for json in [
            r#"{"kind":1,"content":"x","tags":[],"created_at":"secret-time"}"#,
            r#"{"kind":"secret-kind","content":"x","tags":[],"created_at":1}"#,
            r#"{"kind":1,"content":"secret-text""#,
        ] {
            let err = prepare(json, key).unwrap_err().to_string();
            assert!(!err.contains("secret"), "{err}");
        }
    }

    #[test]
    fn absent_pubkey_is_filled_for_every_local_backend() {
        let keys = Keys::generate();
        for auth in local(&keys) {
            let signed = ready(auth.sign_event(absent())).unwrap();
            let event = nostr::event::Event::from_json(signed).unwrap();
            event.verify().unwrap();
            assert_eq!(event.pubkey, keys.public_key());
        }
    }

    #[test]
    fn request_pubkey_must_match() {
        let keys = Keys::generate();
        let other = with_key(Keys::generate().public_key());
        let err = prepare(&other, keys.public_key()).unwrap_err();
        assert_eq!(err.to_string(), PUBKEY_TEXT);
        for auth in local(&keys) {
            let err = ready(auth.sign_event(&other)).unwrap_err();
            assert_eq!(err.to_string(), PUBKEY_TEXT);
        }
    }

    #[test]
    fn preset_id_must_match() {
        let keys = Keys::generate();
        let session = keys.public_key();
        let mut event: serde_json::Value = serde_json::from_str(&with_key(session)).unwrap();
        let right = prepare(&with_key(session), session).unwrap().compute_id();
        let object = event.as_object_mut().unwrap();
        object.insert("id".to_owned(), right.to_hex().into());
        let kept = prepare(&event.to_string(), session).unwrap();
        assert_eq!(kept.id, Some(right));
        let object = event.as_object_mut().unwrap();
        object.insert("id".to_owned(), "ab".repeat(32).into());
        let err = prepare(&event.to_string(), session).unwrap_err();
        assert_eq!(err.to_string(), ID_TEXT);
        for auth in local(&keys) {
            let err = ready(auth.sign_event(&event.to_string())).unwrap_err();
            assert_eq!(err.to_string(), ID_TEXT);
        }
    }

    #[test]
    fn request_shape_errors() {
        let session = Keys::generate().public_key();
        let good = r#""kind":1,"content":"x","tags":[],"created_at":1700000000"#;
        let cases = [
            "{".to_owned(),
            "[1]".to_owned(),
            "\"x\"".to_owned(),
            r#"{"kind":1}"#.to_owned(),
            format!(r#"{{"id":"",{good}}}"#),
            format!(r#"{{"pubkey":null,{good}}}"#),
            r#"{"kind":1,"content":"x","tags":[[1]],"created_at":1700000000}"#.to_owned(),
            r#"{"kind":1,"content":"x","tags":[[]],"created_at":1700000000}"#.to_owned(),
            r#"{"kind":70000,"content":"x","tags":[],"created_at":1700000000}"#.to_owned(),
            r#"{"kind":1,"content":"x","tags":[],"created_at":1.5}"#.to_owned(),
        ];
        for case in cases {
            assert!(
                matches!(
                    prepare(&case, session),
                    Err(NostrAuthError::Serialization(_))
                ),
                "{case}"
            );
        }
    }

    #[test]
    fn read_only_precedes_parsing() {
        let auth = AuthResult::ReadOnly(crate::signers::ReadOnlyHandle {
            public_key: Keys::generate().public_key(),
        });
        let err = ready(auth.sign_event("{}")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Signing failed: Read-only session cannot sign events"
        );
    }

    #[cfg(not(feature = "ssr"))]
    mod returned {
        use super::*;
        use nostr::event::{Event, EventId, FinalizeEvent, Kind, Tag, Tags};
        use nostr::types::Timestamp;

        const INVALID: &str = "Signing failed: signer returned an invalid event";

        fn session() -> (Keys, UnsignedEvent) {
            let keys = Keys::generate();
            let request = UnsignedEvent::new(
                keys.public_key(),
                Timestamp::from_secs(1_700_000_000),
                Kind::TextNote,
                [Tag::hashtag("a"), Tag::hashtag("b")],
                "SENTINEL hi",
            );
            (keys, request)
        }

        fn resigned(
            keys: &Keys,
            request: &UnsignedEvent,
            change: impl FnOnce(&mut UnsignedEvent),
        ) -> String {
            let mut changed = request.clone();
            change(&mut changed);
            changed.finalize(keys).unwrap().as_json()
        }

        fn judged(keys: &Keys, request: &UnsignedEvent, returned: &str) -> String {
            checked_event(request, keys.public_key(), returned)
                .unwrap_err()
                .to_string()
        }

        #[test]
        fn returned_other_key() {
            let (keys, request) = session();
            let other = Keys::generate();
            let forged = resigned(&other, &request, |e| e.pubkey = other.public_key());
            let err = checked_event(&request, keys.public_key(), &forged).unwrap_err();
            assert!(matches!(err, NostrAuthError::SignerKeyMismatch));
        }

        #[test]
        fn off_curve_returned_pubkey_is_not_a_mismatch() {
            let (keys, request) = session();
            let mut value: serde_json::Value =
                serde_json::from_str(&request.clone().finalize(&keys).unwrap().as_json()).unwrap();
            let off = crate::signers::signer_traits::tests::off_curve().to_hex();
            value
                .as_object_mut()
                .unwrap()
                .insert("pubkey".to_owned(), off.into());
            let err = checked_event(&request, keys.public_key(), &value.to_string()).unwrap_err();
            assert!(!matches!(err, NostrAuthError::SignerKeyMismatch), "{err:?}");
        }

        #[test]
        fn returned_kind_changed() {
            let (keys, request) = session();
            let event = resigned(&keys, &request, |e| e.kind = Kind::Metadata);
            assert_eq!(
                judged(&keys, &request, &event),
                "Signing failed: signer changed the event kind"
            );
        }

        #[test]
        fn returned_tags_changed() {
            let (keys, request) = session();
            let event = resigned(&keys, &request, |e| {
                e.tags = Tags::from_list(vec![Tag::hashtag("a")]);
            });
            assert_eq!(
                judged(&keys, &request, &event),
                "Signing failed: signer changed the event tags"
            );
        }

        #[test]
        fn returned_content_changed() {
            let (keys, request) = session();
            let event = resigned(&keys, &request, |e| e.content = "other".to_owned());
            assert_eq!(
                judged(&keys, &request, &event),
                "Signing failed: signer changed the event content"
            );
        }

        #[test]
        fn returned_created_at_changed() {
            let (keys, request) = session();
            let event = resigned(&keys, &request, |e| e.created_at = Timestamp::from_secs(1));
            assert_eq!(
                judged(&keys, &request, &event),
                "Signing failed: signer changed the event created_at"
            );
        }

        #[test]
        fn returned_tags_reordered() {
            let (keys, request) = session();
            let event = resigned(&keys, &request, |e| {
                e.tags = Tags::from_list(vec![Tag::hashtag("b"), Tag::hashtag("a")]);
            });
            assert_eq!(
                judged(&keys, &request, &event),
                "Signing failed: signer changed the event tags"
            );
        }

        fn signed_over(keys: &Keys, request: &UnsignedEvent, id: EventId) -> String {
            let sig = keys.sign_schnorr(id.as_bytes());
            Event::new(
                id,
                request.pubkey,
                request.created_at,
                request.kind,
                request.tags.clone(),
                request.content.clone(),
                sig,
            )
            .as_json()
        }

        #[test]
        fn returned_bad_id() {
            let (keys, request) = session();
            let event = signed_over(&keys, &request, EventId::from_byte_array([7; 32]));
            assert_eq!(
                judged(&keys, &request, &event),
                "Signing failed: signer returned a wrong event id"
            );
        }

        #[test]
        fn returned_bad_sig() {
            let (keys, request) = session();
            let sig = keys.sign_schnorr([9; 32]);
            let event = Event::new(
                request.compute_id(),
                request.pubkey,
                request.created_at,
                request.kind,
                request.tags.clone(),
                request.content.clone(),
                sig,
            )
            .as_json();
            assert_eq!(
                judged(&keys, &request, &event),
                "Signing failed: signer returned an invalid signature"
            );
        }

        #[test]
        fn returned_sig_by_other_key() {
            let (keys, request) = session();
            let sig = Keys::generate().sign_schnorr(request.compute_id().as_bytes());
            let event = Event::new(
                request.compute_id(),
                request.pubkey,
                request.created_at,
                request.kind,
                request.tags.clone(),
                request.content.clone(),
                sig,
            )
            .as_json();
            assert_eq!(
                judged(&keys, &request, &event),
                "Signing failed: signer returned an invalid signature"
            );
        }

        #[test]
        fn all_wrong_reports_key_first() {
            let (keys, request) = session();
            let other = Keys::generate();
            let forged = resigned(&other, &request, |e| {
                e.pubkey = other.public_key();
                e.kind = Kind::Metadata;
                e.tags = Tags::new();
                e.content = "other".to_owned();
                e.created_at = Timestamp::from_secs(1);
            });
            let err = checked_event(&request, keys.public_key(), &forged).unwrap_err();
            assert!(matches!(err, NostrAuthError::SignerKeyMismatch));
        }

        #[test]
        fn returned_extra_fields_stripped() {
            let (keys, request) = session();
            let event = request.clone().finalize(&keys).unwrap();
            let mut value: serde_json::Value = serde_json::from_str(&event.as_json()).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert("nsec".to_owned(), "SENTINEL".into());
            let out = checked_event(&request, keys.public_key(), &value.to_string()).unwrap();
            assert_eq!(out, event.as_json());
            assert!(!out.contains("nsec"));
        }

        #[test]
        fn errors_carry_no_payload() {
            let (keys, request) = session();
            let other = Keys::generate();
            let mut extra: serde_json::Value =
                serde_json::from_str(&resigned(&keys, &request, |e| {
                    e.content = "SENTINEL other".to_owned();
                }))
                .unwrap();
            extra
                .as_object_mut()
                .unwrap()
                .insert("nsec".to_owned(), "SENTINEL".into());
            let returns = [
                r#"{"kind":"SENTINEL"}"#.to_owned(),
                extra.to_string(),
                resigned(&other, &request, |e| e.pubkey = other.public_key()),
                resigned(&keys, &request, |e| e.kind = Kind::Metadata),
                resigned(&keys, &request, |e| e.tags = Tags::new()),
                resigned(&keys, &request, |e| e.created_at = Timestamp::from_secs(1)),
                signed_over(&keys, &request, EventId::from_byte_array([7; 32])),
            ];
            for returned in returns {
                let err = checked_event(&request, keys.public_key(), &returned).unwrap_err();
                assert!(!err.to_string().contains("SENTINEL"), "{err}");
                assert!(!format!("{err:?}").contains("SENTINEL"), "{err:?}");
            }
        }

        #[test]
        fn valid_return_passes() {
            let (keys, request) = session();
            let event = request.clone().finalize(&keys).unwrap();
            let out = checked_event(&request, keys.public_key(), &event.as_json()).unwrap();
            let parsed = Event::from_json(out).unwrap();
            parsed.verify().unwrap();
            assert_eq!(parsed.kind, request.kind);
            assert_eq!(parsed.tags, request.tags);
            assert_eq!(parsed.content, request.content);
            assert_eq!(parsed.created_at, request.created_at);
        }

        #[test]
        fn preset_id_changed_by_signer() {
            let (keys, mut request) = session();
            request.id = Some(request.compute_id());
            let event = signed_over(&keys, &request, EventId::from_byte_array([7; 32]));
            assert_eq!(
                judged(&keys, &request, &event),
                "Signing failed: signer returned a wrong event id"
            );
        }

        #[test]
        fn malformed_returns_share_one_text() {
            let (keys, request) = session();
            let event = request.clone().finalize(&keys).unwrap();
            let sig = event.sig.to_string();
            let mut six: serde_json::Value = serde_json::from_str(&event.as_json()).unwrap();
            six.as_object_mut().unwrap().remove("content");
            let cases = [
                String::new(),
                "null".to_owned(),
                "1".to_owned(),
                "[]".to_owned(),
                "abc".to_owned(),
                "\"abc\"".to_owned(),
                sig.clone(),
                "{}".to_owned(),
                format!(r#"{{"id":"{}"}}"#, event.id.to_hex()),
                format!(r#"{{"sig":"{sig}"}}"#),
                r#"{"sig":null}"#.to_owned(),
                r#"{"sig":123}"#.to_owned(),
                r#"{"sig":""}"#.to_owned(),
                six.to_string(),
            ];
            for case in cases {
                assert_eq!(judged(&keys, &request, &case), INVALID, "{case}");
            }
        }

        #[test]
        fn complete_return_is_judged_by_field() {
            let (keys, request) = session();
            let event = resigned(&keys, &request, |e| e.kind = Kind::Metadata);
            assert_eq!(
                judged(&keys, &request, &event),
                "Signing failed: signer changed the event kind"
            );
            let other = Keys::generate();
            let forged = resigned(&other, &request, |e| e.pubkey = other.public_key());
            let err = checked_event(&request, keys.public_key(), &forged).unwrap_err();
            assert!(matches!(err, NostrAuthError::SignerKeyMismatch));
            let good = request.clone().finalize(&keys).unwrap();
            let mut nulled: serde_json::Value = serde_json::from_str(&good.as_json()).unwrap();
            nulled
                .as_object_mut()
                .unwrap()
                .insert("id".to_owned(), serde_json::Value::Null);
            assert_eq!(judged(&keys, &request, &nulled.to_string()), INVALID);
        }
    }

    #[test]
    fn mismatched_request_through_trait() {
        use core::error::Error as _;
        use nostr::event::{AsyncSignEvent, FinalizeEventAsync};
        let keys = Keys::generate();
        let auth = AuthResult::Ncryptsec(RawKeySession::for_tests(keys));
        let other = unsigned(Keys::generate().public_key());
        let direct = ready(auth.sign_event_async(other.clone())).unwrap_err();
        assert_eq!(direct.to_string(), PUBKEY_TEXT);
        let wrapped = ready(other.finalize_async(&auth)).unwrap_err();
        let source = wrapped
            .source()
            .and_then(|s| s.downcast_ref::<NostrAuthError>());
        assert!(
            matches!(source, Some(NostrAuthError::SigningFailed(t)) if t == "event pubkey differs from the session key")
        );
    }

    #[test]
    fn signer_key_mismatch_display() {
        assert_eq!(
            NostrAuthError::SignerKeyMismatch.to_string(),
            "Signer is using a different account than this session. Log in again to switch."
        );
    }
}
