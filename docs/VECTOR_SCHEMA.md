# Kilit — vector file schemas (verbatim from DESIGN.md §3.9)

### 3.9 Vector file schemas (normative for WP1 and WP5)

Encodings: every byte string is **lowercase hex** unless the key name ends in `_b64` or the value is a copy of wire JSON (envelope objects use base64url exactly as on the wire). Integers are JSON numbers. Expected errors are strings equal to the Swift case name: `KilitCryptoError` cases `lowOrderPoint, badKeyLength, badPublicKey, badSignature, identityMismatch, replay, staleSPK, tooManySkipped, badHeader, badPadding, sizeLimit, unknownSession`; CryptoKit cases `authenticationFailure, incorrectKeySize, incorrectParameterSize`; store errors `rollback`. Classification strings are the reason codes of §3.2b.

```jsonc
// primitives.json
{"x25519":[{"name":"rfc7748","priv":"hex32","pub":"hex32","peer_pub":"hex32","shared":"hex32"}],
 "x25519_negative":[{"name":"low_order","priv":"hex32","peer_pub":"hex32","error":"lowOrderPoint"},
                    {"name":"short_key","priv":"hex32","peer_pub":"hex31","error":"badKeyLength"}],
 "ed25519":[{"name":"rfc8032_1","seed":"hex32","pub":"hex32","msg":"hex","go_sig":"hex64"}],
 "ed25519_negative":[{"name":"s_ge_l","pub":"hex32","msg":"hex","sig":"hex","error":"badSignature"}],
 "ed25519_small_order_points":["hex32", "…14 entries"],
 "hkdf":[{"name":"rfc5869_1","ikm":"hex","salt":"hex","info":"hex","len":42,"okm":"hex"},
         {"name":"empty_vs_zero_salt","ikm":"hex","salt_a":"","salt_b":"00…(32)","info":"hex","len":32,"okm":"hex"}],
 "hmac_kdf_ck":[{"ck":"hex32","mk":"hex32","ck_next":"hex32"}],
 "chachapoly":[{"name":"rfc8439","key":"hex32","nonce":"hex12","aad":"hex","pt":"hex","wire":"hex"}],
 "chachapoly_negative":[{"name":"short_key","key":"hex31","error":"incorrectKeySize"},
                        {"name":"bad_tag","key":"hex32","nonce":"hex12","aad":"hex","wire":"hex","error":"authenticationFailure"}]}

// base64url.json
{"cases":[{"bytes":"hex","text":"base64url"}],
 "negative":[{"name":"padding","text":"AQ==","error":"bad_envelope"},{"name":"alphabet","text":"AQ+/","error":"bad_envelope"},
             {"name":"length_mod4_1","text":"AQIDB","error":"bad_envelope"},{"name":"trailing_bits","text":"AR","error":"bad_envelope"}]}

// x3dh_session.json
{"inputs":{"alice":{"username":"alice","ik_sig_seed":"hex32","ik_dh_priv":"hex32","ek_priv":"hex32","dhs_priv":"hex32"},
           "bob":{"username":"bob","ik_sig_seed":"hex32","ik_dh_priv":"hex32","spk_priv":"hex32","spk_id":7,"spk_created_at":1759900000,
                  "opks":[{"id":1203,"priv":"hex32"},{"id":1204,"priv":"hex32"}]},
           "device_id":"uuid","nonce":"hex32","ts":1760000000,"server_origin":"https://kilit.example.com"},
 "public":{"alice":{"ik_sig":"hex32","ik_dh":"hex32","ek":"hex32"},"bob":{"ik_sig":"hex32","ik_dh":"hex32","spk":"hex32","opks":[{"id":1203,"pub":"hex32"}]}},
 "signatures":{"ik_bind_sig":{"signer":"bob","msg":"hex","sig":"hex64"},"spk_sig":{...},"opks_sig":{...},
               "register_proof":{"signer":"alice","msg":"hex","sig":"hex64"},"login_sig":{...},"delete_sig":{...}},
 "x3dh":{"dh1":"hex32","dh2":"hex32","dh3":"hex32","dh4":"hex32","sk":"hex32","sk_no_opk":"hex32","ws":"hex32","sid":"hex8","ad":"hex"},
 "first_envelope":{ /* wire JSON object, base64url fields */ },
 "negative":[{"name":"ik_dh_swapped","error":"identityMismatch"},{"name":"bad_bind_sig","error":"badSignature"},{"name":"stale_spk","spk_created_at":1758000000,"error":"staleSPK"}]}

// ratchet_conversation.json
{"scenarios":[{"name":"basic","clock_start":1760000000,
  "bundles":{"A":{"spk_priv":"hex32","spk_id":9,"spk_created_at":1759900000,"opks":[{"id":2301,"priv":"hex32"},{"id":2302,"priv":"hex32"}]},
             "B":{"spk_priv":"hex32","spk_id":7,"spk_created_at":1759900000,"opks":[{"id":1203,"priv":"hex32"},{"id":1204,"priv":"hex32"}]}},   // SPK/OPK private keys of both sides; never drawn from key_sources (§3.8)
  "key_sources":{"A":["hex32","…"],"B":["hex32","…"]},   // EK and DHs only, consumed in the §3.8 order
  "steps":[
   {"op":"init_alice","side":"A","session":"S1","sid":"hex8","sk":"hex32","peer_pub":"hex32","ad":"hex","state_after":{STATE}},
   {"op":"init_bob","side":"B","session":"S1","sid":"hex8","sk":"hex32","dhs_priv":"hex32","ad":"hex","state_after":{STATE}},
   {"op":"encrypt","side":"A","session":"S1","label":"A1","pt_padded":"hex","hdr":"hex41","aad":"hex","mk":"hex32","key":"hex32","nonce":"hex12","wire":"hex","state_after":{STATE}},
   {"op":"decrypt","side":"B","session":"S1","label":"A1","hdr":"hex41","wire":"hex","pt_padded":"hex","state_after":{STATE}},
   {"op":"decrypt_expect_error","side":"B","session":"S1","hdr":"hex41","wire":"hex","error":"authenticationFailure","state_unchanged":true},
   {"op":"decrypt_expect_error","side":"B","session":"S1","dh_pub":"hex31","pn":0,"n":0,"wire":"hex","error":"badKeyLength","state_unchanged":true},   // direct ratchet-API call with a parsed header; "dh_pub"/"pn"/"n" replace "hdr"
   {"op":"advance_clock","seconds":86400},
   {"op":"deliver_envelope","side":"B","from":"alice","msg_id":"hex16","envelope":{WIRE JSON},"expect":"stored|duplicate|already_processed|parked|classified","reason":"replay","expect_sending_sid":{"A":"hex8","B":"hex8"}},   // already_processed = outer msg_id already in processed_msg_ids (§3.2b step 0); duplicate = decrypted inner (author,id) already present, acked silently, no new row (§3.4)
   {"op":"send","side":"A","peer":"bob","inner":{INNER JSON},"expect_sid":"hex8","expect_kind":"prekey|msg","expect_resend_ids":["uuid"]},   // app-level send through the sending-session rule; expect_resend_ids lists ctrl.resync re-sends triggered by this step
   {"op":"expect_sending_sid","A":"hex8|null","B":"hex8|null"},
   {"op":"expect_messages","side":"B","peer":"alice","ids":[["me|peer","uuid"]]},    // the full ordered (author,id) set of that conversation
   {"op":"rotate_identity","side":"A","new_ik_sig_seed":"hex32","new_ik_dh_priv":"hex32",
    "new_spk":{"id":10,"priv":"hex32","created_at":1760100000},"new_opks":[{"id":2401,"priv":"hex32"}]},   // re-registration with new identity keys; the new SPK/OPKs are given explicitly here and never drawn from key_sources (§3.8)
   {"op":"accept_message_request","side":"B","peer":"alice"},                           // "Kabul et"; before it the rejected-initiation path never fires for that peer (§3.2 step 3)
   {"op":"lookup_result","side":"B","peer":"alice","result":"ok|mismatch|not_found|transient"},   // injected GET /v1/users result for the next TOFU lookup
   {"op":"consumed_report","side":"B","ids":[1203]},                                   // injected consumed_ids report at the current clock
   {"op":"inject_rollback","side":"B","session":"S1"},                                 // next load of that session file fails the generation check → S3
   {"op":"delete_session","side":"B","session":"S1","sid":"hex8","reason":"pruned|parse_failure|rollback"},   // reason is the known_sids deletedReason the runner must record: only parse_failure/rollback make a later unknown-sid msg initiate ctrl.resync (§3.2 S3)
   {"op":"accept_key_change","side":"B","peer":"alice"},
   {"op":"expect_mkskipped","side":"B","session":"S1","keys":[{"dh":"hex32","n":3}]},
   {"op":"expect_mkskipped","side":"B","session":"S1","count":1999,"mkskipped_sha256":"hex32"},   // form used when > 50 entries (§3.8)
   {"op":"expect_state_excludes","side":"B","session":"S1","bytes":"hex32"}]}]}
// STATE = {"rk":"hex32","cks":"hex32|null","ckr":"hex32|null","ns":0,"nr":0,"pn":0,"dhs_priv":"hex32","dhr":"hex32|null","mkskipped":[{"dh":"hex32","n":0,"mk":"hex32"}]}
//         or, when more than 50 entries: {... ,"mkskipped_count":1999,"mkskipped_sha256":"hex32"} (no "mkskipped" key)
// ratchet_eviction.json uses the same schema (one scenario, "eviction").

// attachment.json
{"cases":[{"blob_id":"hex16","file_key":"hex32","mime":"image/jpeg","pt":"hex","key":"hex32","nonce":"hex12","aad":"hex","blob":"hex","sha256":"hex32"}],
 "negative":[{"name":"wrong_len","blob_id":"hex16","file_key":"hex32","mime":"image/jpeg","len":99,"blob":"hex","error":"authenticationFailure"}]}

// envelope.json
{"padding":[{"json":"hex","padded":"hex"}],
 "padding_negative":[{"padded":"hex","error":"badPadding"}],
 "size":{"max_ok_len":40960,"reject_len":40961,"error":"sizeLimit"},
 "outer":[{"name":"opk_null","json":"{…\"opk_id\":null…}","parses":true},{"name":"opk_absent","json":"{…}","parses":true},
          {"name":"v2","json":"…","parses":false,"reason":"bad_envelope"}],
 "inner_roundtrip":[{"json":"{…}"}]}

// safety.json
{"cases":[{"username":"alice","ik_sig":"hex32","ik_dh":"hex32","digits":"30 digits"}],"pairs":[{"a":"alice","b":"bob","number":"60 digits","qr":"kilit-sn:v1:…"}]}

// watermark.json
{"inputs":{"ws":"hex32","viewer":"alice","unix":1760400000},
 "tag":171,"day":7,
 "crc_steps":[{"bit":1,"fb":1,"crc":3},{"bit":0,"fb":0,"crc":6},{"bit":1,"fb":1,"crc":15},{"bit":0,"fb":1,"crc":13},{"bit":1,"fb":0,"crc":10},{"bit":0,"fb":1,"crc":7},
              {"bit":1,"fb":1,"crc":13},{"bit":1,"fb":0,"crc":10},{"bit":0,"fb":1,"crc":7},{"bit":1,"fb":1,"crc":13},{"bit":1,"fb":0,"crc":10},{"bit":1,"fb":0,"crc":4}],
 "crc":4,"payload16":43892,   // = 171<<8 | 7<<4 | 4; the values in this document are illustrative, watermark.json as generated by cmd/vectors is normative
 "sync":"10110100011100101001","cells":[[true,false,…6],…6 rows],
 "delta":{"cell_pt":28,"k_per_scale":4,"amplitude":5,
          "scale1":{"w":168,"h":168,"int8":"hex (28224 bytes)"},
          "scale2_sha256":"hex32","scale3_sha256":"hex32",
          "samples_scale3":[{"x":10,"y":10,"delta":5,"lighter":5,"darker":255}]}}
```

