//! Hostile MCP client: one named test per attack in `testbed::hostile::ATTACKS`.
//! All are ignored until the tool surface exists (Phase 6); Phases 7–8 cover the flow attacks.
//! `cargo test -p testbed --test hostile -- --ignored` lists them failing with "not implemented".

macro_rules! attacks {
    ($($id:ident),* $(,)?) => {
        $(
            #[test]
            #[ignore = "hostile client: lands with the MCP tools (Phase 6+)"]
            fn $id() {
                let a = testbed::hostile::ATTACKS.iter().find(|a| a.id == stringify!($id)).expect("attack listed");
                panic!("not implemented until Phase {}: {} → expect: {}", a.phase, a.tries, a.expect);
            }
        )*

        #[test]
        fn every_listed_attack_has_a_test() {
            let named = [$(stringify!($id)),*];
            for a in testbed::hostile::ATTACKS {
                assert!(named.contains(&a.id), "attack {} has no test case", a.id);
            }
            assert_eq!(named.len(), testbed::hostile::ATTACKS.len());
        }
    };
}

attacks!(
    accounts_find_returns_no_secret,
    accounts_find_site_injection,
    login_lookalike_host,
    login_url_confusion,
    login_homoglyph_site,
    login_account_arg_injection,
    login_without_approval,
    login_approval_replay,
    login_approval_expired,
    login_captcha_page,
    login_injected_page,
    login_read_fields_page,
    login_cross_origin_form,
    login_cross_origin_iframe,
    login_rate_spam,
    signup_fields_expand_handle,
    signup_identity_other_user,
    signup_otp_spoofed_sender,
    snapshot_password_value,
    snapshot_password_length,
    snapshot_other_client_session,
    snapshot_forged_session_id,
    act_type_handle_literal,
    act_type_into_password_then_snapshot,
    act_submit_without_approval,
    act_navigate_exfil,
    act_navigate_scheme,
    act_bad_ref,
    capture_returns_handle_only,
    capture_label_traversal,
    capture_cross_site,
    close_other_client_session,
    wait_foreign_handle,
    wait_forged_handle,
    rpc_malformed_input,
    rpc_unknown_tool_and_extra_args,
    errors_contain_no_secret,
);
