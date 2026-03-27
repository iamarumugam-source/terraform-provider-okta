resource "okta_policy_rule_signon" "default_rule" {
  policy_id = "00pse1f0jC1KpxXA1d7"
  name      = "Default Rule"
  status    = "ACTIVE"
  access    = "DENY"
}
