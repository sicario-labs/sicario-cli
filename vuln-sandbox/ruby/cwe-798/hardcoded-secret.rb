# CWE-798: Hardcoded Credentials in Ruby
# Rule: ruby-hardcoded-secret
# Expected: TruePositive

# VULNERABLE: Hardcoded API key and secret
api_key = "sk-prod-1234567890abcdef"
secret_key = "super_secret_jwt_signing_key_do_not_share"

class PaymentService
  # VULNERABLE: Hardcoded password
  password = "db_password_hardcoded_123"
  token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

  def initialize
    @api_key = api_key
  end
end
