# CWE-798: Hardcoded Credentials - Safe Pattern
# Rule: ruby-hardcoded-secret
# Expected: TrueNegative

# SAFE: Credentials loaded from environment variables
api_key = ENV["API_KEY"]
secret_key = ENV["SECRET_KEY"]

class PaymentService
  # SAFE: Using Rails credentials or environment variables
  def initialize
    @api_key = Rails.application.credentials.payment_api_key
    @password = ENV.fetch("DB_PASSWORD")
  end
end
