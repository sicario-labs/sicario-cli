# CWE-918: Server-Side Request Forgery - Safe Pattern
# Rule: ruby-ssrf-net-http
# Expected: TrueNegative

require 'net/http'
require 'uri'

class WebhookController < ApplicationController
  ALLOWED_HOSTS = %w[api.example.com api.trusted.com].freeze

  def fetch
    # SAFE: Validate URL against allowlist before making request
    uri = URI.parse(params[:url])
    raise "Unauthorized host" unless ALLOWED_HOSTS.include?(uri.host)
    response = Net::HTTP.get(uri)
    render plain: response
  end

  def proxy
    # SAFE: Static URL, no user input
    uri = URI("https://api.example.com/data")
    Net::HTTP.get_response(uri)
  end
end
