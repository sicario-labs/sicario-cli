# CWE-918: Server-Side Request Forgery via Net::HTTP in Ruby
# Rule: ruby-ssrf-net-http
# Expected: TruePositive

require 'net/http'
require 'uri'

class WebhookController < ApplicationController
  def fetch
    # VULNERABLE: User-controlled URL passed to Net::HTTP
    url = params[:url]
    response = Net::HTTP.get(URI("#{url}"))
    render plain: response
  end

  def proxy
    # VULNERABLE: User input in HTTP request
    target = params[:target]
    uri = URI("http://#{target}/api/data")
    Net::HTTP.get_response(uri)
  end
end
