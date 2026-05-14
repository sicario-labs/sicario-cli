# CWE-22: Path Traversal via File.read in Ruby
# Rule: ruby-path-traversal-file-read
# Expected: TruePositive

class DocumentsController < ApplicationController
  def show
    # VULNERABLE: User-controlled filename used in File.read
    filename = params[:filename]
    content = File.read("/uploads/#{filename}")
    render plain: content
  end

  def download
    # VULNERABLE: User input in File.open
    path = params[:path]
    File.open("/data/#{path}") do |f|
      send_data f.read
    end
  end
end
