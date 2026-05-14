# CWE-22: Path Traversal - Safe Pattern
# Rule: ruby-path-traversal-file-read
# Expected: TrueNegative

class DocumentsController < ApplicationController
  UPLOAD_DIR = "/uploads"

  def show
    # SAFE: Validate path stays within allowed directory
    filename = File.basename(params[:filename])
    safe_path = File.join(UPLOAD_DIR, filename)
    raise "Invalid path" unless safe_path.start_with?(UPLOAD_DIR)
    content = File.read(safe_path)
    render plain: content
  end

  def download
    # SAFE: Static path, no user input
    send_file "/data/public_document.pdf"
  end
end
