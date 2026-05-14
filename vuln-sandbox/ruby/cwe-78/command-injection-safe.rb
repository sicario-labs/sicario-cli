# CWE-78: OS Command Injection - Safe Pattern
# Rule: ruby-command-injection-system
# Expected: TrueNegative

class FilesController < ApplicationController
  def convert
    # SAFE: Arguments passed as array, no shell interpolation
    filename = params[:filename]
    sanitized = File.basename(filename)
    system("convert", sanitized, "output.png")
    render plain: "Converted"
  end

  def resize
    # SAFE: Using Open3 with array arguments
    require 'open3'
    size = params[:size].to_s.match?(/\A\d+x\d+\z/) ? params[:size] : "800x600"
    file = File.basename(params[:file])
    Open3.capture2("mogrify", "-resize", size, file)
  end
end
