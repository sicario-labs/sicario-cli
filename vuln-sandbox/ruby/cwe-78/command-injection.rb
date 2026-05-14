# CWE-78: OS Command Injection via system() in Ruby
# Rule: ruby-command-injection-system
# Expected: TruePositive

class FilesController < ApplicationController
  def convert
    # VULNERABLE: User input passed directly to system()
    filename = params[:filename]
    system("convert #{filename} output.png")
    render plain: "Converted"
  end

  def resize
    # VULNERABLE: User input in exec()
    exec("mogrify -resize #{params[:size]} #{params[:file]}")
  end
end
