# CWE-79: Cross-Site Scripting via html_safe in Ruby/Rails
# Rule: ruby-xss-html-safe
# Expected: TruePositive

class CommentsController < ApplicationController
  def show
    # VULNERABLE: User input marked as html_safe bypasses Rails XSS protection
    @comment = params[:comment].html_safe
    render inline: "<p><%= @comment %></p>"
  end

  def preview
    # VULNERABLE: Request parameter marked as html_safe
    content = request.params[:content].html_safe
    render html: content
  end
end
