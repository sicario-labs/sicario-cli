# CWE-79: Cross-Site Scripting - Safe Pattern
# Rule: ruby-xss-html-safe
# Expected: TrueNegative

class CommentsController < ApplicationController
  def show
    # SAFE: Rails auto-escapes output in ERB templates
    @comment = params[:comment]
    render inline: "<p><%= @comment %></p>"
  end

  def preview
    # SAFE: Using sanitize helper to allow only safe HTML
    content = sanitize(params[:content], tags: %w[p b i em strong])
    render html: content.html_safe
  end
end
