# CWE-89: SQL Injection - Safe Pattern
# Rule: ruby-sql-string-interpolation
# Expected: TrueNegative

class UsersController < ApplicationController
  def show
    # SAFE: Using parameterized query with ? placeholder
    user = User.where("name = ?", params[:name]).first
    render json: user
  end

  def search
    # SAFE: Using named parameters
    results = User.where(email: params[:email])
    render json: results
  end
end
