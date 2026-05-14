# CWE-89: SQL Injection via String Interpolation in Ruby
# Rule: ruby-sql-string-interpolation
# Expected: TruePositive

class UsersController < ApplicationController
  def show
    # VULNERABLE: User input interpolated directly into SQL query
    user = User.where("name = '#{params[:name]}'").first
    render json: user
  end

  def search
    # VULNERABLE: Direct interpolation in find_by_sql
    results = User.find_by_sql("SELECT * FROM users WHERE email = '#{params[:email]}'")
    render json: results
  end
end
