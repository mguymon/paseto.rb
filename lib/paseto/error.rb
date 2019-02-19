# frozen_string_literal: true

module Paseto
  Error = Class.new(StandardError)
  HeaderError = Class.new(Error)
  TokenError = Class.new(Error)
  AuthenticationError = Class.new(Error)
end
