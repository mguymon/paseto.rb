module Paseto
  Error = Class.new(StandardError)
  BadHeaderError = Class.new(Error)
  AuthenticationError = Class.new(Error)
end
