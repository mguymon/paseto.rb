# frozen_string_literal: true

# Helper for verifying and parsing tokens
module Paseto
  Token = Struct.new(:header, :payload, :footer) do
    def to_message
      message = [
        header,
        Paseto.encode64(payload)
      ]

      message << Paseto.encode64(footer) if footer && footer != EMPTY_FOOTER

      message.join('.')
    end
  end

  def self.verify_token(token, expected_header, expected_footer)
    token = parse(token) unless token.is_a? Token
    raise HeaderError, "Invalid message header: #{token.header}" if token.header != expected_header

    if token.footer != expected_footer
      raise TokenError, "Invalid message footer: #{token.footer.inspect}"
    end

    token
  end

  def self.parse(raw)
    version, purpose, payload, footer = raw.split('.')

    header = "#{version}.#{purpose}"
    footer = footer.nil? ? EMPTY_FOOTER : Paseto.decode64(footer)
    payload = Paseto.decode64(payload) unless payload.nil?

    Token.new(header, payload, footer)
  end
end
