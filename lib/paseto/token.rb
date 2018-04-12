module Paseto
  Token = Struct.new(:header, :payload, :footer) do
    def to_message
      message = [
        header,
        Paseto.encode64(payload)
      ]

      message << Paseto.encode64(footer) if footer

      message.join('.')
    end
  end

  def self.verify_token(token, expected_header, expected_footer)
    token = parse(token) unless token.is_a? Token
    if token.header != expected_header
      raise HeaderError.new("Invalid message header: #{token.header}")
    end

    if token.footer != expected_footer
      raise TokenError.new("Invalid message footer: #{token.footer.inspect}")
    end

    token
  end

  def self.parse(raw)
    version, purpose, payload, footer = raw.split('.')

    header = "#{version}.#{purpose}"
    footer = Paseto.decode64(footer) unless footer.nil?
    payload = Paseto.decode64(payload) unless payload.nil?

    Token.new(header, payload, footer)
  end
end
