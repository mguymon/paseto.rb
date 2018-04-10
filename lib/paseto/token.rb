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

  def self.parse_raw_token(raw, expected_header)
    version, purpose, payload, footer = raw.split('.')
    header = "#{version}.#{purpose}"
    unless header == expected_header
      raise Paseto::BadHeaderError.new("Invalid message header: #{header}")
    end
    footer = Paseto.decode64(footer) unless footer.nil?
    Token.new(header, Paseto.decode64(payload), footer)
  end
end
