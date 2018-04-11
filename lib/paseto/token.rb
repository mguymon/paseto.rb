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

  def self.parse_raw_token(raw, expected_header = nil, expected_footer = nil)
    version, purpose, payload, footer = raw.split('.')

    header = "#{version}.#{purpose}"
    if !expected_header.nil? && header != expected_header
      raise HeaderError.new("Invalid message header: #{header.inspect}")
    end

    footer = Paseto.decode64(footer) unless footer.nil?
    if !expected_footer.nil? && footer != expected_footer
      raise TokenError.new("Invalid message footer: #{footer.inspect}")
    end

    Token.new(header, Paseto.decode64(payload), footer)
  end
end
