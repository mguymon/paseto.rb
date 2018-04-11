module Paseto
  class Public
    HEADER = 'v2.public'
    SIGNATURE_BYTES = RbNaCl::SigningKey.signature_bytes

    BadMessageError = Class.new(Paseto::Error)

    def self.generate_signing_key
      RbNaCl::SigningKey.generate
    end

    def self.from_encode64_key(encoded_key, footer = nil)
      new(Paseto.decode64(encoded_key), footer)
    end

    def initialize(private_key, footer = nil)
      @signing_key = RbNaCl::SigningKey.new(private_key)
      @verify_key = @signing_key.verify_key
      @footer = footer
    end

    def sign(message)
      data = encode_message(message)
      # Sign a message with the signing key
      signature = @signing_key.sign(data)

      Paseto::Token.new(HEADER, message + signature, @footer).to_message
    end

    def verify(token)
      parsed = Paseto.parse_raw_token(token, HEADER)

      decoded_message = parsed.payload[0..-(SIGNATURE_BYTES + 1)]
      signature = parsed.payload[-SIGNATURE_BYTES..-1]

      raise BadMessageError.new('Unable to process message') if decoded_message.nil? || signature.nil?

      begin
        data = encode_message(decoded_message)
        @verify_key.verify(signature, data)
        true
      rescue RbNaCl::BadSignatureError
        false
      end
    end

    private

    def encode_message(message)
      Paseto.pre_auth_encode(HEADER, message, @footer)
    end
  end
end