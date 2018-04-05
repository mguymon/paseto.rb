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
      @private_key = private_key
      @signing_key = RbNaCl::SigningKey.new(@private_key)
      @verify_key = @signing_key.verify_key
      @footer = footer
    end

    def sign(payload)
      data = encode_message(payload)
      # Sign a message with the signing key
      signature = @signing_key.sign(data)

      Paseto::Message.new(HEADER, data + signature, @footer).to_message
    end

    def verify(message)
      raise Paseto::BadHeaderError.new('Invalid message header.') unless message.start_with?(HEADER)

      computed_msg = Paseto.validate_and_remove_footer(message, @footer)
      decoded_payload = Paseto.decode64(computed_msg[10..-1]);

      decoded_message = decoded_payload[0..-(SIGNATURE_BYTES + 1)]
      signature = decoded_payload[-SIGNATURE_BYTES..-1]

      raise BadMessageError.new('Unable to process message') if decoded_message.nil? || signature.nil?

      begin
        @verify_key.verify(signature, decoded_message)
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