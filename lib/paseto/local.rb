module Paseto
  class Local
    HEADER = 'v2.local'
    NONCE_BYTES = RbNaCl::AEAD::ChaCha20Poly1305IETF.nonce_bytes

    NonceError = Class.new(Paseto::Error)
    AuthError = Class.new(Paseto::Error)
    BadMessageError = Class.new(Paseto::Error)

    def self.generate_nonce
      RbNaCl::Random.random_bytes(NONCE_BYTES)
    end

    def initialize(private_key, footer = [])
      if private_key.is_a? String
        @private_key = Paseto.decode64(private_key)
      else
        @private_key = private_key
      end

      @aead = RbNaCl::AEAD::ChaCha20Poly1305IETF.new(@private_key)
      @footer = footer
    end

    def encrypt(message)
      # Make a nonce: A single-use value never repeated under the same key
      nonce = self.class.generate_nonce

      # Encrypt a message with the AEAD
      ciphertext = @aead.encrypt(nonce, message, additional_data(nonce))

      Paseto::Message.new(HEADER, nonce + ciphertext, @footer).to_message
    end

    def decrypt(message)
      raise Paseto::BadHeaderError.new('Invalid message header.') unless message.start_with?(HEADER)

      computed_msg = Paseto.validate_and_remove_footer(message, @footer)
      decoded_payload = Paseto.decode64(computed_msg[9..-1]);
      nonce = decoded_payload[0, NONCE_BYTES]
      ciphertext = decoded_payload[NONCE_BYTES..-1]

      raise BadMessageError.new('Unable to process message') if nonce.nil? || ciphertext.nil?

      begin
        @aead.decrypt(nonce, ciphertext, additional_data(nonce))
      rescue RbNaCl::LengthError
        raise NonceError, 'Invalid nonce'
      rescue RbNaCl::CryptoError
        raise AuthError, 'Message cannot be authenticated'
      rescue
        raise BadMessageError, 'Unable to process message'
      end
    end

    def additional_data(nonce)
      Paseto.pre_auth_encode(HEADER, nonce, @footer)
    end
  end
end