module Paseto
  module V2
    module Local
      HEADER = 'v2.local'
      NONCE_BYTES = RbNaCl::AEAD::ChaCha20Poly1305IETF.nonce_bytes

      NonceError = Class.new(Paseto::Error)

      class Key
        def self.generate
          new(RbNaCl::Random.random_bytes(RbNaCl::AEAD::ChaCha20Poly1305IETF.key_bytes))
        end

        def self.decode64(encoded_key)
          new(Paseto.decode64(encoded_key))
        end

        def initialize(key)
          @key = key
          @aead = RbNaCl::AEAD::ChaCha20Poly1305IETF.new(key)
        end

        def encode64
          Paseto.encode64(@key)
        end

        def encrypt(message, footer = nil)
          # Make a nonce: A single-use value never repeated under the same key
          nonce = generate_nonce

          # Encrypt a message with the AEAD
          ciphertext = @aead.encrypt(nonce, message, additional_data(nonce, footer))

          Paseto::Token.new(HEADER, nonce + ciphertext, footer).to_message
        end

        def decrypt(token, footer = nil)
          footer ||= token.footer if token.is_a? Paseto::Token
          parsed = Paseto.verify_token(token, HEADER, footer)

          nonce = parsed.payload[0, NONCE_BYTES]
          ciphertext = parsed.payload[NONCE_BYTES..-1]

          raise BadMessageError.new('Unable to process message') if nonce.nil? || ciphertext.nil?

          begin
            data = additional_data(nonce, footer)
            @aead.decrypt(nonce, ciphertext, data)
          rescue RbNaCl::LengthError
            raise NonceError, 'Invalid nonce'
          rescue RbNaCl::CryptoError
            raise AuthenticationError, 'Token signature invalid'
          rescue
            raise TokenError, 'Unable to process message'
          end
        end

        private

        def generate_nonce
          RbNaCl::Random.random_bytes(NONCE_BYTES)
        end

        def additional_data(nonce, footer)
          Paseto.pre_auth_encode(HEADER, nonce, footer)
        end
      end

      def self.encrypt(message, key, footer = nil)
        key.encrypt(message, footer)
      end

      def self.decrypt(token, key, footer = nil)
        key.decrypt(token, footer)
      end
    end
  end
end
