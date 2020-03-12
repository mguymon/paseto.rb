# frozen_string_literal: true

module Paseto
  module V2
    # Symmetric Encryption
    module Local
      HEADER = 'v2.local'
      NONCE_BYTES = RbNaCl::AEAD::XChaCha20Poly1305IETF.nonce_bytes

      NonceError = Class.new(Paseto::Error)

      # Encryption key
      class Key
        def self.generate
          new(RbNaCl::Random.random_bytes(RbNaCl::AEAD::XChaCha20Poly1305IETF.key_bytes))
        end

        def self.decode64(encoded_key)
          new(Paseto.decode64(encoded_key))
        end

        def self.decode_hex(encoded_key)
          new(Paseto.decode_hex(encoded_key))
        end

        def initialize(key)
          @key = key
          @aead = RbNaCl::AEAD::XChaCha20Poly1305IETF.new(key)
        end

        def encode64
          Paseto.encode64(@key)
        end

        def encode_hex
          Paseto.encode_hex(@key)
        end

        def encrypt(message, footer = EMPTY_FOOTER)
          # Make a nonce: A single-use value never repeated under the same key
          nonce = generate_nonce(message)

          # Encrypt a message with the AEAD
          ciphertext = @aead.encrypt(nonce, message, additional_data(nonce, footer))

          Paseto::Token.new(HEADER, nonce + ciphertext, footer).to_message
        end

        def decrypt(token, footer = nil)
          footer ||= token.footer if token.is_a? Paseto::Token
          footer ||= EMPTY_FOOTER

          parsed = Paseto.verify_token(token, HEADER, footer)

          nonce = parsed.payload[0, NONCE_BYTES]
          ciphertext = parsed.payload[NONCE_BYTES..-1]

          raise BadMessageError, 'Unable to process message' if nonce.nil? || ciphertext.nil?

          begin
            data = additional_data(nonce, footer)
            @aead.decrypt(nonce, ciphertext, data)
          rescue RbNaCl::LengthError
            raise NonceError, 'Invalid nonce'
          rescue RbNaCl::CryptoError
            raise AuthenticationError, 'Token signature invalid'
          rescue StandardError
            raise TokenError, 'Unable to process message'
          end
        end

        private

        def generate_nonce_key
          RbNaCl::Random.random_bytes(NONCE_BYTES)
        end

        def generate_nonce(message)
          RbNaCl::Hash::Blake2b.digest(message,
                                       key: generate_nonce_key,
                                       digest_size: NONCE_BYTES)
        end

        def additional_data(nonce, footer)
          Paseto.pre_auth_encode(HEADER + '.', nonce, footer)
        end
      end

      def self.encrypt(message, key, footer = EMPTY_FOOTER)
        key.encrypt(message, footer)
      end

      def self.decrypt(token, key, footer = nil)
        key.decrypt(token, footer)
      end
    end
  end
end
