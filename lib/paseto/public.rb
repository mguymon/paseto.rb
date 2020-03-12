# frozen_string_literal: true

module Paseto
  module V2
    # Asymmetric Authentication (Public-Key Signatures)
    module Public
      HEADER = 'v2.public'
      SIGNATURE_BYTES = RbNaCl::SigningKey.signature_bytes
      BadMessageError = Class.new(Paseto::Error)

      # Encode a message + footer in a Paseto payload
      module Encoder
        private

        def encode_message(message, footer)
          Paseto.pre_auth_encode(HEADER + '.', message, footer)
        end
      end

      # secret-key used for signing and verifying
      class SecretKey
        include Encoder

        def self.generate
          new(RbNaCl::SigningKey.generate.to_bytes)
        end

        def self.decode64(encoded_key)
          new(Paseto.decode64(encoded_key))
        end

        def self.decode_hex(encoded_key)
          new(Paseto.decode_hex(encoded_key))
        end

        def initialize(key)
          @key = key
          @nacl = RbNaCl::SigningKey.new(key)
        end

        def sign(message, footer = EMPTY_FOOTER)
          data = encode_message(message, footer)
          # Sign a message with the signing key
          signature = @nacl.sign(data)

          Paseto::Token.new(HEADER, message + signature, footer).to_message
        end

        def verify(message, footer = nil)
          public_key.verify(message, footer)
        end

        def public_key
          PublicKey.new(@nacl.verify_key.to_bytes)
        end

        def encode64
          Paseto.encode64(@key)
        end

        def encode_hex
          Paseto.encode_hex(@key)
        end
      end

      # public-key used for signing and verifing
      class PublicKey
        include Encoder

        def self.decode64(encoded_key)
          new(Paseto.decode64(encoded_key))
        end

        def self.decode_hex(encoded_key)
          new(Paseto.decode_hex(encoded_key))
        end

        def initialize(key)
          @key = key
          @nacl = RbNaCl::VerifyKey.new(key)
        end

        def encode64
          Paseto.encode64(@key)
        end

        def encode_hex
          Paseto.encode_hex(@key)
        end

        def verify(token, footer = nil)
          footer ||= token.footer if token.is_a? Paseto::Token
          footer ||= EMPTY_FOOTER

          parsed = Paseto.verify_token(token, HEADER, footer)

          decoded_message = parsed.payload[0..-(SIGNATURE_BYTES + 1)]
          signature = parsed.payload[-SIGNATURE_BYTES..-1]

          if decoded_message.nil? || signature.nil?
            raise BadMessageError, 'Unable to process message'
          end

          begin
            data = encode_message(decoded_message, footer)
            @nacl.verify(signature, data)
            decoded_message
          rescue RbNaCl::BadSignatureError
            raise AuthenticationError, 'Token signature invalid'
          end
        end
      end

      def self.sign(message, key, footer = EMPTY_FOOTER)
        key.sign(message, footer)
      end

      def self.verify(token, key, footer = nil)
        key.verify(token, footer)
      end
    end
  end
end
