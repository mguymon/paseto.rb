module Paseto
  module V2
    module Public
      HEADER = 'v2.public'
      SIGNATURE_BYTES = RbNaCl::SigningKey.signature_bytes

      BadMessageError = Class.new(Paseto::Error)

      class SecretKey
        def self.generate
          new(RbNaCl::SigningKey.generate)
        end

        def self.decode64(encoded_key)
          new(Paseto.decode64(encoded_key))
        end

        def initialize(key)
          @key = key
          @nacl = RbNaCl::SigningKey.new(key)
        end

        def public_key
          PublicKey.new(@nacl.verify_key.to_bytes)
        end

        def encode64
          Paseto.encode64(@key)
        end

        attr_reader :nacl
      end

      class PublicKey
        def self.decode64(encoded_key)
          new(Paseto.decode64(encoded_key))
        end

        def initialize(key)
          @key = key
          @nacl = RbNaCl::VerifyKey.new(key)
        end

        def encode64
          Paseto.encode64(@key)
        end

        attr_reader :nacl
      end

      def self.sign(message, key, footer = nil)
        data = encode_message(message, footer)
        # Sign a message with the signing key
        signature = key.nacl.sign(data)

        Paseto::Token.new(HEADER, message + signature, footer).to_message
      end

      def self.verify(token, key, footer = nil)
        parsed = Paseto.parse_raw_token(token, HEADER, footer)

        decoded_message = parsed.payload[0..-(SIGNATURE_BYTES + 1)]
        signature = parsed.payload[-SIGNATURE_BYTES..-1]

        raise BadMessageError.new('Unable to process message') if decoded_message.nil? || signature.nil?

        begin
          key = key.public_key if key.is_a? SecretKey
          data = encode_message(decoded_message, footer)
          key.nacl.verify(signature, data)
          decoded_message
        rescue RbNaCl::BadSignatureError
          raise AuthenticationError.new('Token signature invalid')
        end
      end

      private

      def self.encode_message(message, footer)
        Paseto.pre_auth_encode(HEADER, message, footer)
      end
    end
  end
end
