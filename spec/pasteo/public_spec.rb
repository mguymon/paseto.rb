require 'securerandom'

RSpec.describe Paseto::V2::Public do
  subject { described_class }

  let(:encoded_secret_key) { 'KxltS-uXOrPh5ZV2cwECjkcBrXbhTOaqQgg93j6FZ0w' }
  let(:secret_key) { Paseto::V2::Public::SecretKey.decode64(encoded_secret_key) }
  let(:encoded_public_key) { 'J3caURidJMcqSGLd4iTznFvOMqM1qv5mwFuzRfWBGZU' }
  let(:public_key) { Paseto::V2::Public::PublicKey.decode64(encoded_public_key) }
  let(:footer) { nil }

  let(:signed_message) do
    'v2.public.dGVzdD-ZV9h7UClSTPyEwdDMJ7u82FBGCuLMETNCQ9l27dwuWiTz28cJa3sKwXAalpmmWIHVR6nCSK6uBfGlkDDcNAk'
  end

  let(:bad_message) do
    'v2.public.1GVzdD-ZV9h7UClSTPyEwdDMJ7u82FBGCuLMETNCQ9l27dwuWiTz28cJa3sKwXAalpmmWIHVR6nCSK6uBfGlkDDcNAk'
  end

  let(:signed_message_with_footer) do
    'v2.public.dGVzdAa9qTiwBSzyyzLLVZb9mWW1owZuP_ezSiZZWfSp2GIOE6ZvJ9zMlHZrsm8MYMZcOKTchqxo5dTJKu-xHJ2gFgA.cGxhaW4gdGV4dCBmb290ZXI'
  end

  describe 'common use cases' do
    it 'can be used to sign public cleartext' do
      key = subject::SecretKey.generate
      token = key.sign('clear as day')

      # in the most common case, the public key will be serialized and stored /
      # sent somewhere, and the counterparty will decode it and verify the token
      sent_key = key.public_key.encode64
      decoded_key = subject::PublicKey.decode64(sent_key)
      expect(decoded_key.verify(token)).to eq('clear as day')
    end

    it 'can verify a value signed by pypaseto' do
      # Generated using python 3.6.2 / libsodium: 1.0.16:
      # from paseto import PasetoV2
      # import pysodium
      # import base64
      # import secrets
      # public, secret = pysodium.crypto_sign_keypair()
      # print('public', base64.b64encode(public).replace(b'=', b''))
      # print('token', PasetoV2.sign(b'clear as day', secret, b'yet another footer'))

      python_key = 'PQPq9DMbAVbNUrnjV0QQnmrzwhNwnK7CB05Rj7hXHj0'
      python_token = 'v2.public.Y2xlYXIgYXMgZGF5mRyNO1L70aasWgxbbeJqGTxS649_ok1rL-JogiGUIC_bt3ScnCn2-zrp6D5VgZj5E-4D6Qvw6LEW-x7E72UFCA.eWV0IGFub3RoZXIgZm9vdGVy'

      key = subject::PublicKey.decode64(python_key)
      expect(key.verify(python_token, 'yet another footer')).to eq('clear as day')
    end
  end

  describe Paseto::V2::Public::SecretKey do
    it 'can encode key material' do
      expect(secret_key.encode64).to eq(encoded_secret_key)
    end

    it 'can export public key' do
      expect(secret_key.public_key.encode64).to eq(encoded_public_key)
    end
  end

  describe Paseto::V2::Public::SecretKey do
    it 'can encode key material' do
      expect(public_key.encode64).to eq(encoded_public_key)
    end
  end

  describe '#sign' do
    it 'should sign a message' do
      expect(subject.sign('test', secret_key)).to eq signed_message
    end

    context 'with a footer' do
      let(:footer) { 'plain text footer' }

      it 'should sign a message' do
        expect(subject.sign('test', secret_key, footer)).to eq signed_message_with_footer
      end
    end
  end

  describe '#verify' do
    it 'should verify a message' do
      expect(subject.verify(signed_message, public_key)).to be_truthy
    end

    it 'can verify a message with the secret key' do
      expect(subject.verify(signed_message, secret_key)).to be_truthy
    end

    it 'should reject a bad signature' do
      expect { subject.verify(bad_message, public_key) }.to raise_error Paseto::AuthenticationError
    end

    it 'should raise an error for a bad header' do
      expect { subject.verify("incorrect.header", public_key) }.to raise_error Paseto::HeaderError
    end

    it 'should raise error trying to decrypt junk' do
      expect { subject.verify("v2.public." + SecureRandom.hex, public_key) }.to raise_error Paseto::Error
    end

    it 'should allow access to the signed payload' do
      expect(subject.verify(signed_message, public_key)).to eq('test')
    end

    context 'with a footer' do
      let(:footer) { 'plain text footer' }
      let(:bad_footer) { 'other foot' }

      it "should verify when the footer matches what's expected" do
        message = subject.verify(signed_message_with_footer, public_key, footer)
        expect(message).to eq('test')
      end

      it "does not require a footer from a parsed message" do
        message = public_key.verify(Paseto.parse(signed_message_with_footer))
        expect(message).to eq('test')
      end

      it "should raise when the footer doesn't match what's expected" do
        expect do
          subject.verify(signed_message_with_footer, public_key, bad_footer)
        end.to raise_error Paseto::TokenError
      end
    end
  end
end
