require 'securerandom'

RSpec.describe Paseto::V2::Local do
  subject { described_class }

  let(:payload) { 'test' }
  let(:encoded_key) { '2eOIs+JWWCKvFDg+eHFsIBHfMuN+3bqkceK8moM4S1Y' }
  let(:key) { Paseto::V2::Local::Key.decode64(encoded_key) }
  let(:footer) { nil }
  let(:token) { 'v2.local.6EHOXWuFHUBNy9gEB8sSU5NTF83oMagI/j89rE26Wmk' }
  let(:nonce) { '6EHOXWuFHUBNy9gE' }

  describe Paseto::V2::Local::Key do
    subject { described_class }

    it '.encode64 returns a base64-encoded key' do
      expect(key.encode64).to eq(encoded_key)
    end

    it '.decode64(key.encode64) is a no-op' do
      key = subject.generate
      round_trip = subject.decode64(key.encode64)
      expect(round_trip.instance_variable_get(:@key)).to eq(key.instance_variable_get(:@key))
    end
  end

  describe '.encrypt' do
    it 'should encrypt the message' do
      allow_any_instance_of(described_class::Key).to receive(:generate_nonce)
        .and_return(Paseto.decode64(nonce))

      expect(subject.encrypt(payload, key)).to eq token
    end
  end

  describe '.decrypt' do
    let(:footer) { 'hello there' }
    let(:original) { 'v2.local.6EHOXWuFHUBNy9gEHssSVKOIT//W7AeqENvznTJA+i72bZE.aGVsbG8gdGhlcmU' }
    let(:tampered) { 'v2.local.6EHOXWWFHUBNy9gEHssSVKOIT//W7AeqENvznTJA+i72bZE.aGVsbG8gdGhlcmU' }

    it 'should decrypt the message' do
      expect(subject.decrypt(token, key)).to eq payload
    end

    it 'should decrypt a parsed token' do
      expect(subject.decrypt(Paseto.parse(token), key)).to eq payload
    end

    describe 'with a footer' do
      let(:bad_footer) { 'foot the bill' }
      let(:token) { subject.encrypt(payload, key, footer) }

      it 'should decrypt when the footer is correct' do
        expect(subject.decrypt(token, key, footer)).to eq payload
      end

      it "should raise when the footer doesn't match what's expected" do
        expect { subject.decrypt(token, key, bad_footer) }.to raise_error Paseto::TokenError
      end
    end

    it 'should raise an error for a bad header' do
      expect { subject.decrypt("incorrect.header", key) }.to raise_error Paseto::HeaderError
    end

    it 'should raise an error when trying to decrypt a tampered message' do
      expect(subject.decrypt(original, key, footer)).to eq('message')
      expect { subject.decrypt(tampered, key, footer) }.to raise_error Paseto::AuthenticationError
    end

    it 'should raise error trying to decrypt junk' do
      expect { subject.decrypt("v2.local." + SecureRandom.hex, key) }.to raise_error Paseto::TokenError
    end
  end
end
