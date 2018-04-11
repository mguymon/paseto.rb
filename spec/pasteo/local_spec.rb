require 'securerandom'

RSpec.describe Paseto::Local do
  subject { described_class.from_encode64_key(key, footer) }

  let(:payload) { 'test' }
  let(:key) { '2eOIs+JWWCKvFDg+eHFsIBHfMuN+3bqkceK8moM4S1Y' }
  let(:footer) { nil }
  let(:token) { 'v2.local.6EHOXWuFHUBNy9gEB8sSU5NTF83oMagI/j89rE26Wmk' }
  let(:nonce) { '6EHOXWuFHUBNy9gE' }

  before { allow(described_class).to receive(:generate_nonce).and_return(Paseto.decode64(nonce)) }

  describe '.encrypt' do
    it 'should encrypt the message' do
      expect(subject.encrypt(payload)).to eq token
    end
  end

  describe '.decrypt' do
    let(:original) { 'v2.local.6EHOXWuFHUBNy9gEHssSVKOIT//W7AeqENvznTJA+i72bZE.aGVsbG8gdGhlcmU' }
    let(:tampered) { 'v2.local.6EHOXWWFHUBNy9gEHssSVKOIT//W7AeqENvznTJA+i72bZE.aGVsbG8gdGhlcmU' }

    it 'should decrypt the message' do
      expect(subject.decrypt(token)).to eq payload
    end

    describe 'with a footer' do
      let(:footer) { 'foot the bill' }
      let(:token) { subject.encrypt(payload) }
      let(:bad_footer) { described_class.from_encode64_key(key, 'other foot') }

      it 'should decrypt when the footer is correct' do
        expect(subject.decrypt(token)).to eq payload
      end

      it "should raise when the footer doesn't match what's expected" do
        expect { bad_footer.decrypt(token) }.to raise_error Paseto::TokenError
      end
    end

    it 'should raise an error for a bad header' do
      expect { subject.decrypt("incorrect.header") }.to raise_error Paseto::HeaderError
    end

    it 'should raise an error when trying to decrypt a tampered message' do
      expect(subject.decrypt(original)).to eq('message')
      expect { subject.decrypt(tampered) }.to raise_error Paseto::AuthenticationError
    end

    it 'should raise error trying to decrypt junk' do
      expect { subject.decrypt("v2.local." + SecureRandom.hex) }.to raise_error Paseto::TokenError
    end
  end
end