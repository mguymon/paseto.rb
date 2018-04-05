require 'securerandom'

RSpec.describe Paseto::Local do
  subject { described_class.new(key, footer) }

  let(:key) { '2eOIs+JWWCKvFDg+eHFsIBHfMuN+3bqkceK8moM4S1Y' }
  let(:footer) { nil }
  let(:encrypted_message) { 'v2.local.6EHOXWuFHUBNy9gEB8sSU5NTF83oMagI/j89rE26Wmk' }
  let(:nonce) { '6EHOXWuFHUBNy9gE' }

  before { allow(described_class).to receive(:generate_nonce).and_return(Paseto.decode64(nonce)) }

  describe '.encrypt' do
    it 'should encrypt the message' do
      expect(subject.encrypt('test')).to eq encrypted_message
    end
  end

  describe '.decrypt' do
    it 'should encrypt the message' do
      expect(subject.decrypt(encrypted_message)).to eq 'test'
    end

    it 'should raise an error for a bad header' do
      expect { subject.decrypt("incorrect.header") }.to raise_error Paseto::BadHeaderError
    end

    it 'should raise error trying to decrypt junk' do
      expect { subject.decrypt("v2.local." + SecureRandom.hex ) }.to raise_error described_class::BadMessageError
    end
  end
end