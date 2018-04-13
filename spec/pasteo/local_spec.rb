require 'securerandom'

RSpec.describe Paseto::V2::Local do
  subject { described_class }

  let(:payload) { 'test' }
  let(:encoded_key) { '2eOIs-JWWCKvFDg-eHFsIBHfMuN-3bqkceK8moM4S1Y' }
  let(:key) { Paseto::V2::Local::Key.decode64(encoded_key) }
  let(:footer) { nil }
  let(:token) { 'v2.local.MDEyMzQ1NjcwMTIzNDU2NzAxMjM0NTY37Iy-a-UM_m_pcMUv8uz5GFsiupo' }
  let(:nonce) { '012345670123456701234567' }

  describe Paseto::V2::Local::Key do
    subject { described_class }

    it '.encode64 returns a base64-encoded key' do
      expect(key.encode64).to eq(encoded_key)
    end
  end

  describe '.encrypt' do
    it 'should encrypt the message' do
      allow_any_instance_of(described_class::Key).to receive(:generate_nonce)
        .and_return(nonce)

      expect(subject.encrypt(payload, key)).to eq token
    end
  end

  describe '.decrypt' do
    let(:footer) { 'hello there' }
    let(:original) { 'v2.local.F0gtYeERxvBtusBi459R9XRNkcqO0B36PA6mK8Wspn5fpRCX5amP_lPYRPo.aGVsbG8gdGhlcmU' }
    let(:tampered) { 'v2.local.G0gtYeERxvBtusBi459R9XRNkcqO0B36PA6mK8Wspn5fpRCX5amP_lPYRPo.aGVsbG8gdGhlcmU' }

    # Generated using python 3.6.2 using:
    # from paseto import PasetoV2
    # import base64
    # import secrets
    # key = secrets.token_bytes(32)
    # print(base64.b64encode(key).replace(b'=', b''))
    # print(PasetoV2.encrypt(b'too many secrets', key, b'plaintext footer'))
    let(:python_key) { 'L3kflrX9R4kkA0BJtvRMpXQJ892affEei2SmF2ZRizI' }
    let(:python_token) { 'v2.local.saehdwc7x-autna6Nmhypx_Bo5DJGbsw7Fnlugcl5-arym2_FsOQAA4xZXgyCDpSz7i3GOmI06Y.cGxhaW50ZXh0IGZvb3Rlcg' }

    it 'should decrypt the message' do
      expect(subject.decrypt(token, key)).to eq payload
    end

    it 'should decrypt a token generated from pypaseto' do
      key = subject::Key.decode64(python_key)
      token = Paseto.parse(python_token)
      expect(token.footer).to eq('plaintext footer')
      expect(key.decrypt(token)).to eq('too many secrets')
    end

    describe 'with a footer' do
      let(:bad_footer) { 'foot the bill' }
      let(:token) { subject.encrypt(payload, key, footer) }

      it 'should decrypt when the footer is correct' do
        expect(subject.decrypt(token, key, footer)).to eq payload
      end

      it 'should not require footer to decrypt a parsed token' do
        expect(key.decrypt(Paseto.parse(token))).to eq payload
      end

      it "should raise when the footer doesn't match what's expected" do
        expect { subject.decrypt(token, key, bad_footer) }.to raise_error Paseto::TokenError
      end
    end

    it 'should raise an error for a bad header' do
      expect { subject.decrypt("incorrect.header", key) }.to raise_error Paseto::HeaderError
    end

    it 'should raise an error when trying to decrypt a tampered message' do
      expect(subject.decrypt(original, key, footer)).to eq(payload)
      expect { subject.decrypt(tampered, key, footer) }.to raise_error Paseto::AuthenticationError
    end

    it 'should raise error trying to decrypt junk' do
      expect { subject.decrypt("v2.local." + SecureRandom.hex, key) }.to raise_error Paseto::TokenError
    end
  end
end
