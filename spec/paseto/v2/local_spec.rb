# frozen_string_literal: true

require 'securerandom'

RSpec.describe Paseto::V2::Local do
  let(:local) { described_class }

  # Generated using https://github.com/paragonie/paseto:
  #
  # use ParagonIE\Paseto\Protocol\Version2;
  # use ParagonIE\Paseto\Keys\SymmetricKey;
  # use ParagonIE\ConstantTime\Base64UrlSafe;
  # use ParagonIE\Paseto\Tests\NonceFixer;
  #
  # $v2Encrypt = NonceFixer::buildUnitTestEncrypt(new Version2)->bindTo(null, new Version2)
  # $key = new SymmetricKey(Base64UrlSafe::decode('2eOIs-JWWCKvFDg-eHFsIBHfMuN-3bqkceK8moM4S1Y'))
  # $nonce = str_repeat("\0", 24);
  # $token = $v2Encrypt('test', $key, '', $nonce);
  #
  # echo $token;
  let(:payload) { 'test' }
  let(:encoded_key) { '2eOIs-JWWCKvFDg-eHFsIBHfMuN-3bqkceK8moM4S1Y' }
  let(:key) { Paseto::V2::Local::Key.decode64(encoded_key) }
  let(:footer) { nil }
  let(:token) { 'v2.local.NIE4RiRUscJNFhEh9gkAKcC-JSvDaHsmSEl7mk2eJDWOIAEISxzeKxjamow' }
  let(:nonce) { "\0" * 24 }

  describe Paseto::V2::Local::Key do
    it '.encode64 returns a base64-encoded key' do
      expect(key.encode64).to eq(encoded_key)
    end
  end

  describe '.encrypt' do
    it 'encrypts the message' do
      allow(key)
        .to receive(:generate_nonce_key)
        .and_return(nonce)

      expect(local.encrypt(payload, key)).to eq token
    end

    it 'uses a different nonce for every message, even if random fails' do
      allow(key)
        .to receive(:generate_nonce_key)
        .and_return(nonce)

      first = key.send(:generate_nonce, 'first')
      second = key.send(:generate_nonce, 'second')
      expect(first).not_to eq(second)
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

    it 'decrypts the message' do
      expect(local.decrypt(token, key)).to eq payload
    end

    it 'decrypts a token generated from pypaseto' do
      key = local::Key.decode64(python_key)
      token = Paseto.parse(python_token)
      expect(key.decrypt(token)).to eq('too many secrets')
    end

    it 'decrypts a token footer generated from pypaseto' do
      token = Paseto.parse(python_token)
      expect(token.footer).to eq('plaintext footer')
    end

    describe 'with a footer' do
      let(:bad_footer) { 'foot the bill' }
      let(:token) { local.encrypt(payload, key, footer) }

      it 'decrypts when the footer is correct' do
        expect(local.decrypt(token, key, footer)).to eq payload
      end

      it 'does not require footer to decrypt a parsed token' do
        expect(key.decrypt(Paseto.parse(token))).to eq payload
      end

      it "raises when the footer doesn't match what's expected" do
        expect { local.decrypt(token, key, bad_footer) }.to raise_error Paseto::TokenError
      end
    end

    it 'raises an error for a bad header' do
      expect { local.decrypt('incorrect.header', key) }.to raise_error Paseto::HeaderError
    end

    it 'raises an error when trying to decrypt a tampered message' do
      expect { local.decrypt(tampered, key, footer) }.to raise_error Paseto::AuthenticationError
    end

    it 'raises error trying to decrypt junk' do
      expect { local.decrypt('v2.local.' + SecureRandom.hex, key) }.to raise_error Paseto::TokenError
    end

    context 'without a footer' do
      # Generated using https://github.com/paragonie/paseto:
      #
      # use ParagonIE\Paseto\Protocol\Version2;
      # use ParagonIE\Paseto\Keys\SymmetricKey;
      # use ParagonIE\ConstantTime\Base64UrlSafe;
      #
      # $key = SymmetricKey::generate(new Version2);
      # $token = Version2::encrypt("too many secrets", $key);
      #
      # echo Base64UrlSafe::encodeUnpadded($key->raw());
      # echo $token;
      let(:b64_encoded_key) { 'c3JZWBwqZGzvSvBPI9mrqsLwlqwbTlnB1ITaRuIU38s' }
      let(:token) { 'v2.local.aA_eaOhAMUgdrMW0lH3rAU5e8WCKOAZATWqZ3tdUj7mGhKUA4Hs4t6BHDoytaqpSR47uZGB1qRI' }
      let(:key) { local::Key.decode64(b64_encoded_key) }
      let(:message) { 'too many secrets' }

      it 'decrypts the message' do
        expect(key.decrypt(token)).to eq(message)
      end
    end
  end
end
