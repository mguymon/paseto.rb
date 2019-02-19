# frozen_string_literal: true

RSpec.describe Paseto do
  it 'has a version number' do
    expect(Paseto::VERSION).not_to be nil
  end

  describe '#encode_length' do
    it 'encodes empty' do
      expect(described_class.encode_length(0)).to eq("\x00\x00\x00\x00\x00\x00\x00\x00")
    end

    it 'encodes a length' do
      expect(described_class.encode_length(4)).to eq("\x04\x00\x00\x00\x00\x00\x00\x00")
    end

    it 'encodes numbers greater than 255' do
      expect(described_class.encode_length(256)).to eq("\x00\x01\x00\x00\x00\x00\x00\x00")
    end
  end

  describe '#pre_auth_encode' do
    it 'encodes an empty array' do
      expect(described_class.pre_auth_encode).to eq("\x00\x00\x00\x00\x00\x00\x00\x00")
    end

    it 'encodes an empty string' do
      expect(described_class.pre_auth_encode('')).to(
        eq("\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
      )
    end

    it 'encodes a string' do
      expect(described_class.pre_auth_encode('test')).to(
        eq("\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test")
      )
    end
  end

  describe '#parse' do
    it 'can be used to read the message footer' do
      Token = Paseto::V2::Local
      token = Token.encrypt('message', Token::Key.generate, 'hello there')
      expect(described_class.parse(token).footer).to eq('hello there')
    end
  end
end
