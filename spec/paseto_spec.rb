RSpec.describe Paseto do
  it "has a version number" do
    expect(Paseto::VERSION).not_to be nil
  end

  describe '#encode_length' do
    it 'should encode empty' do
      expect(described_class.encode_length(0)).to eq("\x00\x00\x00\x00\x00\x00\x00\x00")
    end

    it 'should encode a length' do
      expect(described_class.encode_length(4)).to eq("\x04\x00\x00\x00\x00\x00\x00\x00")
    end
  end

  describe '#pre_auth_encode' do
    it 'encodes an empty array' do
      expect(described_class.pre_auth_encode()).to eq("\x00\x00\x00\x00\x00\x00\x00\x00")
    end

    it 'encodes an empty string' do
      expect(described_class.pre_auth_encode('')).to eq("\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    end

    it 'encodes a string' do
      expect(described_class.pre_auth_encode('test')).to eq("\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test")
    end
  end

  describe '#read_unauthenticated_footer' do
    it 'can read a message footer without a key' do
      token = Paseto::Local.encrypt('message', Paseto::Local::Key.generate, 'hello there')
      expect(described_class.read_unauthenticated_footer(token)).to eq('hello there')
    end
  end
end
