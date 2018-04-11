require 'securerandom'

RSpec.describe Paseto::Public do
  subject { described_class.from_encode64_key(key, footer) }

  let(:key) { 'KxltS+uXOrPh5ZV2cwECjkcBrXbhTOaqQgg93j6FZ0w' }
  let(:footer) { nil }

  let(:signed_message) do
    'v2.public.dGVzdBRCVsCf+slzp0+MikU4+sxDF6S5xcho1GMyoNr/4gacdYdjSJ30W6GHnQdEPXam1LxIrN7i0qSn1ZUlUcbQQQg'
  end

  let(:bad_message) do
    'v2.public.cGVzdBRCVsCf+slzp0+MikU4+sxDF6S5xcho1GMyoNr/4gacdYdjSJ30W6GHnQdEPXam1LxIrN7i0qSn1ZUlUcbQQQg'
  end

  let(:signed_message_with_footer) do
    'v2.public.dGVzdPZfnxfDSw8vuPoRaeTao+h1nhbn0e10GUSEBtbbHza6LPdUKApm5YorohRGKO2zdvauiVbAKgixLjKtXxYC7w0.cGxhaW4gdGV4dCBmb290ZXI'
  end

  describe '#sign' do
    it 'should sign a message' do
      expect(subject.sign('test')).to eq signed_message
    end

    context 'with a footer' do
      let(:footer) { 'plain text footer' }

      it 'should sign a message' do
        expect(subject.sign('test')).to eq signed_message_with_footer
      end
    end
  end

  describe '#verify' do
    it 'should verify a message' do
      expect(subject.verify(signed_message)).to be_truthy
    end

    it 'should reject a bad signature' do
      expect { subject.verify(bad_message) }.to raise_error Paseto::AuthenticationError
    end

    it 'should raise an error for a bad header' do
      expect { subject.verify("incorrect.header") }.to raise_error Paseto::HeaderError
    end

    it 'should raise error trying to decrypt junk' do
      expect { subject.verify("v2.public." + SecureRandom.hex) }.to raise_error Paseto::Error
    end

    it 'should allow access to the signed payload' do
      expect(subject.verify(signed_message)).to eq('test')
    end

    context 'with a footer' do
      let(:footer) { 'plain text footer' }
      let(:bad_footer) { described_class.from_encode64_key(key, 'other foot') }

      it "should verify when the footer matches what's expected" do
        expect(subject.verify(signed_message_with_footer)).to eq('test')
      end

      it "should raise when the footer doesn't match what's expected" do
        expect { bad_footer.verify(signed_message_with_footer) }.to raise_error Paseto::TokenError
      end
    end
  end
end
