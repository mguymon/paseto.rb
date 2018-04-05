RSpec.describe Paseto::Public do
  subject { described_class.from_encode64_key(key, footer) }

  let(:key) { 'KxltS+uXOrPh5ZV2cwECjkcBrXbhTOaqQgg93j6FZ0w' }
  let(:footer) { nil }

  let(:signed_message) do
    'v2.public.AgAAAAAAAAAJAAAAAAAAAHYyLnB1YmxpYwQAAAAAAAAAdGVzdBRCVsCf+slzp0+MikU4+sxDF6S5xcho1GMyoNr/4gacdYdjSJ30W6GHnQdEPXam1LxIrN7i0qSn1ZUlUcbQQQg'
  end

  let(:signed_mesage_with_footer) do
    'v2.public.AwAAAAAAAAAJAAAAAAAAAHYyLnB1YmxpYwQAAAAAAAAAdGVzdBEAAAAAAAAAcGxhaW4gdGV4dCBmb290ZXL2X58Xw0sPL7j6EWnk2qPodZ4W59HtdBlEhAbW2x82uiz3VCgKZuWKK6IURijts3b2rolWwCoIsS4yrV8WAu8N.cGxhaW4gdGV4dCBmb290ZXI'
  end

  let(:bad_message) do
    'v2.public.AgAAAAAAAAAJAAAAAAAAAHYyLnB1YmxpYwMAAAAAAAAAYmFk_ss6VBLy-32gO6mH3tPwHH3wn-VPGmW1ZkE6IU2lZqaVcldxp5th-_PVR5B2ZOmGodQBRTb6xwue77AgqBw1Dw'
  end

  describe '#sign' do
    it 'should sign a message' do
      expect(subject.sign('test')).to eq signed_message
    end

    context 'with a footer' do
      let(:footer) { 'plain text footer' }

      it 'should sign a message' do
        expect(subject.sign('test')).to eq signed_mesage_with_footer
      end
    end
  end

  describe '#verify' do
    it 'should verify a message' do
      expect(subject.verify(signed_message)).to be_truthy
    end

    it 'should reject a bad signature' do
      expect(subject.verify(bad_message)).to be_falsey
    end

    it 'should raise an error for a bad header' do
      expect { subject.verify("incorrect.header") }.to raise_error Paseto::BadHeaderError
    end

    it 'should raise error trying to decrypt junk' do
      expect { subject.verify("v2.public." + SecureRandom.hex ) }.to raise_error Paseto::Error
    end

    context 'with a footer' do
      let(:footer) { 'plain text footer' }

      it 'should sign a message' do
        expect(subject.verify(signed_mesage_with_footer)).to be_truthy
      end
    end
  end
end