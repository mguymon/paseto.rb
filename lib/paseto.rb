require 'base64'
require 'rbnacl/libsodium'

require 'paseto/version'
require 'paseto/error'
require 'paseto/token'
require 'paseto/public'
require 'paseto/local'

module Paseto

  # https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#pae-definition
  def self.encode_length(n)
    str = []
    (0..7).each do |i|
      # Clear the MSB for interoperability
      n &= 127 if (i === 7)

      str << (n & 255)
      n = n >> 8
    end

    str.pack('Q')
  end

  # https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#pae-definition
  def self.pre_auth_encode(*pieces)
    compacted_pieces = pieces.compact

    initial_output = encode_length(compacted_pieces.length)
    compacted_pieces.reduce(initial_output) do |output, piece|
      output += encode_length(piece.length)
      output += piece
    end
  end

  def self.decode64(str)
    Base64.urlsafe_decode64(str)
  end

  def self.encode64(bin)
    # Remove the padding on the encode64
    Base64.urlsafe_encode64(bin).gsub(/=+$/, '')
  end
end
