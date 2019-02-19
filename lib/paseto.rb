# frozen_string_literal: true

require 'base64'
require 'rbnacl'

require 'paseto/version'
require 'paseto/error'
require 'paseto/token'
require 'paseto/public'
require 'paseto/local'

# Platform-Agnostic SEcurity TOkens
module Paseto
  EMPTY_FOOTER = ''

  # An Array#pack format to pack an unsigned little-endian 64-bit integer
  UNSIGNED_LITTLE_64 = 'Q<'

  # https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#pae-definition
  def self.encode_length(num)
    [num].pack(UNSIGNED_LITTLE_64)
  end

  # https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#pae-definition
  def self.pre_auth_encode(*pieces)
    initial_output = encode_length(pieces.length)

    pieces.reduce(initial_output) do |output, piece|
      output + encode_length(piece.length) + piece
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
