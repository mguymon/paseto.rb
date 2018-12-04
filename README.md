# Paseto

![](https://travis-ci.org/mguymon/paseto.rb.svg?branch=master)

Ruby implementation of [Paseto](https://github.com/paragonie/paseto) using [libsodium](https://github.com/crypto-rb/rbnacl) that currently only supports [Version 2](https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md).

> Paseto (Platform-Agnostic SEcurity TOkens) is a specification for secure stateless tokens.

## Installation

To use Paseto, you will need to install [libsodium][] (at least version `1.0.12` is
required). See [Installing libsodium][] for installation instructions.

Add this line to your application's Gemfile:

```ruby
gem 'paseto'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install paseto

[libsodium]: https://github.com/jedisct1/libsodium
[Installing libsodium]: https://github.com/crypto-rb/rbnacl/wiki/Installing-libsodium

## Usage

For all examples:

    require 'paseto'

## Signing Plaintext Public Messages

    Public = Paseto::V2::Public
    key = Public::SecretKey.generate
    token = key.sign('too many secrets')

    saved_key = key.public_key.encode64 # you can save this string to a db
    decoded_key = Public::PublicKey.decode64(saved_key)
    decoded_key.verify(token) # => 'too many secrets'

## Encrypting Messages with a Shared Secret

    Key = Paseto::V2::Local::Key
    key = Key.generate
    token = key.encrypt('a fancy message')

    saved_key = key.encode64 # a base64 string representation of the key
    decoded_key = Key.decode64(saved_key)
    decoded_key.decrypt(token) # => 'a fancy message'

## Using the Message Footer

The message footer is transmitted plaintext, and can be used for key lookup.
Note that you still must always verify the token via `#decrypt`,  or `#verify`,
as this also verifies the integrity of the footer:

    Local = Paseto::V2::Local
    token = Paseto.parse(raw_data)
    # NOTE: this has not yet been verified! You will always want to call
    # .decrypt or .verify *immediately* after using this value. Otherwise, you
    # will be using data that has not been authenticated.
    kid = token.footer

    saved_key = database.find_key(kid) # find the previously stored key
    decoded_key = Local::Key.decode64(saved_key)
    decoded_key.decrypt(token) # => 'too many secrets'

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/paseto. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Paseto project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/[USERNAME]/paseto/blob/master/CODE_OF_CONDUCT.md).
