# Paseto

![](https://travis-ci.org/mguymon/paseto.rb.svg?branch=master)

Ruby implementation of [Paseto](https://github.com/paragonie/paseto) using [libsodium](https://github.com/crypto-rb/rbnacl) that supports [Version 2](https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md).

> Paseto (Platform-Agnostic SEcurity TOkens) is a specification for secure stateless tokens.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'paseto'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install paseto

## Usage

## Public Signing

    require 'paseto'
    key = Paseto::Public.generate_signing_key
    public = Paseto::Public.new(key)
    signed_msg = public.sign('a fancy message')
    public.verify(signed_msg) == true

## Local encryption

    require 'paseto'
    key = Paseto::Local.generate_aead_key
    local = Paseto::Local.new(key)
    encrypted_msg = local.encrypt('a fancy message')
    local.decrypt(encrypted_msg) == 'a fancy message'

## Using a Base64 key

    key = Paseto.encode64(Paseto::Public.generate_signing_key)
    public = Paseto::Public.from_encode64_key(key)

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/paseto. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Paseto project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/[USERNAME]/paseto/blob/master/CODE_OF_CONDUCT.md).
