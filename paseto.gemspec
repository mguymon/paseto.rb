# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'paseto/version'

Gem::Specification.new do |spec|
  spec.name          = 'paseto'
  spec.version       = Paseto::VERSION
  spec.authors       = ['Michael Guymon', 'Frank Murphy']
  spec.email         = ['mguymon@instructure.com', 'fmurphy@instructure.com']

  spec.summary       = 'Ruby impl of Paseto'
  spec.description   = 'Ruby impl of Paseto'
  spec.homepage      = 'https://github.com/mguymon/paseto.rb'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.require_paths = ['lib']
  spec.required_ruby_version = '>= 2.3.0'

  spec.add_dependency 'rbnacl', '>= 7.1.1'
  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'pry', '~> 0.11'
  spec.add_development_dependency 'rake', '>= 12.3.3'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'rubocop', '~> 0.65.0'
  spec.add_development_dependency 'rubocop-rspec', '~> 1.32.0'
end
