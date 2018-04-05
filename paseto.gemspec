
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'paseto/version'

Gem::Specification.new do |spec|
  spec.name          = 'paseto'
  spec.version       = Paseto::VERSION
  spec.authors       = ['Michael Guymon']
  spec.email         = ['mguymon@instructure.com']

  spec.summary       = %q{Ruby impl of Paseto}
  spec.description   = %q{Ruby impl of Paseto}
  spec.homepage      = 'https://github.com/mguymon/paseto.rb'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = 'bin'
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'rbnacl-libsodium', '~> 1.0'
  spec.add_development_dependency 'bundler', '~> 1.16'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'pry', '~> 0.11'
end
