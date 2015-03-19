require 'openssl'
require 'base64'
require 'hiera/backend/eyaml/encryptor'
require 'hiera/backend/eyaml/encryptors/pkcs7'
require 'hiera/backend/eyaml/utils'
require 'hiera/backend/eyaml/plugins'
require 'hiera/backend/eyaml/options'

class Hiera
  module Backend
    module Eyaml
      module Encryptors

        class Pkcs7sig < Encryptor

          VERSION = "0.6"

          self.tag = "PKCS7SIG"

          def self.public_x509
            public_key = Hiera::Backend::Eyaml::Encryptors::Pkcs7::option :public_key
            raise StandardError, "pkcs7_public_key is not defined" unless public_key
            public_key_pem = File.read public_key
            OpenSSL::X509::Certificate.new(public_key_pem)
          end

          def self.private_rsa
            private_key = Hiera::Backend::Eyaml::Encryptors::Pkcs7::option :private_key
            raise StandardError, "pkcs7_private_key is not defined" unless private_key
            private_key_pem = File.read private_key
            OpenSSL::PKey::RSA.new(private_key_pem)
          end

          def self.encrypt plaintext
            crypted = Hiera::Backend::Eyaml::Encryptors::Pkcs7::encrypt plaintext
            flags = OpenSSL::PKCS7::BINARY

            OpenSSL::PKCS7::sign(self.public_x509, self.private_rsa, crypted, nil, flags).to_der
          end

          def self.decrypt ciphertext
            store = OpenSSL::X509::Store.new
            flags = OpenSSL::PKCS7::NOVERIFY
            pkcs7 = OpenSSL::PKCS7.new(ciphertext)
            if not pkcs7.verify([self.public_x509], store, nil, flags)
              raise StandardError, "failed to verify signature"
            end

            Hiera::Backend::Eyaml::Encryptors::Pkcs7::decrypt pkcs7.data
          end

          def self.create_keys
            Hiera::Backend::Eyaml::Encryptors::Pkcs7::create_keys
          end

        end

      end

    end

  end

end
