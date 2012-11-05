#!/usr/bin/env ruby

require "json"
require "openssl"
require "securerandom"

modp_groups = JSON.parse(File.read('primes.json'))

# Pure ruby version
def modpow(base, pow, mod)
  raise ArgumentError if pow < 0
  result = 1
  base = base % mod

  until pow.zero?
    result = (result * base) % mod if pow.odd?
    pow >>= 1
    base = (base * base) % mod
  end

  result
end

# OpenSSL version
def modpow(base, pow, mod)
  base.to_bn.mod_exp(pow, mod)
end

# Needed variables to perform key exchange:
#   a = Alice's private key
#   b = Bob's private key
#   g = DH generator
#   p = Prime number
#
# Calculated variables:
#   aA = Alice's public key
#   bB = Bob's public key
#   sA = sB = Secret key

class DHUser
  attr_reader :generator, :prime, :id

  def initialize(generator, prime)
    @id = SecureRandom.hex(4).to_i(16)

    @generator = generator
    @prime = prime

    new_key
  end

  def new_key
    @private_key = SecureRandom.hex(32).to_i(16)
  end

  def public_key
    modpow(generator, private_key, prime)
  end
end

# Min 2, Up to 8
participant_count = rand(6) + 2
participants = []

participant_count.times { participants << DHUser.new(modp_groups[5]["generator"], modp_groups[5]["prime"].to_i(16)) }

# Print out their private keys
puts "Alice's private key:\t#{participants[0].private_key.to_s(16).downcase}"
puts "Bob's private key:\t#{participants[1].private_key.to_s(16).downcase}"
puts

# Print out their public keys
puts "Alice's public key:\t#{participants[0].public_key.to_s(16).downcase}"
puts "Bob's public key:\t#{participants[1].public_key.to_s(16).downcase}"
puts

# Caclulate the shared secret key
sA = modpow(participants[1].public_key, participants[0].private_key, participants[0].prime)
sB = modpow(participants[0].public_key, participants[1].private_key, participants[1].prime)

puts "Alice's secret:\t\t#{sA.to_s(16).downcase}"
puts "Bob's secret:\t\t#{sB.to_s(16).downcase}"

