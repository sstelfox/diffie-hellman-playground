#!/usr/bin/env ruby

require "openssl"
require "securerandom"

def openssl_modexp(base, pow, mod)
  base.to_bn.mod_exp(pow, mod).to_i
end

def lp_modexp(x, r, m)
    y = r
    z = x
    v = 1
    while y > 0
        u = y % 2
        t = y / 2
        if u == 1
            v = (v * z) % m
        end
        z = z * z % m
        y = t
    end
    return v
end

def pure_modexp(base, pow, mod)
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

# openssl_modexp
# lp_modexp
# pure_modexp

# Simple integrity check of each...
openssl_sanity = (openssl_modexp(5, 6, 23) == 8)
lp_sanity = (lp_modexp(5, 6, 23) == 8)
pure_sanity = (pure_modexp(5, 6, 23) == 8)

puts "OpenSSL:\t#{openssl_sanity}"
puts "LP:\t\t#{lp_sanity}"
puts "Pure:\t\t#{pure_sanity}"

# Speed test OpenSSL
openssl_start = Time.now
(1..100).each do |b|
  (1..100).each do |e|
    (1..100).each do |m|
      openssl_modexp(b, e, m)
    end
  end
end
openssl_end = Time.now
puts "OpenSSL Time:\t#{openssl_end - openssl_start}"

# Speed test lp
lp_start = Time.now
(1..100).each do |b|
  (1..100).each do |e|
    (1..100).each do |m|
      lp_modexp(b, e, m)
    end
  end
end
lp_end = Time.now
puts "LP Time:\t#{lp_end - lp_start}"

# Speed test pure
pure_start = Time.now
(1..100).each do |b|
  (1..100).each do |e|
    (1..100).each do |m|
      pure_modexp(b, e, m)
    end
  end
end
pure_end = Time.now
puts "Pure Time:\t#{pure_end - pure_start}"

# Deeper sanity check
successes = 0
failures = 0

puts "Beginning deeper sanity check..."
(1..100).each do |b|
  (1..100).each do |e|
    (1..100).each do |m|
      l = lp_modexp(b, e, m)
      o = openssl_modexp(b, e, m)
      p = pure_modexp(b, e, m)

      (l == o && o == p && p == l) ?  successes += 1 : failures += 1
    end
  end
end

puts "Successes: #{successes}, Failures: #{failures}"

puts "Beginning large number tests..."

openssl_start = Time.now
100.times do |n|
  b = n % 10
  e = SecureRandom.hex(32).to_i(16)
  m = SecureRandom.hex(32).to_i(16)
  openssl_modexp(b, e, m)
end
openssl_end = Time.now
puts "OpenSSL Time:\t#{openssl_end - openssl_start}"

lp_start = Time.now
100.times do |n|
  b = n % 10
  e = SecureRandom.hex(32).to_i(16)
  m = SecureRandom.hex(32).to_i(16)
  lp_modexp(b, e, m)
end
lp_end = Time.now
puts "LP Time:\t#{lp_end - lp_start}"

pure_start = Time.now
10000.times do |n|
  b = n % 10
  e = SecureRandom.hex(32).to_i(16)
  m = SecureRandom.hex(32).to_i(16)
  pure_modexp(b, e, m)
end
pure_end = Time.now
puts "Pure Time:\t#{pure_end - pure_start}"

