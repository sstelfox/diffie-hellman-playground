#!/usr/bin/env ruby

require "json"
require "openssl"
require "securerandom"

def modpow(base, pow, mod)
  base.to_bn.mod_exp(pow, mod).to_i
end

gp = JSON.parse(File.read('primes.json'))[0]

GENERATOR=gp["generator"].to_i
PRIME=gp["prime"].to_i(16)

class Network
  def initialize
    @clients = []
  end

  @@instance = Network.new

  def self.instance
    @@instance
  end

  def register_client(client)
    @clients << client
  end

  def send(sender, message)
    puts "#{sender} Sent:\t\t#{message}"
    @clients.each do |c|
      unless c.client_id == sender
        c.receive(message)
      end
    end
  end

  private_class_method :new
end

class SessionKey < Struct.new(:keys_included, :key)
  def attributes
    {
      "keys_included" => keys_included,
      "key" => key
    }
  end
end

class Client
  attr_reader :client_id, :known_clients

  def initialize
    @client_id = SecureRandom.hex(4).downcase
    @known_clients = [@client_id]

    puts "Initialized: #{@client_id}"

    announce_message
    request_clients_message
    init_key_exchange_message
  end

  def receive(message)
    #puts "#{client_id} Received:\t#{message}"

    message = JSON.parse(message)
    data = message["data"]

    case message["type"]
    when "announce"
      unless @known_clients.include?(data)
        @known_clients << data
        @known_clients.sort!
      end
    when "requestClients"
      unless data.include?(client_id)
        announce_message
      end
    when "initKeyExchange"
      @generator = data["generator"]
      @prime = data["prime"]
      @private_key = SecureRandom.hex(32).to_i(16)

      @session_keys = [
        SessionKey.new(data["keys_included"], data["key"]),
        SessionKey.new([client_id], public_key),
      ]

      announce_key(@session_keys[1])

      @session_keys << SessionKey.new(
        (@session_keys[0].keys_included + [client_id]).sort,
        modpow(@session_keys[0].key, @private_key, @prime)
      )

      unless (@known_clients - @session_keys.last.keys_included).empty?
        announce_key(@session_keys.last)
      end
    when "announceKey"
      sk = SessionKey.new(data["keys_included"], data["key"])

      unless @session_keys.include?(sk)
        @session_keys << sk

        unless sk.keys_included.include?(client_id)
          @session_keys << SessionKey.new(
            (sk.keys_included + [client_id]).sort,
            modpow(sk.key, @private_key, @prime)
          )

          unless (@known_clients - @session_keys.last.keys_included).empty?
            announce_key(@session_keys.last)
          end
        end
      end
    end
  end

  def public_key
    @public_key ||= modpow(@generator, @private_key, @prime).to_i
  end

  def announce_key(sk)
    raise ArgumentError unless sk.kind_of?(SessionKey)

    socket.send(client_id, JSON.generate({
      "type" => "announceKey",
      "data" => sk.attributes
    }))
  end

  def announce_message
    socket.send(client_id, JSON.generate({"type" => "announce", "data" => client_id}))
  end

  def init_key_exchange_message
    @generator = GENERATOR
    @prime = PRIME
    @private_key = SecureRandom.hex(32).to_i(16)

    @session_keys = [SessionKey.new([client_id], public_key)]

    socket.send(client_id, JSON.generate({
      "type" => "initKeyExchange",
      "data" => {
        "generator" => @generator,
        "prime" => @prime,
        "key" => @session_keys.last.key,
        "keys_included" => @session_keys.last.keys_included
      }
    }))
  end

  def request_clients_message
    socket.send(client_id, JSON.generate({"type" => "requestClients", "data" => @known_clients}))
  end

  def session_enc_key
    return @sek unless @sek.nil?

    @session_keys.each do |sk|
      if (@known_clients - [client_id]).sort == sk["keys_included"].sort
        @sek = modpow(sk.key, @private_key, @prime)
        return @sek
      end
    end

    return nil
  end

  private

  def socket
    return @socket unless @socket.nil?

    @socket = Network.instance
    @socket.register_client(self)
    @socket
  end
end

clients = []

6.times do 
  clients << Client.new
end

puts

clients.each do |c|
  puts "#{c.client_id}: #{c.known_clients.join(",")}"
  puts "#{c.session_enc_key}"
end

