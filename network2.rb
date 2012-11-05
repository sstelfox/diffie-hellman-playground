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
        puts "#{c.client_id} Received:\t\t#{message}"
        c.receive(message)
      end
    end
  end

  private_class_method :new
end

class Client
  attr_reader :client_id, :known_clients

  def initialize
    @client_id = SecureRandom.hex(6).downcase
    @session_id = nil

    puts "Initialized: #{@client_id}"

    socket.send(client_id, JSON.generate({"type" => "announce", "data" => client_id}))
  end

  def public_key
    @public_key ||= modpow(@generator, @private_key, @prime).to_i
  end

  def receive(message)
    msg = JSON.parse(message)

    return if @session_id && message["session"] != @session_id
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

4.times do 
  clients << Client.new
end

