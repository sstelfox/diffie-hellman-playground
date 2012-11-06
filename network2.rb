#!/usr/bin/env ruby

require "json"
require "openssl"
require "securerandom"

gp = JSON.parse(File.read('primes.json'))[0]

GENERATOR=gp["generator"].to_i
PRIME=gp["prime"].to_i(16)

VERSION="0.2"

class Integer
  def mod_exp(pow, mod)
    self.to_bn.mod_exp(pow, mod).to_i
  end
end

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

  def transmit(sender, message)
    @clients.each do |c|
      unless c.client_id == sender
        c.receive(message)
      end
    end
  end

  private_class_method :new
end

class Client
  attr_reader :client_id, :session_id, :private_key
  attr_accessor :known_hosts

  def initialize(handle, session_name = nil)
    @client_id    = SecureRandom.hex(6).downcase
    @handle       = handle
    
    @session_name = session_name
    @known_hosts  = [client_id]

    transmit({"type" => "announce"})
    transmit({"type" => "ping"})

    request_new_session
  end

  def public_key
    return @public_key unless @public_key.nil?
    return nil if @generator.nil? || @prime.nil? || @private_key.nil?

    @public_key = @generator.mod_exp(@private_key, @prime)
  end

  def receive(message)
    msg = JSON.parse(message)

    # Allows for multiple sessions to go on
    return if msg["session"] && msg["session"] != @session_id
    return if msg["destination"] && msg["destination"] != client_id

    puts "#{client_id} Recv:\t #{message}"

    if self.respond_to?(msg["type"])
      self.public_send(msg["type"], msg)
    end
  end

  def transmit(data)
    data["session"] = @session_name if @session_name
    data["source"] = client_id

    message = JSON.generate(data)
    puts "#{client_id} Send:\t #{message}"
    
    socket.transmit(client_id, message)
  end

  ##### BEGIN PACKET HANDLERS #####

  def announce(msg)
    unless client_id == msg["source"] || known_hosts.include?(msg["source"])
      known_hosts << msg["source"]
      known_hosts.sort!
    end
  end

  def ping(msg)
    transmit({"type" => "pong", "destination" => msg["source"]})
  end

  def pong(msg)
    # Register responses from a ping like an announce
    announce(msg)
  end

  ##### END PACKET HANDLERS #####

  private

  def init_private_key
    @private_key  = SecureRandom.hex(32).to_i(16)
  end

  def request_new_session
    init_private_key

    @generator = GENERATOR
    @prime = PRIME
  end

  def socket
    return @socket unless @socket.nil?

    @socket = Network.instance
    @socket.register_client(self)
    @socket
  end
end

clients = []

4.times do |n|
  clients << Client.new("client#{n}")
end

clients.each do |c|
  puts c.known_hosts.join(",")
end

