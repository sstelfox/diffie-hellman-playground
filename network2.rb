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
    @private_key  = SecureRandom.hex(32).to_i(16)

    @msg_handler  = MsgHandler.new(self)
    
    @session_name = session_name
    @known_hosts  = [client_id]

    transmit({"type" => "announce"})
    transmit({"type" => "ping"})
    transmit({"type" => "publicKey", "data" => public_key})
  end

  def public_key
    @public_key ||= GENERATOR.mod_exp(@private_key, PRIME)
  end

  def receive(message)
    msg = JSON.parse(message)

    # Allows for multiple sessions to go on
    return if msg["session"] && msg["session"] != @session_id
    return if msg["destination"] && msg["destination"] != client_id

    puts "#{client_id} Recv:\t #{message}"

    if @msg_handler.respond_to?(msg["type"])
      @msg_handler.send(msg["type"], msg)
    end
  end

  def transmit(data)
    data["session"] = @session_name if @session_name
    data["source"] = client_id

    message = JSON.generate(data)
    puts "#{client_id} Send:\t #{message}"
    
    socket.transmit(client_id, message)
  end

  private

  def socket
    return @socket unless @socket.nil?

    @socket = Network.instance
    @socket.register_client(self)
    @socket
  end
end

class MsgHandler < BasicObject
  def initialize(client)
    @client = client
  end

  def respond_to?(name)
    ["announce", "ping", "pong"].include?(name)
  end

  def send(*args)
    __send__(*args)
  end

  ##### BEGIN PACKET HANDLERS #####

  def announce(msg)
    unless @client.client_id == msg["source"] || @client.known_hosts.include?(msg["source"])
      @client.known_hosts << msg["source"]
      @client.known_hosts.sort!
    end
  end

  def ping(msg)
    @client.transmit({"type" => "pong", "destination" => msg["source"]})
  end

  def pong(msg)
    # Register responses from a pong, like an announce
    announce(msg)
  end

  private

  def puts(output)
    $stdout << output << "\n"
  end
end

clients = []

4.times do |n|
  clients << Client.new("client#{n}")
end

clients.each do |c|
  puts c.known_hosts.join(",")
end

