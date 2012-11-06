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
  attr_reader :client_id, :session_key
  attr_accessor :known_hosts

  def initialize(handle)
    @client_id    = SecureRandom.hex(6).downcase
    @handle       = handle
    @known_hosts  = [client_id]
    @session_key  = nil

    # Announce allows other clients to add this one to their known host list
    transmit({"type" => "announce"})

    # Ping allows this client to become aware of all other hosts
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

    return if msg["destination"] && msg["destination"] != client_id

    puts "#{client_id} Recv:\t #{message}"

    if self.respond_to?("handle_" + msg["type"])
      self.public_send("handle_" + msg["type"], msg)
    end
  end

  def transmit(data)
    data["source"] = client_id

    message = JSON.generate(data)
    puts "#{client_id} Send:\t #{message}"
    
    socket.transmit(client_id, message)
  end

  def transmit_to_next_host(data)
    # Find this client's position in the list
    my_position = known_hosts.index(client_id)

    # Increment our position by 1 and wrap around to the first host if we go
    # beyond the number of known hosts
    next_position = (my_position + 1) % known_hosts.count

    # No point in continuing if I'm going to be sending to myself
    return if my_position == next_position

    # Set our destination and transmit as normal
    data["destination"] = known_hosts[next_position]
    transmit(data)
  end

  ##### BEGIN PACKET HANDLERS #####

  def handle_announce(msg)
    unless client_id == msg["source"] || known_hosts.include?(msg["source"])
      known_hosts << msg["source"]
      known_hosts.sort!
    end
  end

  def handle_init_key_exchange(msg)
    init_private_key
    
    @prime      = msg["data"]["prime"].to_i(16)
    @generator  = msg["data"]["generator"].to_i(16)

    @session_key = {"hosts" => [client_id], "key" => public_key}
    announce_session_key
  end

  def handle_ping(msg)
    transmit({"type" => "pong", "destination" => msg["source"]})
  end

  def handle_pong(msg)
    # Register responses from a ping like an announce
    handle_announce(msg)
  end

  def handle_public_key(msg)
    # If the key exchange continues far enough that this client receives a key
    # that has already been signed by itself it indicates that some client
    # shared the full completed session key across the network in plaintext.
    if msg["data"]["hosts"].include?(client_id)
      puts "ERROR: Session key compromised."
      return
    end

    @session_key = {
      "hosts" => (msg["data"]["hosts"] + [client_id]).sort,
      "key"   => msg["data"]["key"].to_i(16).mod_exp(@private_key, @prime)
    }

    unless @session_key["hosts"] == @known_hosts
      announce_session_key
    end
  end

  ##### END PACKET HANDLERS #####

  private

  def announce_session_key
    transmit_to_next_host({
      "type" => "public_key",
      "data" => {
        "hosts" => @session_key["hosts"],
        "key"   => @session_key["key"].to_s(16)
      }
    })
  end

  def init_private_key
    @private_key  = SecureRandom.hex(32).to_i(16)
  end

  def request_new_session
    init_private_key

    @generator = GENERATOR
    @prime = PRIME

    transmit({
      "type" => "init_key_exchange",
      "data" => {
        "generator" => @generator.to_s(16),
        "prime"     => @prime.to_s(16),
      }
    })
    
    @session_key = {"hosts" => [client_id], "key" => public_key}
    announce_session_key
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

puts
clients.each do |c|
  puts c.client_id + ": " + c.known_hosts.join(",")
end

puts
clients.each do |c|
  puts c.client_id + ": " + JSON.generate(c.session_key)
end

