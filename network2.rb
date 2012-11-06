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
        c.msg_queue.push(message)
      end
    end
  end

  private_class_method :new
end

class Client
  attr_reader :client_id, :session_key
  attr_accessor :known_hosts, :msg_queue

  def initialize(handle)
    @client_id    = SecureRandom.hex(6).downcase
    @handle       = handle
    @session_key  = nil

    reset_known_hosts

    # Queue for pending network messages
    @msg_queue    = []

    # Ping allows other clients to become aware of this new client and requests
    # other live clients on the network to update their known host list
    transmit({"type" => "ping"})

    request_new_session
  end

  # Process exactly one message
  def tick
    return if sleeping?
    receive(@msg_queue.shift)
  end

  # Returns true if the client has no pending messages to process
  def sleeping?
    @msg_queue.empty?
  end

  def public_key
    return @public_key unless @public_key.nil?
    return nil if @generator.nil? || @prime.nil? || @private_key.nil?

    @public_key = @generator.mod_exp(@private_key, @prime)
  end

  ##### BEGIN PACKET HANDLERS #####

  def handle_init_key_exchange(msg)
    init_private_key
    
    @prime      = msg["data"]["prime"].to_i(16)
    @generator  = msg["data"]["generator"].to_i(16)

    @session_key = {"hosts" => [client_id], "key" => public_key}
    announce_session_key
  end

  def handle_ping(msg)
    reset_known_hosts
    add_source(msg["source"])
    transmit({"type" => "pong"})
  end

  def handle_pong(msg)
    add_source(msg["source"])
  end

  def handle_public_key(msg)
    # If the key exchange continues far enough that this client receives a key
    # that has already been signed by itself it indicates that some client
    # shared the full completed session key across the network in plaintext.
    if msg["data"]["hosts"].include?(client_id)
      puts "ERROR: Session key compromised."
      return
    end

    # Don't over-write our session key if the message has fewer hosts listed
    return if @session_key && ((msg["data"]["hosts"] & @known_hosts).count < @session_key["hosts"].count)

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

  def add_source(source)
    unless client_id == source || known_hosts.include?(source)
      known_hosts << source
      known_hosts.sort!
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

  def receive(message)
    msg = JSON.parse(message)

    return if msg["destination"] && msg["destination"] != client_id

    puts "#{client_id} Recv:\t #{message}"

    if self.respond_to?("handle_" + msg["type"])
      self.public_send("handle_" + msg["type"], msg)
    end
  end

  def reset_known_hosts
    @known_hosts  = [client_id]
  end

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

3.times do |n|
  clients << Client.new("client#{n}")
end

clients.each do |c|
  c.msg_queue = []
end
clients << Client.new("client3")

processing = true
while processing
  clients.each do |c|
    c.tick
  end

  # Continue processing until all clients are sleeping
  processing = !(clients.inject(true) { |p, c| p && c.sleeping? })
end

puts
clients.each do |c|
  puts c.client_id + ": " + c.known_hosts.join(",")
end

puts
clients.each do |c|
  puts c.client_id + ": " + JSON.generate(c.session_key)
end

