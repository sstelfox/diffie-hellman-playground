#!/usr/bin/env ruby

require "json"
require "securerandom"

VERSION="0.3"

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
  attr_reader :client_id, :session_key, :tick_count
  attr_accessor :known_hosts, :msg_queue

  def initialize(client_id)
    @client_id    = client_id.to_s
    @session_id   = nil
    @session_key  = nil
    @known_hosts  = [@client_id]
    @tick_count = 0

    # Queue for pending network messages
    @msg_queue    = []

    # Ping allows other clients to become aware of this new client and requests
    # other live clients on the network to update their known host list
    transmit({"type" => "ping"})
    
    @session_id = SecureRandom.hex(4)
    transmit({"type" => "new_session_request", "data" => {"known_hosts" => @known_hosts, "session_id" => @session_id}})
  end

  # Returns true if the client has no pending messages to process
  def sleeping?
    @msg_queue.empty?
  end

  # Process exactly one message
  def tick
    return if sleeping?
    @tick_count += 1
    receive(@msg_queue.shift)
  end

  ##### BEGIN PACKET HANDLERS #####
  
  def handle_new_session_request(msg)
    if msg["data"]["known_hosts"].include?(client_id)
      @session_key = {"hosts" => [client_id]}
      @session_id = msg["data"]["session_id"]

      announce_session_key
    else
      @session_id = SecureRandom.hex(4)
      transmit({"type" => "new_session_request", "data" => {"known_hosts" => @known_hosts, "session_id" => @session_id}})
    end
  end

  def handle_ping(msg)
    add_source(msg["source"])
    transmit({"type" => "pong"})
  end

  def handle_pong(msg)
    add_source(msg["source"])
  end

  def handle_public_key(msg)
    return unless msg["data"]["session_id"] == @session_id
    
    # If the key exchange continues far enough that this client receives a key
    # that has already been signed by itself it indicates that some client
    # shared the full completed session key across the network in plaintext.
    if msg["data"]["hosts"].include?(client_id)
      log("ERROR: Session key compromised.", msg)
      return
    end
    
    # Don't over-write our session key if the message has fewer hosts listed
    return if @session_key && ((msg["data"]["hosts"] & @known_hosts).count < @session_key["hosts"].count)

    @session_key = {
      "hosts" => (msg["data"]["hosts"] + [client_id]).sort
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

  def announce_session_key
    transmit_to_next_host({
      "type" => "public_key",
      "data" => {
        "session_id" => @session_id,
        "hosts" => @session_key["hosts"]
      }
    })
  end

  def log(message, data = nil)
    puts "#{client_id} Log:\t#{message} #{JSON.generate(data) unless data.nil?}".strip
  end

  ##### BEGIN "NETWORK" RELATED FUNCTIONS #####

  def transmit(data)
    data["source"] = client_id
    data["tick"] = tick_count

    message = JSON.generate(data)

    puts "#{client_id} Sent:\t#{message}"
    socket.transmit(client_id, message)
  end
  
  def transmit_to_next_host(data)
    # Find this client's position in the list
    my_position = known_hosts.index(client_id)

    # Increment our position by 1 and wrap around to the first host if we go
    # beyond the number of known hosts
    next_position = (my_position + 1) % known_hosts.count
    
    # No point in continuing if I'm going to be sending to myself
    if my_position == next_position
      log("Refusing to send to myself", data)
      return
    end

    # Set our destination and transmit as normal
    data["destination"] = known_hosts[next_position]
    transmit(data)
  end

  def receive(message)
    msg = JSON.parse(message)

    return if msg["destination"] && msg["destination"] != client_id

    puts "#{client_id} Recv:\t#{message}"

    if self.respond_to?("handle_" + msg["type"])
      self.public_send("handle_" + msg["type"], msg)
    end
  end

  def socket
    return @socket unless @socket.nil?

    @socket = Network.instance
    @socket.register_client(self)
    @socket
  end
  
  ##### END "NETWORK" RELATED FUNCTIONS #####
end

clients = []

4.times do |n|
  clients << Client.new(n)

  processing = true
  while processing
    clients.each do |c|
      c.tick
    end

    # Continue processing until all clients are sleeping
    processing = !(clients.inject(true) { |p, c| p && c.sleeping? })
  end
end

puts
clients.each do |c|
  puts c.client_id + ": " + c.known_hosts.join(",")
end

puts
clients.each do |c|
  puts c.client_id + ": " + JSON.generate(c.session_key)
end

