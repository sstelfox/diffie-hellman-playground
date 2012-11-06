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
  attr_reader :client_id, :session_key
  attr_accessor :known_hosts, :msg_queue

  def initialize
    @client_id    = SecureRandom.hex(6).downcase
    @session_key  = nil
    @known_hosts  = [@client_id]

    # Queue for pending network messages
    @msg_queue    = []

    # Ping allows other clients to become aware of this new client and requests
    # other live clients on the network to update their known host list
    transmit({"type" => "ping"})
  end

  # Returns true if the client has no pending messages to process
  def sleeping?
    @msg_queue.empty?
  end

  # Process exactly one message
  def tick
    return if sleeping?
    receive(@msg_queue.shift)
  end

  ##### BEGIN PACKET HANDLERS #####

  def handle_ping(msg)
    add_source(msg["source"])
    transmit({"type" => "pong"})
  end

  def handle_pong(msg)
    add_source(msg["source"])
  end

  ##### END PACKET HANDLERS #####

  private

  def add_source(source)
    unless client_id == source || known_hosts.include?(source)
      known_hosts << source
      known_hosts.sort!
    end
  end

  def log(message, data = nil)
    puts "#{client_id} Log:\t#{message} #{JSON.generate(data) unless data.nil?}".strip
  end

  def transmit(data)
    data["source"] = client_id

    message = JSON.generate(data)

    puts "#{client_id} Sent:\t#{message}"
    socket.transmit(client_id, message)
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
end

clients = []

4.times do |n|
  clients << Client.new

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

