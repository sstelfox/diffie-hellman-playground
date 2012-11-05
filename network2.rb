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
  attr_reader :client_id, :session_id, :private_key

  def initialize
    @client_id = SecureRandom.hex(6).downcase
    @msg_handler = MsgHandler.new(self)
    @private_key = rand(100) + 1
    @session_id = nil

    puts "Initialized: #{@client_id}"

    socket.send(client_id, JSON.generate({"type" => "announce", "data" => client_id}))
  end

  def public_key
    @public_key ||= @generator.mod_exp(@private_key, @prime)
  end

  def receive(message)
    msg = JSON.parse(message)

    return if @session_id && message["session"] != @session_id

    if @msg_handler.respond_to?(msg["type"])
      @msg_handler.send(msg["type"].to_sym, msg["data"])
    end
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
    ["announce"].include?(name)
  end

  def send(*args)
    __send__(*args)
  end

  ##### BEGIN PACKET HANDLERS #####

  def announce(data)
  end

  private

  def puts(output)
    $stdout << output << "\n"
  end
end

clients = []

4.times do 
  clients << Client.new
end

