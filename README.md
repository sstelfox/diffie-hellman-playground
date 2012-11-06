I suspect my code is technically working at commit 8c75b05, however I'm
encountering a problem of synchronicity. I expect all clients to have received
the "init key exchange" message before receiving any public keys.

The first client that receives the "init key exchange" message, however, will
immediately send it's public key announcement message to it's neighbor next
inline (which has yet to receive the "init key exchange" message), and so and so
on.

This leads to a case where the only client to truly complete the key exchange
will be the first to receive the "init key exchange" message.

I see two things I need to add to get around this problem in my network
simulator, first a message queue, and a process method. Receiving a message
would append it to a client's message queue and then the network would 'tick'
allowing each client to pop a single message out of their queue and process
it.

The next thing that may not be necessary with the just mentioned solution is
threading. This may be easier than implementing the 'tick', but on the other
hand it very well might not...
