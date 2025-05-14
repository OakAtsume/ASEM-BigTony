require("openssl")
require("json")
require("readline")

class ASM
  def initialize()
    @keysize = 64 # Bits
    @keypair = {
      public: nil,
      private: nil,
    }
  end

  def generate()
    prime = OpenSSL::BN.generate_prime(@keysize).to_i
    privateKey = OpenSSL::BN.pseudo_rand_range(2 ** @keysize)
    publicKey = OpenSSL::BN.new(2).mod_exp(privateKey, OpenSSL::BN.new(prime)).to_i
    @keypair = {
      public: "#{publicKey}:#{prime}",
      private: "#{privateKey}:#{prime}",
    }
    return @keypair
  end

  def encrypt(msg, publicKey, pack: true)
    key, prime = publicKey.split(":").map(&:to_i)
    bytes = msg.bytes # Turn message into array of bytes
    encrypted = []
    bytes.each do |byte|
      encrypted.push(
        (byte * key) % prime
      )
    end
    packed = encrypted.pack("Q*").force_encoding("UTF-8")
    packed = packed.unpack1("H*") if pack
    return packed
  end

  def decrypt(msg, privateKey, pack: false)
    key, prime = privateKey.split(":").map(&:to_i)
    if pack
      packed = [msg].pack("H*")
      packed = packed.unpack("Q*")
    else
      packed = msg.unpack("Q*")
    end

    decrypted = []
    invert = modInverse(
      OpenSSL::BN.new(2).mod_exp(
        key,
        OpenSSL::BN.new(prime)
      ).to_i,
      prime
    )

    packed.each do |byte|
      decrypted.push(
        (byte * invert[0]) % prime
      )
    end
    decrypted.pack("C*")
  end

  def modInverse(a, b)
    # trivial case first: gcd(a, 0) == 1*a + 0*0
    return 1, 0 if b == 0

    # recurse: a = q*b + r
    q, r = a.divmod b
    s, t = modInverse(b, r)

    # compute and return coefficients:
    # gcd(a, b) == gcd(b, r) == s*b + t*r == s*b + t*(a - q*b)
    return t, s - q * t
  end
end