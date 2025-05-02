require "big"

class Asem
  def initialize
  end

  def powmod(base : Int32, exponent : BigInt, modulus : BigInt)
    result = 1.to_big_i
    base = base.to_big_i

    while exponent > 0
      result = (result * base) % modulus if exponent.odd?
      base = (base * base) % modulus
      exponent >>= 1
    end

    result
  end

  def modInverse(a : BigInt, m : BigInt) : BigInt
    m0 = m
    x0 = 0.to_big_i
    x1 = 1.to_big_i

    return 0.to_big_i if m == 1

    while a > 1
      q = a // m
      m, a = a % m, m
      x0, x1 = x1 - q * x0, x0
    end

    x1 += m0 if x1 < 0
    x1
  end

  def repackStringHexToBytes(input : String) : Slice(UInt8)
    input.hexbytes
  end

  def repackBytesToString(input : Slice(UInt8) | Array(BigInt)) : String
    String.build do |io|
      input.each { |byte| io.write_byte(byte.to_u8) }
    end
  end

  def encrypt(msg : String, key : BigInt, prime : BigInt, pack : Bool = false) : String
    io = IO::Memory.new
    msg.each_byte do |byte|
      enc = (byte.to_big_i * key) % prime
      io.write_bytes(enc.to_u64, IO::ByteFormat::LittleEndian)
    end
    raw = io.to_slice
    pack ? raw.hexstring : String.new(raw)
  end

  def decrypt(msg : String, key : BigInt, prime : BigInt, pack : Bool = false) : String
    encrypted_bytes = pack ? repackStringHexToBytes(msg) : msg.to_slice
    decrypted = Array(BigInt).new

    io = IO::Memory.new(encrypted_bytes)
    while io.pos < io.size
      decrypted << io.read_bytes(UInt64, IO::ByteFormat::LittleEndian).to_big_i
    end

    inverse = modInverse(powmod(2, key, prime), prime)

    decrypted_bytes = decrypted.map { |val| (val * inverse) % prime }

    repackBytesToString(decrypted_bytes)
  end
end

# keypair = {} of String => BigInt


# a = Asem.new()
# # 5563165926023721623:13981220595791735327

# # 9088707104111967125:13981220595791735327

# keypair = 9088707104111967125_i128.to_big_i
# prime   = 13981220595791735327_i128.to_big_i
# keypriv = 5563165926023721623_i128.to_big_i


# msg = "Hello World"

# enc = ""
# dec = ""
# enc = a.encrypt("Hello World", keypair, prime, false)

# puts("Enc: #{enc}")

# dec = a.decrypt(enc, keypriv, prime, false)

# puts("Dec: #{dec}")