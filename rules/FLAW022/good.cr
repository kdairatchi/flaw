require "compress/zip"

def extract(archive : String, dest : String)
  root = File.expand_path(dest)
  Compress::Zip::File.open(archive) do |zip|
    zip.entries.each do |entry|
      target = File.expand_path(File.join(root, entry.filename))
      next unless target.starts_with?(root + File::SEPARATOR)
      File.open(target, "w") { |f| IO.copy(entry.open, f) }
    end
  end
end
