require "compress/zip"

def extract(archive : String, dest : String)
  Compress::Zip::File.open(archive) do |zip|
    zip.entries.each do |entry|
      File.open(File.join(dest, entry.filename), "w") do |f|
        IO.copy(entry.open, f)
      end
    end
  end
end
