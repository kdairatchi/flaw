require "./spec_helper"

describe Flaw::SourcePrep do
  it "masks heredoc bodies while preserving line count" do
    src = "x = <<-SQL\nSELECT * FROM u WHERE id = \#{id}\nSQL\n"
    out = Flaw::SourcePrep.mask_heredocs(src)
    out.lines.size.should eq src.lines.size
    out.should_not contain("SELECT * FROM u")
  end
end
