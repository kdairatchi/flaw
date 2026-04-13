require "./spec_helper"

describe Flaw::Suppression do
  it "parses same-line directives" do
    s = Flaw::Suppression.parse("foo # flaw:ignore FLAW001\n")
    s.suppressed?("FLAW001", 1).should be_true
    s.suppressed?("FLAW002", 1).should be_false
  end

  it "handles ignore-next" do
    src = "# flaw:ignore-next FLAW002\nbar\n"
    s = Flaw::Suppression.parse(src)
    s.suppressed?("FLAW002", 2).should be_true
  end

  it "handles ignore-file + ALL" do
    s = Flaw::Suppression.parse("# flaw:ignore-file ALL\n")
    s.suppressed?("FLAW999", 42).should be_true
  end
end
