require "./spec_helper"

describe Flaw::Baseline do
  it "roundtrips findings through save/load/filter" do
    finding = Flaw::Finding.new("FLAW001", Flaw::Severity::High, "t", "m", "f.cr", 1, 0, "snip")
    tmp = File.tempname("flaw-bl", ".json")
    begin
      Flaw::Baseline.save([finding], tmp)
      bl = Flaw::Baseline.load(tmp)
      Flaw::Baseline.filter([finding], bl).should be_empty
    ensure
      File.delete(tmp) if File.exists?(tmp)
    end
  end
end
