require "./spec_helper"

describe Flaw::Entropy do
  it "scores crypto-random strings high" do
    Flaw::Entropy.shannon("xk_demo_51H8nJvabcdefghijKLMN0123").should be > 3.5
  end

  it "scores placeholders low" do
    Flaw::Entropy.shannon("changeme").should be < 3.5
  end

  it "handles empty strings" do
    Flaw::Entropy.shannon("").should eq 0.0
  end
end
