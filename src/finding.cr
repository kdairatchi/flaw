require "json"

module Flaw
  enum Severity
    Info
    Low
    Medium
    High
    Critical

    def self.parse?(s : String) : Severity?
      case s.downcase
      when "info"     then Info
      when "low"      then Low
      when "medium"   then Medium
      when "high"     then High
      when "critical" then Critical
      end
    end

    def label : String
      to_s.downcase
    end
  end

  struct Finding
    include JSON::Serializable

    getter rule_id : String
    getter severity : Severity
    getter title : String
    getter message : String
    getter file : String
    getter line : Int32
    getter column : Int32
    getter snippet : String

    def initialize(@rule_id, @severity, @title, @message, @file, @line, @column, @snippet)
    end
  end
end
