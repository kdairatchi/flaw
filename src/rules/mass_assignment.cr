require "./rule"

module Flaw
  # FLAW015 — Mass assignment. A JSON::Serializable / YAML::Serializable
  # struct exposes admin/role/permission/is_* fields as writable — deserialising
  # untrusted payloads lets the client set them.
  class MassAssignment < Rule
    def id : String
      "FLAW015"
    end

    def title : String
      "Privilege field exposed through Serializable"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def description : String
      <<-DESC
      A struct including `JSON::Serializable` or `YAML::Serializable` has a
      property named `admin`, `role`, `is_*`, `permission`, `scope`, etc.
      `from_json(request.body)` will populate it. Split read/write DTOs or
      mark the field `@[JSON::Field(ignore: true)]` on deserialisation.
      DESC
    end

    # Only `property` makes a field writable under Serializable; `getter`
    # is read-only and safe even on admin-like fields.
    PRIV_FIELD = /\bproperty\s+(is_admin|admin|role|roles|permissions?|scopes?|owner_id|user_id|superuser|staff)\b/

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      return results unless source =~ /include\s+(?:JSON|YAML)::Serializable/
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        if m = line.match(PRIV_FIELD)
          next if line.includes?("ignore: true")
          results << finding(source, path, idx, m.begin(0) || 0,
            "Privilege field '#{m[1]}' is mass-assignable — use a write-only DTO or JSON::Field(ignore: true)")
        end
      end
      results
    end
  end
end
