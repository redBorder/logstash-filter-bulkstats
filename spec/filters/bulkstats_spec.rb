# encoding: utf-8
require 'spec_helper'
require "logstash/filters/bulkstats"

describe LogStash::Filters::Bulkstats do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        bulkstats {
          directory => "/opt/rb/share/bulkstats"
        }
      }
    CONFIG
    end

    sample("directory" => "/opt/rb/share/bulkstats") do
      expect(subject.get("directory")).to eq('/opt/rb/share/bulkstats')
    end
  end
end
