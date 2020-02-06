# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "json" 
require "time"

# This bulkstats filter will map the data coming with keys
# defined in a directory in a certains way.
#
# It is only intended to be used on a redBorder platform.
class LogStash::Filters::Bulkstats < LogStash::Filters::Base

  config_name "bulkstats"
  config :directory, :validate => :string, :default => "/opt/rb/share/bulkstats", :required => true

  public
  def build_columns_from_dir(dir="/opt/rb/share/bulkstats")
    bulkstats_columns = {}
    Dir["#{dir}/*"].each do |file|
      bulkstats_columns[file.split("/").last] = JSON.load(File.read(file))
    end
    bulkstats_columns
  end

  def register
    # Add instance variables
    @bulkstats_columns = build_columns_from_dir(@directory)
  end # def register

  def get_key(schema_id,ref_id,index)
    if @bulkstats_columns && @bulkstats_columns[schema_id] && @bulkstats_columns[schema_id][ref_id] && @bulkstats_columns[schema_id][ref_id][index]
      "bulkstats_" + @bulkstats_columns[schema_id][ref_id][index].to_s
    else
      nil
    end
  end

  def filter(event)
    message           = (event.get("message") || "").split(",")
    timestamp         = event.get("@timestamp") || Time.now
    path              = (event.get("path") || "").split("/")
    schema_id         = path[-2]
    ref_id            = message[1]

    message.each_with_index do |value, index|
      e = LogStash::Event.new("timestamp" => timestamp.to_i,
                              "monitor" => get_key(schema_id,ref_id,index),
                              "value" => value,
                              "type" => "bulkstats",
                              "sensor_uuid" => path[-3]
                             )
     yield e
    end

    @logger.debug? && @logger.debug("Message is now: #{event.get("message")}")
    # filter_matched should go in the last line of our successful code
    event.cancel
    #filter_matched(event)
  end # def filter
end # class LogStash::Filters::Bulkstats
