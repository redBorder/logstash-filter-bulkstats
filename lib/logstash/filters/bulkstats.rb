# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "json" 
require "time"
require 'rubygems/package'
require 'zlib'
require 'fileutils'

# This bulkstats filter will map the data coming with keys
# defined in a directory in a certains way.
#
# It is only intended to be used on a redBorder platform.
class LogStash::Filters::Bulkstats < LogStash::Filters::Base

  config_name "bulkstats"
  config :bulkstats_columns_tar_gz, :validate => :string, :default => "/opt/rb/share/bulkstats.tar.gz", :required => false

  public
  def build_columns_from_dir(destination)
    bulkstats_columns = {}
    Dir["#{destination}/*"].each do |file|
      bulkstats_columns[file.split("/").last] = JSON.load(File.read(file))
    end
    FileUtils.rm_rf(destination)
    bulkstats_columns
  end
  def extract_bulkstats_tar_gz(destination, tar_gz_archive)   
    tar_longlink = '././@LongLink'
    FileUtils.rm_rf(destination)
    FileUtils.mkdir_p(destination)
    Gem::Package::TarReader.new( Zlib::GzipReader.open tar_gz_archive ) do |tar|
    dest = nil
    tar.each do |entry|
      if entry.full_name == tar_longlink
        dest = File.join destination, entry.read.strip
        next
      end
      dest ||= File.join destination, entry.full_name
      if entry.directory?
        File.delete dest if File.file? dest
        FileUtils.mkdir_p dest, :mode => entry.header.mode, :verbose => false
      elsif entry.file?
        FileUtils.rm_rf dest if File.directory? dest
        File.open dest, "wb" do |f|
          f.print entry.read
        end
        FileUtils.chmod entry.header.mode, dest, :verbose => false
      elsif entry.header.typeflag == '2' #Symlink!
        File.symlink entry.header.linkname, dest
      end
      dest = nil
    end
    end
  end

  def get_bulkstats_columns
      return {} if !File.exist?("#{@bulkstats_columns_tar_gz}")
      destination = "/tmp/bulkstats-#{Time.now.to_i}"
      extract_bulkstats_tar_gz(destination, @bulkstats_columns_tar_gz)
      build_columns_from_dir(destination)
  end

  def register
    # Add instance variables
    @bulkstats_columns = get_bulkstats_columns
  end # def register

  def get_key(schema_id,ref_id,index)
    if @bulkstats_columns && @bulkstats_columns[schema_id] && @bulkstats_columns[schema_id][ref_id] && @bulkstats_columns[schema_id][ref_id][index]
      "bulkstats_" + @bulkstats_columns[schema_id][ref_id][index].to_s.downcase
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
      key = get_key(schema_id,ref_id,index)
      if (key)
        e = LogStash::Event.new("timestamp" => timestamp.to_i,
                                "monitor" => key,
                                "value" => value,
                                "type" => "bulkstats",
                                "sensor_uuid" => [path[-3][0..7], path[-3][8..11],path[-3][12..15],path[-3][16..19],path[-3][20..-1]].join("-"),
                                "bulkstats" => value
                               )
       yield e
      end
    end

    @logger.debug? && @logger.debug("Message is now: #{event.get("message")}")
    # filter_matched should go in the last line of our successful code
    event.cancel
    #filter_matched(event)
  end # def filter
end # class LogStash::Filters::Bulkstats
