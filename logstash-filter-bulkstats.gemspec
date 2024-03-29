Gem::Specification.new do |s|
  s.name = 'logstash-filter-bulkstats'
  s.version         = '1.0.5'
  s.licenses = ['Apache License (2.0)']
  s.summary = "This bulkstats filter get a message from bulkstats cisco machine and parse it"
  s.description     = "we can do this later"
  s.authors = ["Elastic"]
  s.email = 'systems@redborder.com'
  s.homepage = "https://www.redborder.com"
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_development_dependency 'logstash-devutils'
end
