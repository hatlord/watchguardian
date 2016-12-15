#!/usr/bin/env ruby
#Parses Watchguard x series XML to CSV

require 'nokogiri'
require 'csv'
require 'colorize'

fwpol = Nokogiri::XML(File.read(ARGV[0]))
@rule_array = []

def parse(fwpol)
  fwpol.xpath('./profile/policy-list/policy').each do |pol|
    rules = {}
    rules[:name]     = pol.xpath('name').text
    rules[:property] = pol.xpath('property').text
    rules[:service]  = pol.xpath('service').text
    rules[:firewall] = pol.xpath('firewall').text
    rules[:src]      = pol.xpath('source').text
    rules[:dest]     = pol.xpath('destination ').text
    rules[:inif]     = pol.xpath('in-if').text
    rules[:outif]    = pol.xpath('out-if').text
    rules[:enable]   = pol.xpath('enable').text
    rules[:log]      = pol.xpath('log').text
    rules[:desc]      = pol.xpath('description').text
    
    @rule_array << rules.dup

  end
end

 def create_file
    Dir.mkdir("#{Dir.home}/Documents/Watchguardian/") unless File.exists?("#{Dir.home}/Documents/Watchguardian/")
    @file    = "Watchguardian_#{Time.now.strftime("%d%b%Y_%H%M%S")}"
    @csvfile = File.new("#{Dir.home}/Documents/Watchguardian/#{@file}.csv", 'w+')
    puts "Output written to #{@csvfile.path}".light_blue.bold
  end

def generate
  @rulestring = CSV.generate do |csv|
    csv << ['Name', 'src', 'dest', 'Service', 'In Interface', 'Out Interface', 'Enabled', 'Log', 'Firewall', 'Property', 'Description']
    puts @rulestring
      @rule_array.each { |row| csv << [row[:name], row[:src], row[:dest], row[:service], row[:inif], row[:outif], row[:enable], row[:log], row[:firewall], row[:property], row[:desc]] }
  end
end

def writefile
  @csvfile.puts(@rulestring)
end


parse(fwpol)
create_file
generate
writefile