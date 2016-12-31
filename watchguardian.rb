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
    rules[:name]     = pol.xpath('name').map(&:text).join("\r")
    rules[:property] = pol.xpath('property').map(&:text).join("\r")
    rules[:service]  = pol.xpath('service').map(&:text).join("\r")
    rules[:firewall] = pol.xpath('firewall').map(&:text).join("\r")
    rules[:src]      = pol.xpath('source').map(&:text).join("\r")
    rules[:dest]     = pol.xpath('destination ').map(&:text).join("\r")
    rules[:inif]     = pol.xpath('in-if').map(&:text).join("\r")
    rules[:outif]    = pol.xpath('out-if').map(&:text).join("\r")
    rules[:enable]   = pol.xpath('enable').map(&:text).join("\r")
    rules[:log]      = pol.xpath('log').map(&:text).join("\r")
    rules[:desc]     = pol.xpath('description').map(&:text).join("\r")

      if rules[:firewall] == '2'
        rules[:action] = 'DROP'
      elsif rules[:firewall] == '4'
        rules[:action] = 'PROXY?' #Not convinced 100% that 4 == proxy. This will have to do for now
      else
        rules[:action] = 'ALLOW'
      end
    
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
    csv << ['Name', 'src', 'dest', 'Service', 'In Interface', 'Out Interface', 'Action', 'Enabled', 'Log', 'Firewall', 'Property', 'Description']
    puts @rulestring
      @rule_array.each { |row| csv << [row[:name], row[:src], row[:dest], row[:service], row[:inif], row[:outif], row[:action], row[:enable], row[:log], row[:firewall], row[:property], row[:desc]] }
  end
end

def writefile
  @csvfile.puts(@rulestring)
end


parse(fwpol)
create_file
generate
writefile