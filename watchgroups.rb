#!/usr/bin/env ruby
#Pulls address and service groups from Watchguard

require 'nokogiri'
require 'csv'
require 'colorize'

fwpol = Nokogiri::XML(File.read(ARGV[0]))
@rule_array = []
@host_array = []

def parse_services(fwpol)
  fwpol.xpath('./profile/service-list/service').each do |service|
    services = {}
    services[:name] = service.xpath('name').map(&:text).join("\r")
    services[:desc] = service.xpath('description').map(&:text).join("\r")
      service.xpath('./service-item/member').each do |member|
        services[:proto] = member.xpath('protocol').map(&:text).join("\r")
          if services[:proto] == '6'
            services[:proto] = "TCP"
          elsif services[:proto] == '17'
            services[:proto] = "UDP"
          end
        services[:port]  = member.xpath('server-port').map(&:text).join("\r")

    @rule_array << services.dup
    end
  end
end

def parse_hosts(fwpol)
  fwpol.xpath('./profile/address-group-list/address-group').each do |host|
    hosts = {}
    hosts[:name] = host.xpath('name').map(&:text).join("\r")
    hosts[:desc] = host.xpath('description').map(&:text).join("\r")
      host.xpath('./addr-group-member/member').each do |member|
        hosts[:ip]             = member.xpath('host-ip-addr').map(&:text).join("\r")
        hosts[:network]        = member.xpath('ip-network-addr').map(&:text).join("\r")
        hosts[:netmask]        = member.xpath('ip-mask').map(&:text).join("\r")
        hosts[:start_address]  = member.xpath('start-ip-addr').map(&:text).join("\r")
        hosts[:end_address]    = member.xpath('end-ip-addr').map(&:text).join("\r")

        @host_array << hosts.dup
      end
    end
end


 def create_file
    Dir.mkdir("#{Dir.home}/Documents/Watchguardian/") unless File.exists?("#{Dir.home}/Documents/Watchguardian/")
    @file    = "Watchguardian_groups_#{Time.now.strftime("%d%b%Y_%H%M%S")}"
    @csvfile = File.new("#{Dir.home}/Documents/Watchguardian/#{@file}.csv", 'w+')
    puts "Output written to #{@csvfile.path}".light_blue.bold
  end

def generate
  @rulestring = CSV.generate do |csv|
    csv << ["PORT TO GROUPNAME MAPPINGS"]
    csv << @rule_array.first.keys
    @rule_array.each do |rules|
      csv << rules.values
    end
    csv << ["\n"]
    csv << ["IP TO GROUP MAPPINGS"]
    csv << @host_array.first.keys
    @host_array.each do |hosts|
      csv << hosts.values
    end

  end
end


  # def output_data
  #   CSV.open(@csvfile, 'w+') do |csv|
  #     csv << @scanner.final_array.first.keys
  #       @scanner.final_array.each do |vuln|
  #         csv << vuln.values
  #     end
  #   end

def writefile
  @csvfile.puts(@rulestring)
end


parse_services(fwpol)
parse_hosts(fwpol)
create_file
generate
writefile