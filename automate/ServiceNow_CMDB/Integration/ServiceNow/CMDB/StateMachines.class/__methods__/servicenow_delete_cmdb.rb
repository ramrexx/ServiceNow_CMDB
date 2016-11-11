=begin
 servicenow_delete_cmdb.rb

 Author: Kevin Morey <kevin@redhat.com>

 Description: This method deletes a ServiceNow CMDB Record via REST API
-------------------------------------------------------------------------------
   Copyright 2016 Kevin Morey <kevin@redhat.com>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
-------------------------------------------------------------------------------
=end
def log(level, msg, update_message = false)
  $evm.log(level, "#{msg}")
  @task.message = msg if @task && (update_message || level == 'error')
end

def call_servicenow(action, tablename='cmdb_ci_server', sysid=nil, body=nil)
  require 'rest_client'
  require 'json'
  require 'base64'

  servername = nil || $evm.object['servername']
  username = nil   || $evm.object['username']
  password = nil   || $evm.object.decrypt('password')
  url = "https://#{servername}/api/now/table/#{tablename}/#{sysid}"

  params = {
    :method=>action, :url=>url,
    :headers=>{
      :content_type=>:json, :accept=>:json,
      :authorization => "Basic #{Base64.strict_encode64("#{username}:#{password}")}"
    }
  }
  params[:payload] = body.to_json if body
  log(:info, "Calling url: #{url} action: #{action} payload: #{params}")

  RestClient.proxy = $evm.object['proxy_url'] unless $evm.object['proxy_url'].nil?

  snow_response = RestClient::Request.new(params).execute
  log(:info, "response headers: #{snow_response.headers}")
  log(:info, "response code: #{snow_response.code}")
  log(:info, "response: #{snow_response}")
  return snow_response
end

def get_tablename
  os = get_operatingsystem.downcase
  log(:info, "os: #{os}")
  if os.include?('windows')
    table_name    = 'cmdb_ci_win_server'
  elsif os.include?('linux') || os.include?('unknown')
    table_name    = 'cmdb_ci_linux_server'
  elsif os.include?('rhel')
    table_name    = 'cmdb_ci_linux_server'
  else
    table_name    = 'cmdb_ci_server'
  end
  return table_name
end

def get_serialnumber
  serial_number = nil
  case @object.vendor
  when 'vmware'
    # converts vmware bios (i.e. "4231c89f-0b98-41c8-3f92-a11576c13db5") to a proper serial number
    # "VMware-42 31 c8 9f 0b 98 41 c8-3f 92 a1 15 76 c1 3d b5"
    bios = (@object.hardware.bios rescue nil)
    return nil if bios.nil?
    bios1 = bios[0, 18].gsub(/-/, '').scan(/\w\w/).join(" ")
    bios2 = bios[19, bios.length].gsub(/-/, '').scan(/\w\w/).join(" ")
    serial_number = "VMware-#{bios1}-#{bios2}"
    log(:info, "converted bios: #{bios} to serial_number: #{serial_number}")
  end
  return serial_number
end

def get_operatingsystem
  @object.try(:operating_system).try(:product_name) ||
    @object.try(:hardware).try(:guest_os_full_name) ||
    @object.try(:hardware).try(:guest_os) || 'unknown'
end

def get_hostname
  hostname = @object.hostnames.first rescue nil
  hostname.blank? ? (return @object.name) : (return hostname)
end

def get_diskspace
  diskspace = @object.allocated_disk_storage
  return nil if diskspace.nil?
  return diskspace / 1024**3
end

def get_ipaddress
  ip = @object.ipaddresses.first
  ip.blank? ? (return @object.hardware.ipaddresses.first || nil) : (return ip)
end

def get_comments
  comments = "Updated: #{Time.now.utc.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
  comments +=  "Vendor: #{@object.vendor}\n"
  comments += "CloudForms: #{$evm.root['miq_server'].name}\n"
  comments += "Tags: #{@object.tags.inspect}\n"
end

def build_payload
  body_hash = {
    :virtual            => true,
    :name               => @object.name,
    :cpu_count          => @object.num_cpu,
    :ram                => @object.mem_cpu,
    :host_name          => get_hostname,
    :serial_number      => get_serialnumber,
    :os                 => get_operatingsystem,
    :os_version         => get_operatingsystem,
    :disk_space         => get_diskspace,
    :ip_address         => get_ipaddress,
    :cpu_core_count     => (@object.hardware.cpu_total_cores rescue nil),
    :vendor             => @object.vendor
  }
  log(:info, "pre compact body_hash: #{body_hash}")
  # ServiceNow does not like nil values using compact to remove them
  return body_hash.compact
end


begin
  $evm.root.attributes.sort.each { |k, v| log(:info, "Root:<$evm.root> Attribute - #{k}: #{v}")}

  case $evm.root['vmdb_object_type']
  when 'vm', 'miq_provision'
    @task   = $evm.root['miq_provision']
    @object = @task.try(:destination) || $evm.root['vm']
  when 'automation_task'
    @task   = $evm.root['automation_task']
    @object = $evm.vmdb(:vm).find_by_name($evm.root['vm_name']) ||
      $evm.vmdb(:vm).find_by_id($evm.root['vm_id'])
  end

  exit MIQ_STOP unless @object

  servicenow_cmdb_table = @object.custom_get(:servicenow_cmdb_table)
  log(:info, "Found custom attribute {:servicenow_cmdb_table=>#{servicenow_cmdb_table}} from #{@object.name}") if servicenow_cmdb_table
  servicenow_cmdb_sysid = @object.custom_get(:servicenow_cmdb_sysid)
  log(:info, "Found custom attribute {:servicenow_cmdb_sysid=>#{servicenow_cmdb_sysid}} from #{@object.name}") if servicenow_cmdb_sysid

  raise "missing servicenow_cmdb_sysid" if servicenow_cmdb_sysid.nil?

  # call servicenow
  servicenow_result = call_servicenow(:delete, get_tablename, servicenow_cmdb_sysid)

  log(:info, "servicenow_result: #{servicenow_result.inspect}")

  log(:info, "Removning custom attribute :servicenow_cmdb_table")
  @object.custom_set(:servicenow_cmdb_table, nil)
  log(:info, "Removning custom attribute :servicenow_cmdb_sysid")
  @object.custom_set(:servicenow_cmdb_sysid, nil)

rescue => err
  log(:error, "[#{err}]\n#{err.backtrace.join("\n")}")
  exit MIQ_STOP
end
