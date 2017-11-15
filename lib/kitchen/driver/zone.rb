#
# Copyright 2016, Noah Kantrowitz
# Copyright 2017-2018, Bloomberg Finance L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require 'base64'
require 'openssl'
require 'securerandom'
require 'shellwords'
require 'net/ssh'

module Kitchen
  module Driver
    # Driver plugin for Test-Kitchen to use Solaris Zones.
    class Zone < Kitchen::Driver::Base
      MUTEX_FOR_SSH_KEYS = Mutex.new

      default_config :zone_name do |driver|
        # The zone name identifies the zone to the configuration utility. The following rules apply to zone names:
        #     Each zone must have a unique name.
        #     A zone name is case-sensitive.
        #     A zone name must begin with an alpha-numeric character.
        #     The name can contain alpha-numeric characters, underbars (_), hyphens (-), and periods (.).
        #     The name cannot be longer than 64 characters.
        #     The name global and all names beginning with SUNW are reserved and cannot be used.
        driver.instance.name[0..53] + '-' + SecureRandom.hex(10)
      end

      default_config :zone_port do
        rand(65535 - 1025) + 1025
      end

      default_config :zone_profile_erb, File.join(File.dirname(__FILE__), '../../../templates/profile.xml.erb')
      expand_path_for :zone_profile_erb
      
      default_config :zone_config_erb, File.join(File.dirname(__FILE__), '../../../templates/profile.cfg.erb')
      expand_path_for :zone_config_erb

      default_config :zone_boot_timeout, 30

      default_config :ssh_private_key, File.join(Dir.pwd, '.kitchen', 'id_rsa')
      expand_path_for :ssh_private_key

      default_config :ssh_public_key, File.join(Dir.pwd, '.kitchen', 'id_rsa.pub')
      expand_path_for :ssh_public_key

      def create(state)
        generate_keys
        create_zone_config
        create_zone_profile

        instance.transport.connection(backcompat_merged_state(state)) do |command|
          command.execute("/usr/sbin/zonecfg -z #{state[:zone_name]} -f #{state[:zone_config]}")
          command.execute("/usr/sbin/zoneadm -z #{state[:zone_name]} clone -c #{state[:zone_profile]} template")

          info "Waiting for local zone '#{state[:zone_name]}' to be available..."
          max_retries = config[:zone_boot_timeout] / 5
          command.execute_with_retry("/usr/sbin/zlogin #{state[:zone_name]} ipadm show-addr", [0], 5, max_retries)

          # Set up the NAT.
          command.execute("echo \"rdr net0 0.0.0.0/0 port #{state[:zone_port]} -> #{state[:zone_ip]} port 22\" | /usr/sbin/ipnat -f -")
          # Populate the state information for transport.
          state[:hostname] = config[:transport][:host]
          state[:port] = state[:zone_port]
          state[:username] = 'kitchen'
        end
      end

      def destroy(state)
        if state[:zone_port] && state[:zone_ip]
          remote_command("echo \"rdr net0 0.0.0.0/0 port #{state[:zone_port]} -> #{state[:zone_ip]} port 22\" | /usr/sbin/ipnat -f -")
          state.delete(:zone_port)
          state.delete(:zone_ip)
        end

        if state[:zone_name]
          instance.transport.connection(backcompat_merged_state(state)) do |command|
            command.execute("/usr/sbin/zoneadm -z #{state[:zone_name]} halt")
            command.execute("/usr/sbin/zoneadm -z #{state[:zone_name]} uninstall -F")
            command.execute("/usr/sbin/zonecfg -z #{state[:zone_name]} delete -F")
          end
          state.delete(:zone_name)
        end
      end

      protected

      def generate_keys
        MUTEX_FOR_SSH_KEYS.synchronize do
          if !File.exist?(config[:ssh_public_key]) || !File.exist?(config[:ssh_private_key])
            private_key = OpenSSL::PKey::RSA.new(2048)
            blobbed_key = Base64.encode64(private_key.to_blob).gsub("\n", '')
            public_key = "ssh-rsa #{blobbed_key} test_kitchen"
            File.open(config[:ssh_private_key], 'w') do |file|
              file.write(private_key)
              file.chmod(0600)
            end
            File.open(config[:ssh_public_key], 'w') do |file|
              file.write(public_key)
              file.chmod(0600)
            end
          end
        end        
      end

      def render_file(erbfile)
        template = File.expand_path(erbfile, config[:kitchen_root])
        if File.exist?(template)
          ERB.new(IO.read(template)).result(binding).gsub(%r{^\s*$\n}, "")
        else
          raise ActionFailed, "Could not find Zone template #{template}"
        end
      end

      def debug_file(configfile)
        return unless logger.debug?

        debug("------------")
        IO.read(configfile).each_line { |l| debug("#{l.chomp}") }
        debug("------------")        
      end

      def create_zone_config
        return if state[:zone_config]
        
        state[:zone_config] = File.join(config[:kitchen_root], 'profile.cfg')
        File.open(state[:zone_config], 'wb') { |f| f.write(render_file(state[:zone_config_erb])) }
        debug_file(state[:zone_config])
      end

      def create_zone_profile
        return if state[:zone_profile]
        
        state[:zone_profile] = File.join(config[:kitchen_root], 'profile.xml')
        File.open(state[:zone_profile], 'wb') { |f| f.write(render_file(state[:zone_profile_erb])) }
        debug_file(state[:zone_profile])
      end

    end
  end
end
