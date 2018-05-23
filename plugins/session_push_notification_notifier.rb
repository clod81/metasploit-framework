require 'webpush'
# https://github.com/rapid7/metasploit-framework/pull/8102

module Msf
  class Plugin::SessionPushNotificationNotifier < Msf::Plugin

    include Msf::SessionEvent

    class Exception < ::RuntimeError ; end

    class SessionPushNotificationCommandDispatcher

      include Msf::Ui::Console::CommandDispatcher

      attr_reader :http_port
      attr_reader :minimum_ip
      attr_reader :maximum_ip

      def commands
        {
          'set_session_push_notification_http_port'          => 'Set the HTTP port for the temporary web server used for browser registration to push notifications',
          'set_session_push_notification_minimum_ip'         => 'Set the minimum session IP range you want to be notified for',
          'set_session_push_notification_maximum_ip'         => 'Set the maximum session IP range you want to be notified for',
          'save_session_push_notification_notifier_settings' => 'Save all the session push notification notifier settings to framework',
          'start_session_push_notification_notifier'         => 'Start notifying sessions',
          'stop_session_push_notification_notifier'          => 'Stop notifying sessions',
          'restart_session_push_notification_notifier'       => 'Restart notifying sessions'
        }
      end

      def initialize(driver)
        super(driver)
        load_settings_from_config
      end

      def name
        'SessionPushNotificationNotifier'
      end

      def http_port(*args)
        @http_port = args[0]
      end

      def cmd_set_session_push_notification_http_port(*args)
        port = args[0]
        if port =~ /^\d+$/
          @http_port = args[0]
        else
          print_error('Invalid port setting. Must be a number.')
        end
      end

      def cmd_set_session_push_notification_minimum_ip(*args)
        ip = args[0]
        if ip.blank?
          @minimum_ip = nil
        elsif Rex::Socket.dotted_ip?(ip)
          @minimum_ip = IPAddr.new(ip)
        else
          print_error('Invalid IP format')
        end
      end

      def cmd_set_session_push_notification_maximum_ip(*args)
        ip = args[0]
        if ip.blank?
          @maximum_ip = nil
        elsif Rex::Socket.self.dotted_ip?(ip)
          @maximum_ip = IPAddr.new(ip)
        else
          print_error('Invalid IP format')
        end
      end

      def cmd_save_session_push_notification_notifier_settings(*args)
        save_settings_to_config
        print_status("Session Push Notification Notifier settings saved in config file.")
      end

      def cmd_start_session_push_notification_notifier(*args)
        if is_session_push_notification_notifier_subscribed?
          print_status('You already have an active session push notification notifier.')
          return
        end

        begin
          self.framework.events.add_session_subscriber(self)
          http_port = @http_port || 8888
          # TODO - start server
          print_status("Session notification started.")
        rescue Msf::Plugin::SessionPushNotificationNotifier::Exception
          print_error(e.message)
        end
      end

      def cmd_stop_session_push_notification_notifier(*args)
        self.framework.events.remove_session_subscriber(self)
        print_status("Session notification stopped.")
      end

      def cmd_restart_session_push_notification_notifier(*args)
        cmd_stop_session_push_notification_notifier(args)
        cmd_start_session_push_notification_notifier(args)
      end

      def on_session_open(session)
        subject = "You have a new #{session.type} session!"
        msg = "#{session.tunnel_peer} (#{session.session_host}) #{session.info ? "\"#{session.info.to_s}\"" : nil}"
        notify_session(session, subject, msg)
      end

      private

      def save_settings_to_config
        config_file = Msf::Config.config_file
        ini = Rex::Parser::Ini.new(config_file)
        ini.add_group(name) unless ini[name]
        ini[name]['http_port']         = self.http_port       unless self.http_port.blank?
        ini[name]['minimum_ip']        = self.minimum_ip.to_s unless self.minimum_ip.blank?
        ini[name]['maximum_ip']        = self.maximum_ip.to_s unless self.maximum_ip.blank?
        ini[name]['vapid_public_key']  = @vapid_public_key
        ini[name]['vapid_private_key'] = @vapid_private_key
        ini.to_file(config_file)
      end

      def load_settings_from_config
        config_file = Msf::Config.config_file
        ini = Rex::Parser::Ini.new(config_file)
        group = ini[name]
        if group
          @http_port     = group['http_port']              if group['http_port']
          @minimum_ip    = IPAddr.new(group['minimum_ip']) if group['minimum_ip']
          @maximum_ip    = IPAddr.new(group['maximum_ip']) if group['maximum_ip']
          if group['vapid_private_key'].blank? || group['vapid_public_key'].blank?
            vapid_keys = Webpush.generate_key
            @vapid_public_key  = vapid_key.public_key
            @vapid_private_key = vapid_key.private_key
            save_settings_to_config # generate keys only once - always store them in config
          else
            @vapid_public_key  = group['vapid_public_key']
            @vapid_private_key = group['vapid_private_key']
          end
          print_status('Session Push Notification Notifier settings loaded from config file.')
        end
      end

      def is_session_push_notification_notifier_subscribed?
        subscribers = framework.events.instance_variable_get(:@session_event_subscribers).collect { |s| s.class }
        subscribers.include?(self.class)
      end

      def notify_session(session, subject, msg)
        if is_in_range?(session)
          # TODO
          print_status("Session notified to: #{self.sms_number}")
        end
      end

      def is_in_range?(session)
        # If both blank, it means we're not setting a range.
        return true if self.minimum_ip.blank? && self.maximum_ip.blank?

        ip = IPAddr.new(session.session_host)

        if self.minimum_ip && !self.maximum_ip
          # There is only a minimum IP
          self.minimum_ip < ip
        elsif !self.minimum_ip && self.maximum_ip
          # There is only a max IP
          self.maximum_ip > ip
        else
          # Both ends are set
          range = self.minimum_ip..self.maximum_ip
          range.include?(ip)
        end
      end

    end # end Class

    def name
      'SessionPushNotificationNotifier'
    end

    def initialize(framework, opts)
      super
      add_console_dispatcher(SessionPushNotificationCommandDispatcher)
    end

    def cleanup
      remove_console_dispatcher(name)
    end

    def desc
      'This plugin notifies you a new session via browser push notification. You need to visit the registration page at least once with your device and allow for notifications.'
    end

  end
end
