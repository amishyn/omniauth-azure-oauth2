require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class AzureOauth2 < OmniAuth::Strategies::OAuth2
      BASE_AZURE_URL = 'https://login.microsoftonline.com'

      option :name, 'azure_oauth2'

      option :tenant_provider, nil

      # AD resource identifier
      option :resource, '00000002-0000-0000-c000-000000000000'

      # tenant_provider must return client_id, client_secret and optionally tenant_id and base_azure_url
      args [:tenant_provider]

      def client
        if options.tenant_provider
          provider = options.tenant_provider.new(self)
        else
          provider = options  # if pass has to config, get mapped right on to options
        end

        options.client_id = provider.client_id
        options.client_secret = provider.client_secret
        options.tenant_id =
          provider.respond_to?(:tenant_id) ? provider.tenant_id : 'common'
        options.base_azure_url =
          provider.respond_to?(:base_azure_url) ? provider.base_azure_url : BASE_AZURE_URL
        options.authorize_params.domain_hint = provider.domain_hint if provider.respond_to?(:domain_hint) && provider.domain_hint
        options.authorize_params.prompt = request.params['prompt'] if request.params['prompt']
        options.client_options.authorize_url = "#{options.base_azure_url}/#{options.tenant_id}/oauth2/v2.0/authorize"
        options.client_options.token_url = "#{options.base_azure_url}/#{options.tenant_id}/oauth2/v2.0/token"
        options.authorize_params.scope = 'openid email profile offline_access https://outlook.office.com/User.Read https://outlook.office.com/Calendars.ReadWrite'
        super
      end

      uid {
        raw_info['Id']
      }

      info do
        {
          name: raw_info['DisplayName'],
          email: raw_info['EmailAddress']
        }
      end

      def callback_url
        full_host + script_name + callback_path
      end

      def raw_info
        @raw_info ||= access_token.get('https://outlook.office.com/api/v2.0/me').parsed
      end

    end
  end
end
