# Force the SWD (Simple Web Discovery) gem to use plain HTTP for discovery
# endpoints. By default it hardcodes URI::HTTPS, which causes SSL errors when
# Keycloak runs behind a reverse proxy on plain HTTP (the container-to-container
# path is never TLS). This is the standard fix for non-TLS environments.
require 'swd'
SWD.url_builder = URI::HTTP

# Seek::Config lives in lib/, which SEEK >= 1.18 autoloads with Zeitwerk, so it
# cannot be referenced while initializers run. Patch it as soon as it loads,
# which is before seek_omniauth.rb's middleware block reads the providers.
Rails.autoloaders.main.on_load('Seek::Config') do |config|
  class << config
    alias_method :original_omniauth_providers, :omniauth_providers
    def omniauth_providers
      providers = original_omniauth_providers

      # Public URL — used by the browser for the authorization redirect and as
      # the `issuer` claim (must match what Keycloak puts into tokens).
      issuer = ENV['KEYCLOAK_PUBLIC_URL'] + '/realms/digitaltwins'

      # Internal URL — used by the SEEK container for server-side calls (token
      # exchange, userinfo, JWKS). Goes container-to-container over the Docker
      # network so it never hits the gateway or needs TLS. This mirrors the
      # pattern used by Airflow and JupyterHub in the same platform.
      internal_base = ENV.fetch('KEYCLOAK_INTERNAL_URL', ENV['KEYCLOAK_PUBLIC_URL'])
      internal_uri = URI(internal_base)

      # Remove the default :oidc provider if it was added by Seek::Config
      providers.reject! { |p| p[1][:name] == :oidc }

      # We add :oidc directly with discovery disabled to avoid OIDC discovery
      # issues in local dev. client_options.scheme/host/port set the base URL
      # for server-side HTTP calls (token, userinfo, JWKS).
      # authorization_endpoint uses the public URL so the browser redirect works.
      providers << [:openid_connect, {
        name: :oidc,
        issuer: issuer,
        discovery: false,
        response_type: 'code',
        scope: [:openid, :email, :profile],
        client_options: {
          identifier: 'seek',
          secret: ENV['SEEK_KEYCLOAK_CLIENT_SECRET'],
          redirect_uri: "#{ENV['PLATFORM_PROTOCOL']}://#{ENV['PLATFORM_DOMAIN']}/seek/auth/oidc/callback",
          scheme: internal_uri.scheme,
          host: internal_uri.host,
          port: internal_uri.port,
          authorization_endpoint: "#{ENV['KEYCLOAK_PUBLIC_URL']}/realms/digitaltwins/protocol/openid-connect/auth",
          token_endpoint: '/auth/realms/digitaltwins/protocol/openid-connect/token',
          userinfo_endpoint: '/auth/realms/digitaltwins/protocol/openid-connect/userinfo',
          jwks_uri: '/auth/realms/digitaltwins/protocol/openid-connect/certs'
        }
      }]

      providers
    end
  end
end

# Monkey-patch SEEK's SessionsController to support Keycloak Single Logout (SLO).
# By default, SEEK only destroys the local session. This patch ensures that logging
# out of SEEK also logs the user out of Keycloak (the platform).
Rails.application.config.to_prepare do
  SessionsController.class_eval do
    # Override the destroy action
    def destroy
      logout_user
      flash[:notice] = 'You have been logged out.'
      
      # Build the Keycloak logout URL with a redirect back to SEEK
      keycloak_url = ENV['KEYCLOAK_PUBLIC_URL'] || 'http://localhost/auth'
      seek_url = "#{ENV['PLATFORM_PROTOCOL'] || 'http'}://#{ENV['PLATFORM_DOMAIN'] || 'localhost'}/seek"
      logout_url = "#{keycloak_url}/realms/digitaltwins/protocol/openid-connect/logout"
      logout_url += "?client_id=seek&post_logout_redirect_uri=#{CGI.escape(seek_url)}"
      
      redirect_to logout_url
    end

    # First /seek login for a Keycloak user SEEK has not seen: provision the
    # account exactly as the API token path does (keycloak_jwt_auth.rb), so the
    # user lands logged in instead of on SEEK's "create a profile" form.
    # Only reached when Seek::Config.omniauth_user_create is on.
    private def create_user_from_omniauth(auth)
      @user = KeycloakJwtAuth.provision_user(
        sub: auth.uid, email: auth.info.email, first_name: auth.info.first_name,
        last_name: auth.info.last_name, username: auth.info.nickname)
      if @user
        check_login
      else
        failed_login "No #{Seek::Config.instance_name} account could be created for #{auth.info.email}; please contact an administrator."
      end
    end
  end
end
