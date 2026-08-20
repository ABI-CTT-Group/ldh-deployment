# Keycloak JWT Bearer-token authentication for SEEK API requests.
#
# This initializer monkey-patches AuthenticatedSystem so that SEEK's
# `current_user` chain can authenticate API callers who present a
# Keycloak-issued JWT in the `Authorization: Bearer <token>` header.
#
# How it works:
#   1. Extracts the Bearer token from the Authorization header.
#   2. Fetches (and caches) the Keycloak realm's JWKS public keys.
#   3. Decodes and verifies the JWT (RS256) using the `jwt` gem.
#   4. Looks up the SEEK User via the `identities` table
#      (provider: 'oidc', uid: token['sub']).
#   5. Returns the User if found, or nil (falls through to the next
#      auth method in the chain).
#
# Mounted as a read-only volume in docker-compose.yml:
#   ./keycloak_jwt_auth.rb:/seek/config/initializers/keycloak_jwt_auth.rb:ro

require 'jwt'
require 'net/http'
require 'json'

module KeycloakJwtAuth
  KEYCLOAK_INTERNAL_URL = ENV.fetch('KEYCLOAK_INTERNAL_URL', ENV.fetch('KEYCLOAK_PUBLIC_URL', 'http://keycloak:8080/auth'))
  JWKS_URI = "#{KEYCLOAK_INTERNAL_URL}/realms/digitaltwins/protocol/openid-connect/certs"

  # Public issuer must match the `iss` claim in the token (browser-facing URL).
  EXPECTED_ISSUER = "#{ENV.fetch('KEYCLOAK_PUBLIC_URL', 'http://localhost/auth')}/realms/digitaltwins"

  @jwks_keys = nil
  @jwks_last_fetched = nil
  JWKS_CACHE_TTL = 300 # seconds

  class << self
    def jwks_keys(force_refresh: false)
      if force_refresh || @jwks_keys.nil? || @jwks_last_fetched.nil? || (Time.now - @jwks_last_fetched) > JWKS_CACHE_TTL
        uri = URI(JWKS_URI)
        response = Net::HTTP.get_response(uri)
        if response.is_a?(Net::HTTPSuccess)
          jwks_raw = JSON.parse(response.body)
          # jwt gem v2.5.0 expects the raw hash directly for the jwks parameter
          @jwks_keys = jwks_raw.deep_symbolize_keys
          @jwks_last_fetched = Time.now
        else
          Rails.logger.warn "[keycloak_jwt_auth] Failed to fetch JWKS from #{JWKS_URI}: #{response.code}"
          # Return stale keys if available, otherwise empty
          @jwks_keys ||= { keys: [] }
        end
      end
      @jwks_keys
    end

    def decode_token(token)
      # First attempt with cached keys
      begin
        decoded = JWT.decode(token, nil, true, {
          algorithms: ['RS256'],
          iss: EXPECTED_ISSUER,
          verify_iss: true,
          jwks: jwks_keys
        })
        return decoded.first # the payload hash
      rescue JWT::DecodeError => e
        # Key may have rotated — retry with fresh keys
        Rails.logger.info "[keycloak_jwt_auth] First decode failed (#{e.message}), refreshing JWKS..."
      end

      # Second attempt with refreshed keys
      begin
        decoded = JWT.decode(token, nil, true, {
          algorithms: ['RS256'],
          iss: EXPECTED_ISSUER,
          verify_iss: true,
          jwks: jwks_keys(force_refresh: true)
        })
        return decoded.first
      rescue JWT::DecodeError => e
        Rails.logger.warn "[keycloak_jwt_auth] JWT decode failed after JWKS refresh: #{e.message}"
        return nil
      end
    end
  end
end

# Monkey-patch AuthenticatedSystem to insert Keycloak JWT auth
# at the front of the current_user chain.
Rails.application.config.to_prepare do
  AuthenticatedSystem.module_eval do
    private

    # Look up a SEEK User from a Keycloak JWT Bearer token.
    def user_from_keycloak_jwt
      auth_header = request.headers['Authorization']
      return nil unless auth_header.present?

      # Only handle Bearer tokens; skip if it looks like a SEEK API token
      # (SEEK API tokens use "Token token=<value>" format).
      return nil unless auth_header.start_with?('Bearer ')

      token = auth_header.sub('Bearer ', '')
      return nil if token.blank?

      payload = KeycloakJwtAuth.decode_token(token)
      return nil unless payload

      sub = payload['sub']
      return nil unless sub.present?

      identity = Identity.find_by(provider: 'oidc', uid: sub)
      return nil unless identity

      user = identity.user
      Rails.logger.info "[keycloak_jwt_auth] Authenticated SEEK user #{user.id} (#{user.login}) from Keycloak sub=#{sub}"
      user
    end

    # Override current_user to try Keycloak JWT first.
    alias_method :original_current_user, :current_user

    def current_user
      if defined?(@current_user)
        @current_user
      else
        self.current_user = (user_from_keycloak_jwt || user_from_session || user_from_doorkeeper || user_from_basic_auth || user_from_cookie || user_from_api_token)
      end
    end
  end
end
