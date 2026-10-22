# Checks the browser-login OIDC provider built by keycloak_oidc.rb can reach
# Keycloak for the server-side parts of the callback. Read-only: it only fetches
# Keycloak's signing keys.
#
# Run from the platform repo root (the file is not mounted, so pipe it in):
#   docker compose exec -T seek bash -c 'cd /seek && RAILS_ENV=production bundle exec rails runner -' \
#     < services/seek/ldh-deployment/test/keycloak_oidc_check.rb

$failures = 0

def check(name)
  result = yield
  puts "#{result ? 'PASS' : 'FAIL'}: #{name}"
  $failures += 1 unless result
rescue StandardError => e
  puts "FAIL: #{name} (#{e.class}: #{e.message})"
  $failures += 1
end

options = Seek::Config.omniauth_providers.find { |p| p[1][:name] == :oidc }&.last
check('oidc provider is configured') { options }

# The callback verifies the id_token with these keys. omniauth_openid_connect
# >= 0.8 fetches jwks_uri as given, without resolving it against host/port.
check('signing keys can be fetched from jwks_uri') do
  strategy = OmniAuth::Strategies::OpenIDConnect.new(->(_env) {}, options)
  strategy.send(:public_key).respond_to?(:any?) && strategy.send(:public_key).any?
end

puts $failures.zero? ? 'ALL PASSED' : "#{$failures} FAILED"
