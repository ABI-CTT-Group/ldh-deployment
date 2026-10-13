# Checks KeycloakJwtAuth.provision_user (keycloak_jwt_auth.rb) against the live
# SEEK database. Every case runs in a transaction that is rolled back, so no rows
# are left behind and no after_commit jobs fire.
#
# Run from the platform repo root (the file is not mounted, so pipe it in):
#   docker compose exec -T seek bash -c 'cd /seek && RAILS_ENV=production bundle exec rails runner -' \
#     < services/seek/ldh-deployment/test/keycloak_provisioning_check.rb

require 'securerandom'

$failures = 0

def check(name, condition)
  puts "#{condition ? 'PASS' : 'FAIL'}: #{name}"
  $failures += 1 unless condition
end

def in_rollback
  ActiveRecord::Base.transaction do
    yield
    raise ActiveRecord::Rollback
  end
end

def counts
  [User.count, Person.count, Identity.count]
end

def new_claims(**overrides)
  tag = SecureRandom.hex(4)
  { sub: SecureRandom.uuid, email: "jit-check-#{tag}@example.org", first_name: 'Jit',
    last_name: "Check#{tag}", username: "jit-check-#{tag}" }.merge(overrides)
end

check('provision_user is defined', KeycloakJwtAuth.respond_to?(:provision_user))
exit 1 unless KeycloakJwtAuth.respond_to?(:provision_user)

in_rollback do
  claims = new_claims
  user = KeycloakJwtAuth.provision_user(**claims)
  check('new identity: returns a user', user.is_a?(User))
  check('new identity: user is active', user&.active?)
  check('new identity: registration is complete', user&.registration_complete?)
  check('new identity: person has the token names and email',
        user&.person && [user.person.first_name, user.person.last_name, user.person.email] ==
          [claims[:first_name], claims[:last_name], claims[:email]])
  check('new identity: identity links sub to the user',
        Identity.find_by(provider: 'oidc', uid: claims[:sub])&.user == user)

  before = counts
  again = KeycloakJwtAuth.provision_user(**claims)
  check('same sub again: returns the same user', again == user)
  check('same sub again: creates no rows', counts == before)
end

in_rollback do
  existing = new_claims
  KeycloakJwtAuth.provision_user(**existing)
  before = counts
  clash = KeycloakJwtAuth.provision_user(**new_claims(email: existing[:email].upcase))
  check('email clash: returns nil', clash.nil?)
  check('email clash: creates no rows', counts == before)
end

in_rollback do
  before = counts
  check('blank email: returns nil', KeycloakJwtAuth.provision_user(**new_claims(email: nil)).nil?)
  check('blank email: creates no rows', counts == before)
end

in_rollback do
  before = counts
  check('service account: returns nil',
        KeycloakJwtAuth.provision_user(**new_claims(username: 'service-account-api')).nil?)
  check('service account: creates no rows', counts == before)
end

puts $failures.zero? ? 'ALL PASSED' : "#{$failures} FAILED"
exit($failures.zero? ? 0 : 1)
