# typed: ignore

class Rack::Attack
  ### Configure Cache ###

  # If you don't want to use Rails.cache (Rack::Attack's default), then
  # configure it here.
  #
  # Note: The store is only used for throttling (not blocklisting and
  # safelisting). It must implement .increment and .write like
  # ActiveSupport::Cache::Store

  # Configure Rack Attack to use a separate Redis instance
  Rack::Attack.cache.store = ActiveSupport::Cache::RedisCacheStore.new(
    url: ENV.fetch("REDIS_RATE_LIMIT_URL", "redis://localhost:6379/1"),
    namespace: "rack-attack",
    error_handler: ->(method:, returning:, exception:) { # rubocop:disable Lint/UnusedBlockArgument
      Rails.logger.warn "Rack::Attack Redis error in #{method}: #{exception.message}"
    }
  )

  ### Throttle Spammy Clients ###

  # If any single client IP is making tons of requests, then they're
  # probably malicious or a poorly-configured scraper. Either way, they
  # don't deserve to hog all of the app server's CPU. Cut them off!
  #
  # Note: If you're serving assets through rack, those requests may be
  # counted by rack-attack and this throttle may be activated too
  # quickly. If so, enable the condition to exclude them from tracking.

  # Throttle all requests by IP (60rpm)
  #
  # Key: "rack::attack:#{Time.now.to_i/:period}:req/ip:#{req.ip}"
  # throttle('req/ip', limit: 300, period: 5.minutes) do |req|
  #   req.ip # unless req.path.start_with?('/assets')
  # end

  # Throttle based of authorization header
  # throttle('auth_header_throttles', limit: 10, period: 1.second) do |req|
  #   auth_header = req.env['HTTP_AUTHORIZATION']
  #   auth_header.presence
  # end

  # Track requests by authorization header (monitoring only)
  track("auth_header_requests", limit: 1, period: 1.second) do |req|
    if req.path.start_with?("/v1/")
      auth_header = req.env["HTTP_AUTHORIZATION"]
      Digest::SHA512.hexdigest(auth_header) if auth_header.present?
    end
  end

  ### Prevent Brute-Force Login Attacks ###

  # The most common brute-force login attack is a brute-force password
  # attack where an attacker simply tries a large number of emails and
  # passwords to see if any credentials match.
  #
  # Another common method of attack is to use a swarm of computers with
  # different IPs to try brute-forcing a password for a specific account.

  # Throttle POST requests to /login by IP address
  #
  # Key: "rack::attack:#{Time.now.to_i/:period}:logins/ip:#{req.ip}"
  # throttle('logins/ip', limit: 5, period: 20.seconds) do |req|
  #   if req.path == '/login' && req.post?
  #     req.ip
  #   end
  # end

  # Throttle POST requests to /login by email param
  #
  # Key: "rack::attack:#{Time.now.to_i/:period}:logins/email:#{normalized_email}"
  #
  # Note: This creates a problem where a malicious user could intentionally
  # throttle logins for another user and force their login requests to be
  # denied, but that's not very common and shouldn't happen to you. (Knock
  # on wood!)
  # throttle('logins/email', limit: 5, period: 20.seconds) do |req|
  #   if req.path == '/login' && req.post?
  #     # Normalize the email, using the same logic as your authentication process, to
  #     # protect against rate limit bypasses. Return the normalized email if present, nil otherwise.
  #     req.params['email'].to_s.downcase.gsub(/\s+/, '').presence
  #   end
  # end

  ### Custom Throttle Response ###

  # Log when throttling happens
  # self.throttled_response = lambda do |env|
  #   Rails.logger.info("gcp_tag:request_throttled, #{env['rack.attack.matched']} - #{env['rack.attack.match_discriminator']}")
  #   [ 429,  # status
  #     {},   # headers
  #     ['Too Many Requests']] # body
  # end

  ### Tracking Callbacks ###

  # This callback runs when a track limit is exceeded (but request still goes through)
  ActiveSupport::Notifications.subscribe("track.rack_attack") do |_name, _start, _finish, _request_id, payload|
    Rails.logger.info(
      {
        gcp_tag: "rack_attack_track_limit_exceeded",
        matched: payload[:request].env["rack.attack.matched"],
        count: payload[:request].env["rack.attack.match_data"][:count]
      }
    )
  end
end
