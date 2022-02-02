require 'addressable'
require 'base64'
require 'json'
require 'restclient'

module RSpotify
  class MissingAuthentication < StandardError; end

  API_URI       = 'https://api.spotify.com/v1/'.freeze
  AUTHORIZE_URI = 'https://accounts.spotify.com/authorize'.freeze
  TOKEN_URI     = 'https://accounts.spotify.com/api/token'.freeze
  VERBS         = %w[get post put delete].freeze

  class << self
    attr_accessor :raw_response
    attr_reader :client_token

    def authenticate(client_id, client_secret, proxy = nil)
      @client_id, @client_secret = client_id, client_secret
      response = RestClient::Request.execute(
        open_timeout: 30,
        method: 'post',
        url: TOKEN_URI,
        proxy: proxy,
        headers: auth_header,
        payload: { grant_type: 'client_credentials' }
      )
      @client_token = JSON.parse(response)['access_token']
      true
    end

    def authenticate_many(client_creds_hash, proxy = nil)
      @client_token_store = []
      client_ids = client_creds_hash[:client_ids]
      client_secrets = client_creds_hash[:client_secrets]

      client_ids.each_with_index do |current_id, idx|
        current_secret = client_secrets[idx]
        authenticate(current_id, current_secret, proxy)
        @client_token_store << @client_token
      end
    end

    VERBS.each do |verb|
      define_method verb do |path, proxy = nil|
        send_request(verb, path, proxy)
      end
    end

    def resolve_auth_request(user_id, url)
      users_credentials = if User.class_variable_defined?('@@users_credentials')
        User.class_variable_get('@@users_credentials')
      end

      if users_credentials && users_credentials[user_id]
        User.oauth_get(user_id, url)
      else
        get(url)
      end
    end

    private

    def select_client_token
      return client_token unless @client_token_store.is_a?(Array) && @client_token_store[0]
      rand_idx = rand(0..(@client_token_store.count - 1))
      @client_token_store[rand_idx]
    end

    def send_request(verb, path, headers, proxy = nil)
      chosen_token = select_client_token
      headers = { 'Authorization' => "Bearer #{chosen_token}" } if chosen_token
      url = path.start_with?('http') ? path : API_URI + path
      url, query = *url.split('?')
      url = Addressable::URI.encode(url)
      url << "?#{query}" if query

      begin
        response = RestClient::Request.execute(
          method: verb,
          url: url,
          proxy: proxy,
          headers: headers
        )
      rescue RestClient::Unauthorized => e
        raise e if request_was_user_authenticated?(headers)
        raise MissingAuthentication
      end

      return response if raw_response
      JSON.parse(response) unless response.nil? || response.empty?
    end

    def request_was_user_authenticated?(headers)
      users_credentials = if User.class_variable_defined?('@@users_credentials')
        User.class_variable_get('@@users_credentials')
      end

      if users_credentials
        creds = users_credentials.map{|_user_id, creds| "Bearer #{creds['token']}"}

        if creds.include?(headers.dig('Authorization'))
          return true
        end
      end

      false
    end

    def auth_header
      authorization = Base64.strict_encode64("#{@client_id}:#{@client_secret}")
      { 'Authorization' => "Basic #{authorization}" }
    end

  end
end
