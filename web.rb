require 'bcrypt'
require 'net/http'
require 'uri'
require 'json'
require_relative 'login_service/sparql_queries.rb'

configure do
  set :salt, ENV['MU_APPLICATION_SALT']
end

###
# Vocabularies
###

MU_ACCOUNT = RDF::Vocabulary.new(MU.to_uri.to_s + 'account/')
MU_SESSION = RDF::Vocabulary.new(MU.to_uri.to_s + 'session/')


###
# POST /sessions
#
# Body    {"data":{"type":"sessions","attributes":{"nickname":"john_doe","password":"secret"}}}
# Returns 201 on successful login
#         400 if session header is missing
#         400 on login failure (incorrect user/password or inactive account)
###
post '/sessions/github/?' do
  ###
  # Validate headers
  ###
  validate_json_api_content_type(request)

  session_uri = session_id_header(request)
  error('Session header is missing') if session_uri.nil?

  rewrite_url = rewrite_url_header(request)
  error('X-Rewrite-URL header is missing') if rewrite_url.nil?

  ###
  # Validate request and obtain username and password @ github
  ###
  payload = {
    "client_id" => ENV['GITHUB_CLIENT_ID'],
    "client_secret" => ENV['GITHUB_CLIENT_SECRET'],
    "code" => @json_body['authorizationCode']
  }

  uri = URI.parse(ENV['GITHUB_OAUTH_URL'] + "/login/oauth/access_token")

  header = {
       "Content-Type" => "application/json",
       "Accept" => "application/json"
  }

  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  request = Net::HTTP::Post.new(uri.request_uri, header)
  request.body = payload.to_json

  # get a valid access token from the github website
  response = http.request(request)
  responseHash = JSON.parse(response.body)

  accessToken = responseHash['access_token']
  tokenType = responseHash['token_type']

  user_response = Net::HTTP.get_response(URI(ENV['GITHUB_OAUTH_API_URL'] + "/user?access_token=" + accessToken))
  user_json = JSON.parse(user_response.body)

  status 200

  # ###
  # # Validate login
  # ###
  account = nil

  result = select_account_github(user_json['login'])

  if result.empty?
    account = insert_account_github(user_json['login'],
                          user_json['html_url'],
                          user_json['name'],
                          user_json['email'],
                          user_json['location'])
  else
    account = result.first
  end

  ###
  # Remove old sessions
  ###
  remove_old_sessions(session_uri)

  ###
  # Insert new session
  ###

  session_id = generate_uuid()
  insert_new_session_for_account(account[:uri].to_s, session_uri, session_id)
  update_modified(session_uri)

  status 201
  {
    links: {
      self: rewrite_url.chomp('/') + '/current'
    },
    data: {
      type: 'sessions',
      id: session_id
    },
    relationships: {
      account: {
        links: {
          related: "/accounts/#{account[:uuid]}"
        },
        data: { 
          type: "accounts", 
          id: account[:uuid]
        }
      }
    }
  }.to_json
end

###
# DELETE /sessions/current
#
# Returns 204 on successful logout
#         400 if session header is missing or session header is invalid
###
delete '/sessions/current/?' do
  content_type 'application/vnd.api+json'

  ###
  # Validate session
  ###

  session_uri = session_id_header(request)
  error('Session header is missing') if session_uri.nil?


  ###
  # Get account
  ### 

  result = select_account_by_session(session_uri)
  error('Invalid session') if result.empty?
  account = result.first[:account].to_s


  ###
  # Remove session
  ###

  result = select_current_session(account)
  result.each { |session| update_modified(session[:uri]) }
  delete_current_session(account)

  status 204
end


###
# GET /sessions/current
#
# Returns 204 if current session exists
#         400 if session header is missing or session header is invalid
###
get '/sessions/current/?' do
  content_type 'application/vnd.api+json'

  ###
  # Validate session
  ###

  session_uri = session_id_header(request)
  error('Session header is missing') if session_uri.nil?


  ###
  # Get account
  ###

  result = select_account_by_session(session_uri)
  error('Invalid session') if result.empty?
  account = result.first

  rewrite_url = rewrite_url_header(request)

  status 200
 {
    links: {
      self: rewrite_url.chomp('/')
    },
    data: {
      type: 'sessions',
      id: session_uri
    },
    relationships: {
      account: {
        links: {
          related: "/accounts/#{account[:uuid]}"
        },
        data: { 
          type: "accounts", 
          id: account[:uuid]
        }
      }
    }
  }.to_json
end


###
# Helpers
###

helpers LoginService::SparqlQueries
