require 'openssl'
require 'base64'
require 'json'
require 'net/http'


def initiate_payment
    puts "starting a new payment"
    hash_secret = "hash_secret"
    encryption_key = "encryption_key"
    api_key = "api_key"


    merchant_order_id = "6DFDKJFGLKD343" + rand(10..10000).to_s
    payin_status_data = {
      "customer_name" => "bingo das ruby",
      "customer_ip" => "127.0.0.1",
      "customer_mobile" => "+919241589568",
      "customer_email" => "bings@gmail.com",
      "customer_upi_id" => "bingdas@hdfcbank",
      "merchant_order_id" => merchant_order_id,
      "merchant_code" => "Mercht101",
      "merchant_transaction_date" => "2023 March 18",
      "payin_amount" => 1000,
      "mode" => "cash"
    }
    payin_status_data_str = payin_status_data.to_json

    puts "plain data in json string " + payin_status_data_str

    signature, encrypted_data = create_request_data(payin_status_data_str, hash_secret, encryption_key)

    headers = {
      "Content-Type" => "application/json",
      "signature" => signature,
      "api_key" => api_key
    }
    
    uri = URI.parse("https://pay.jigspay.com/newpayment.php")
 
    http = Net::HTTP.new(uri.host, uri.port)

    http.use_ssl = true
    # please don't do this in production 
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE 
    
    request = CaseSensitivePost.new(uri.path, headers)
    request.body = JSON.generate({ "data" => encrypted_data })
    
    puts "request body :  " + request.body

    response = http.request(request)
    
    puts "response body :  " + response.body

    header_size = response.header.size
    headers = response.to_hash

    puts "response  header : "
    puts headers
    
    if response_signature = response['signature']
        puts "signature is present int the header : " + response['signature']
        
        body_obj = JSON.parse(response.body)

        puts "Redirect response data : "+ body_obj["data"]
        response_data_str = validate_and_extract_response_data(body_obj["data"], response_signature, hash_secret, encryption_key)


        puts '##################################'
        puts '##################################'
        puts "GREAT JOB: now redirect to #{JSON.parse(response_data_str)['redirect_url']}"
        puts '##################################'
        puts '##################################'
        
    end    
    
end

def validate_and_extract_response_data(data, signature, hash_secret, key)
    if is_valid_signature(signature, data, hash_secret)
      puts "data is not tampered"
      data_in_json = JSON.parse(data)
      ciphertext = Base64.strict_decode64(data_in_json["cipher_text"])
      iv = [data_in_json["iv"]].pack("H*")
      decrypted = OpenSSL::Cipher.new('aes-256-cbc').decrypt
      decrypted.key = [key].pack("H*")
      decrypted.iv = iv
      decrypted_data = decrypted.update(ciphertext) + decrypted.final
      return decrypted_data
    end
end
  
def create_request_data(data_str, hash_secret, key)
    puts "creating request data"

    iv = OpenSSL::Random.random_bytes(16)

    encrypted_data = OpenSSL::Cipher.new('aes-256-cbc').encrypt
    encrypted_data.key = [key].pack('H*')
    encrypted_data.iv = iv
    encrypted_data_str = encrypted_data.update(data_str) + encrypted_data.final

    puts "Encrypted data in base 64 before creating response object : " + Base64.strict_encode64(encrypted_data_str)

    response_data = ResponseData.new(Base64.strict_encode64(encrypted_data_str), iv.unpack1('H*'))
    response_data_str = response_data.to_json
    
    response_data = ResponseData.new(Base64.strict_encode64(encrypted_data_str), iv.unpack1('H*'))
    response_data_str = response_data.to_json

    puts "response data as json string : " + response_data_str

    signature = get_signature(hash_secret, response_data_str)

    puts "signature  :  " + signature

    return [signature, response_data_str]
end

def is_valid_signature(signature, data, secret)
    get_signature(secret, data) == signature
end

def get_signature(secret, data)
  hmac = OpenSSL::HMAC.digest('sha256', secret, data)
  Base64.encode64(hmac).strip
end

class ResponseData
    attr_accessor :cipher_text, :iv
    
    def initialize(cipher_text, iv)
      @cipher_text = cipher_text
      @iv = iv
    end
    
    def to_json(*args)
      {
        cipher_text: @cipher_text,
        iv: @iv
      }.to_json(*args)
    end
end
  
class CaseSensitivePost < Net::HTTP::Post
    def initialize_http_header(headers)
      @header = {}
      headers.each{|k,v| @header[k.to_s] = [v] }
    end
  
    def [](name)
      @header[name.to_s]
    end
  
    def []=(name, val)
      if val
        @header[name.to_s] = [val]
      else
        @header.delete(name.to_s)
      end
    end
  
    def capitalize(name)
      name
    end
end

initiate_payment()
  
