require 'io/console'
require 'sqlite3'

class Enpass < U::Package

  class << self
    def start
      db_path = settings.enpass
      print 'Password: '
      password = STDIN.noecho(&:gets).chomp
      puts
      db = SQLite3::Database.new db_path
      db.execute "PRAGMA load_extension"
      db.execute "PRAGMA cipher_default_kdf_iter = 24000;"
      db.execute "PRAGMA kdf_iter = 24000;"
      db.execute "PRAGMA key='#{password}'"
      identity_row = db.execute 'SELECT * FROM Identity;'
      id, version, signature, sync_uuid, hash, info = identity_row.first
  
      iv = info[16..31]
      salt = info[32..48]
      key = generate_key hash, salt
      return iv, key, db
    end

    def generate_key hash, salt
      digest = OpenSSL::Digest::SHA256.new
      OpenSSL::PKCS5.pbkdf2_hmac(hash, salt, 2, 32, digest)
    end

    def decrypt encoded, key, iv
      decipher = OpenSSL::Cipher::AES.new(256, :CBC)
      decipher.decrypt
      decipher.key = key
      decipher.iv = iv
      decipher.update(encoded) + decipher.final
    end
  end

  script 'pass' do
    iv, key, db = start
    card_rows = db.execute "SELECT data FROM Cards;"
    puts decrypt card_rows.first.first, key, iv
  end
end

# type Card struct {
#   id int                  // from db
#   uuid string
#   title string
#   subtitle string
#   ctype string
#   category string
#   deleted int
#   trashed int

#   Fields []Field          // rest from data json
#   Iconid int64
#   Name string
#   Note string
#   Templatetype string
#   Updatetime string       // really a date
#   Uuid string
# }
