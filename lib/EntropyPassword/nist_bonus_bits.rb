module EntropyPassword
  module NISTBonusBits
    @@bonus_bits_for_password = {}

    def self.bonus_bits(password)
      @@bonus_bits_for_password[password] ||= begin
                                                calculate_bonus_bits_for(password)

      end
    end

    def self.reset_bonus_cache!
      @@bonus_bits_for_password = {}
    end

    def self.calculate_bonus_bits_for(password)
      upper = !!(password =~ /[[:upper:]]/)
      lower = !!(password =~ /[[:lower:]]/)
      numeric = !!(password =~ /[[:digit:]]/)
      other   = !!(password =~ /[^a-zA-Z0-9 ]/)
      space   = !!(password =~ / /)

      bonus_bits = if upper && lower && other && numeric
                     6
                   elsif upper && lower && other && !numeric
                     5
                   elsif numeric && other && !upper && !lower
                     -2
                   elsif numeric && !other && !upper && !lower
                     -6
                   else
                     0
                   end

      if !space
        bonus_bits = bonus_bits - 2
      elsif password.split(/\s+/).length > 3
        bonus_bits = bonus_bits + 1
      end
      bonus_bits
    end
  end
end