module EntropyPassword
  module PasswordVariants
    COOL_SPEAK_1 = {
        "@" => "a",
        "!" => "i",
        "$" => "s",
        "1" => "i",
        "2" => "z",
        "3" => "e",
        "4" => "a",
        "5" => "s",
        "6" => "g",
        "7" => "t",
        "8" => "b",
        "9" => "g",
        "0" => "o"
    }

    COOL_SPEAK_2 = {
        "@" => "a",
        "!" => "i",
        "$" => "s",
        "1" => "l",
        "2" => "z",
        "3" => "e",
        "4" => "a",
        "5" => "s",
        "6" => "g",
        "7" => "t",
        "8" => "b",
        "9" => "g",
        "0" => "o"
    }

    KEYBOARD_DOWN_NOCAPS = {
        "z" => "",
        "x" => "",
        "c" => "",
        "v" => "",
        "b" => "",
        "n" => "",
        "m" => "",
        "," => "",
        "." => "",
        "/" => "",
        "<" => "",
        ">" => "",
        "?" => ""
    }

    KEYBOARD_DOWNRIGHT = {
        "a" => "z",
        "q" => "a",
        "1" => "q",
        "s" => "x",
        "w" => "s",
        "2" => "w",
        "d" => "c",
        "e" => "d",
        "3" => "e",
        "f" => "v",
        "r" => "f",
        "4" => "r",
        "g" => "b",
        "t" => "g",
        "5" => "t",
        "h" => "n",
        "y" => "h",
        "6" => "y",
        "j" => "m",
        "u" => "j",
        "7" => "u",
        "i" => "k",
        "8" => "i",
        "o" => "l",
        "9" => "o",
        "0" => "p"
    }

    KEYBOARD_DOWNLEFT = {
        "2" => "q",
        "w" => "a",
        "3" => "w",
        "s" => "z",
        "e" => "s",
        "4" => "e",
        "d" => "x",
        "r" => "d",
        "5" => "r",
        "f" => "c",
        "t" => "f",
        "6" => "t",
        "g" => "v",
        "y" => "g",
        "7" => "y",
        "h" => "b",
        "u" => "h",
        "8" => "u",
        "j" => "n",
        "i" => "j",
        "9" => "i",
        "k" => "m",
        "o" => "k",
        "0" => "o",
        "p" => "l",
        "-" => "p"
    }

    def self.all_variants(password)
      passwords = [password.dup.downcase]
      passwords += keyboard_shift_variants(password)
      passwords += cool_speak_variants(password)
      passwords.uniq
    end

    def self.keyboard_caps_variants(password)
      password = password.dup.downcase
      variants = []

      if password == password.tr(KEYBOARD_DOWN_NOCAPS.keys.join, KEYBOARD_DOWN_NOCAPS.values.join)
        variant = password.tr(KEYBOARD_DOWNRIGHT.keys.join, KEYBOARD_DOWNRIGHT.values.join)
        variants << variant
        variants << variant.reverse
        variant = password.tr(KEYBOARD_DOWNLEFT.keys.join, KEYBOARD_DOWNLEFT.values.join)
        variants << variant
        variants << variant.reverse
      end
      variants

    end

    def self.cool_speak_variants(password)
      password = password.dup.downcase
      variants = []
      coolness = password.tr(COOL_SPEAK_1.keys.join, COOL_SPEAK_1.values.join)
      if coolness != password
        variants << coolness
        variants << coolness.reverse
      end

      coolprime = password.tr(COOL_SPEAK_2.keys.join, COOL_SPEAK_2.values.join)
      if coolprime != password && coolprime != coolness
        variants << coolprime
        variants << coolprime.reverse
      end
      variants
    end
  end
end