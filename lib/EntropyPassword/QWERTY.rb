module EntropyPassword
  class QWERTY
    QWERTY_STRINGS = %W(1234567890-qwertyuiopasdfghjkl;zxcvbnm,./ 1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/-['=]:?_{\"+} 1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p qazwsxedcrfvtgbyhnujmik,ol.p;/-['=]:?_{\"+} qazwsxedcrfvtgbyhnujmikolp ]\"/=[;.-pl,0okm9ijn8uhb7ygv6tfc5rdx4esz3wa2q1 pl0okm9ijn8uhb7ygv6tfc5rdx4esz3wa2q1 ]\"/[;.pl,okmijnuhbygvtfcrdxeszwaq plokmijnuhbygvtfcrdxeszwaq 014725836914702583697894561230258/369*+-*/ abcdefghijklmnopqrstuvwxyz)
    attr_reader :base_password

    def initialize(password)
      @base_password = password.dup.downcase
    end

    def is_strong?(min_entropy: 18)
      adjusted_entropy(entropy_threshold: min_entropy) >= min_entropy
    end

    def is_weak?(min_entropy: 18)
      !is_strong?(entropy_threshold: min_entropy)
    end

    def adjusted_entropy(entropy_threshold: 0)
      revpassword = base_password.reverse
      min_entropy = [EntropyCalculator.bits(base_password), EntropyCalculator.bits(revpassword)].min
      QWERTY_STRINGS.each do |qwertystr|
        qpassword = mass_qwerty_strings(base_password, qwertystr)
        qrevpassword = mask_qwerty_string(revpassword, qwertystr)

        if qpassword != base_password
          numbits = EntropyCalculator.calculate(qpassword)
          min_entropy = [min_entropy, numbits].min
          return min_entropy if min_entropy < entropy_threshold
        end
        if qrevpassword != revpassword
          numbits = EntropyCalculator.calculate(qpassword)
          min_entropy = [min_entropy, numbits].min
          return min_entropy if min_entropy < entropy_threshold
        end
      end
      min_entropy
    end

    private
      def mask_qwerty_strings(password, qwerty_string)
        masked_password = password
        z = 6
        begin
          y = qwerty_string.length - z
          (0..y).each do |x|
            str = qwerty_string[x, z].sub('-', '\\-')
            masked_password = masked_password.sub(str, '*')
          end
          z = z - 1

        end while z > 2
        masked_password
      end
  end
end