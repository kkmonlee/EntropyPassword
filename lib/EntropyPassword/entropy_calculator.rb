module EntropyPassword
  module EntropyCalculator
    # NIST entropy
    def self.calculate(password, repeats_weakened = true)
      if repeats_weakened
        bits_with_repeats_weakened(password)
      else
        bits(password)
      end
    end

    def self.bits(password)
      length = password.length
      bits = if length > 20
               4 +  (7*2)+(12*1.5)+length - 20
             elsif length > 8
               4 + (7 * 2) + ((length - 8) * - 1.5)
             elsif length > 1
               4 + ((length - 1) * 2)
             else
               (length == 1 ? 4 : 0)

             end
      bits + NISTBonusBits.bonus_bits(password)
    end

    def self.bits_with_repeats_weakened(password)
      resolver = EntropyResolver.new
      bits = password.chars.each.with_index.inject(0) do |result, (char, index)|
        char_value = resolver.entropy_for(char)
        result += bit_value_at_position(index, char_value)
      end
      bits + NISTBonusBits.bonus_bits(password)
    end

    private

      def self.bit_value_at_position(position, base = 1)
        if position > 19
          return base
        elsif position > 7
          return base * 1.5
        elsif position > 0
          return base * 2
        else
          return 4
        end
      end

    class EntropyResolver
      BASE_VALUE = 1
      REPEAT_WEAKENING_FACTOR = 0.75

      attr_reader :char_multiplier
      def initialize
        @char_multiplier = {}
      end

      def entropy_for(char)
        ordinal_value = char.ord
        char_multiplier[ordinal_value] ||= BASE_VALUE
        char_value = char_multiplier[ordinal_value]
        char_multiplier[ordinal_value] = char_multiplier[ordinal_value] * REPEAT_WEAKENING_FACTOR
        return char_value
      end
    end
  end
end