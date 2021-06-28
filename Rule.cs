using System;
using System.Linq;

namespace HCA_Crypto
{
    public class Rule
    {
        public int[] Bits { get; private set; }
        public int Length { get; private set; }
        public bool IsLeftSensible { get; private set; }
        public bool IsRightSensible { get; private set; }

        public Rule(int[] bits)
        {
            Bits = bits;
            Length = bits.Length;

            IsLeftSensible = true;
            IsRightSensible = true;
            int halfLength = Length / 2;
            for (int i = 0; i < halfLength; ++i)
            {
                IsLeftSensible = IsLeftSensible && (Bits[i] != Bits[i + halfLength]);
                IsRightSensible = IsRightSensible && (Bits[2 * i] != Bits[2 * i + 1]);
            }
        }

        public Rule(string bits)
        {
            Bits = bits.Select(c => (int)c - 48).ToArray();
            Length = bits.Length;

            IsLeftSensible = true;
            IsRightSensible = true;
            int halfLength = Length / 2;
            for (int i = 0; i < halfLength; ++i)
            {
                IsLeftSensible = IsLeftSensible && (Bits[i] != Bits[i + halfLength]);
                IsRightSensible = IsRightSensible && (Bits[2 * i] != Bits[2 * i + 1]);
            }
        }

        public static Rule GenerateLeftSensibleRule(int[] nuclei)
        {
            int[] ruleBits = new int[2 * nuclei.Length];
            for (int idx = 0; idx < nuclei.Length; ++idx)
            {
                ruleBits[idx] = nuclei[idx];
                ruleBits[nuclei.Length + idx] = Util.OppositeBit(nuclei[idx]);
            }
            return new Rule(ruleBits);
        }

        public static Rule GenerateRightSensibleRule(int[] nuclei)
        {
            int[] ruleBits = new int[2 * nuclei.Length];
            for (int idx = 0; idx < nuclei.Length; ++idx)
            {
                ruleBits[2 * idx] = nuclei[idx];
                ruleBits[2 * idx + 1] = Util.OppositeBit(nuclei[idx]);
            }
            return new Rule(ruleBits);
        }

        public static Rule[] GetAllLeftSensibleRulesByShiftingNuclei(int[] nuclei)
        {
            #region Pré-Condições
            double nucleiLengthLogDec = (Math.Log(nuclei.Length) / Math.Log(2));
            if (nucleiLengthLogDec % 1 != 0)
                throw new Exception("Nuclei length must be a power of two");

            int nucleiLengthLog = (int)nucleiLengthLogDec;

            if (nucleiLengthLog % 2 == 1)
                throw new Exception("Invalid nuclei length. No equivalent radius");
            #endregion /* Pré-Condições */

            Rule[] mainRules = new Rule[nuclei.Length];
            int[] temp = nuclei;
            for (int shiftIdx = 0; shiftIdx < nuclei.Length; ++shiftIdx)
            {
                mainRules[shiftIdx] = Rule.GenerateLeftSensibleRule(temp);
                temp = Util.LeftShift(temp);
            }
            return mainRules;
        }

        public static Rule[] GetAllRightSensibleRulesByShiftingNuclei(int[] nuclei)
        {
            #region Pré-Condições
            double nucleiLengthLogDec = (Math.Log(nuclei.Length) / Math.Log(2));
            if (nucleiLengthLogDec % 1 != 0)
                throw new Exception("Nuclei length must be a power of two");

            int nucleiLengthLog = (int)nucleiLengthLogDec;

            if (nucleiLengthLog % 2 == 1)
                throw new Exception("Invalid nuclei length. No equivalent radius");
            #endregion /* Pré-Condições */

            Rule[] mainRules = new Rule[nuclei.Length];
            int[] temp = nuclei;
            for (int shiftIdx = 0; shiftIdx < nuclei.Length; ++shiftIdx)
            {
                mainRules[shiftIdx] = Rule.GenerateRightSensibleRule(temp);
                temp = Util.RightShift(temp);
            }
            return mainRules;
        }

        public static Rule[] GenerateLeftSensibleMarginRules()
        {
            var zeros = Enumerable.Repeat(0, 256);
            var ones = Enumerable.Repeat(1, 256);
            return new Rule[] {
                new Rule(Enumerable.Concat(zeros, ones).ToArray()),
                new Rule(Enumerable.Concat(ones, zeros).ToArray())
            };
        }

        public static Rule[] GenerateRightSensibleMarginRules()
        {
            return new Rule[] {
                new Rule(String.Join("", Enumerable.Repeat("01", 256))),
                new Rule(String.Join("", Enumerable.Repeat("10", 256)))
            };
        }
    }
}
