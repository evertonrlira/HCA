namespace CACrypto.Commons
{
    public class Rule
    {
        public int[] Bits { get; private set; }
        public int Length { get; private set; }
        public bool IsLeftSensible { get; private set; }
        public bool IsRightSensible { get; private set; }

        public Rule(int[] bits) {
            Bits = bits;
            Length = bits.Length;

            IsLeftSensible = true;
            IsRightSensible = true;
            int halfLength = Length / 2;
            for (int i=0; i < halfLength; ++i)
            {
                IsLeftSensible = IsLeftSensible && (Bits[i] != Bits[i + halfLength]);
                IsRightSensible = IsRightSensible && (Bits[2*i] != Bits[2*i + 1]);
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

        public static int VonNeumannNeighborhoodLengthIn1D(int radius)
        {
            return (2 *radius) + 1;
        }

        public override string ToString()
        {
            var binaryRuleRepresentationStr = string.Concat(Bits.Reverse());
            var ruleNumber = Convert.ToInt32(binaryRuleRepresentationStr, 2);
            return string.Format("Rule {0}: [ {1} ]", ruleNumber, string.Join(" | ", Bits.Select(cell => cell)));
        }

        internal static bool IsValidRule(string bits)
        {
            double ruleLengthLogDec = (Math.Log(bits.Length) / Math.Log(2));
            if (ruleLengthLogDec % 1 != 0)
                return false;

            int ruleLengthLog = (int)ruleLengthLogDec;

            if (ruleLengthLog % 2 == 0 || ruleLengthLog < 3)            
                return false;

            if (bits.Any(c => c != '0' && c != '1'))
                return false;

            return true;
        }

        internal static bool IsValidRuleNuclei(string bits)
        {
            double nucleiLengthLogDec = (Math.Log(bits.Length) / Math.Log(2));
            if (nucleiLengthLogDec % 1 != 0)
                return false;

            int nucleiLengthLog = (int)nucleiLengthLogDec;

            if (nucleiLengthLog % 2 == 1 || nucleiLengthLog < 2)
                return false;

            if (bits.Any(c => c != '0' && c != '1'))
                return false;

            return true;
        }
        
        public static Rule[] GetRulesFromNuclei(int[] nuclei, bool generateLeftSensible, bool generateRightSensible)
        {
            if (generateLeftSensible && generateRightSensible)
                return new Rule[] { Rule.GenerateLeftSensibleRule(nuclei), Rule.GenerateRightSensibleRule(nuclei) };
            else if (generateLeftSensible)
                return new Rule[] { Rule.GenerateLeftSensibleRule(nuclei) };
            else if (generateRightSensible)
                return new Rule[] { Rule.GenerateRightSensibleRule(nuclei) };
            else
                return new Rule[] { };
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

        public static IEnumerable<Rule> LoadFromFile(string relativePath)
        {
            var lines = File.ReadAllLines(relativePath);
            List<Rule> rules = new List<Rule>();
            foreach (var line in lines)
            {
                if (Rule.IsValidRule(line.Trim()))
                {
                    var rule = new Rule(line.Trim());
                    rules.Add(rule);
                }
            }
            return rules;
        }

        public static IEnumerable<Rule> LoadFromFileAndCreateAllPermutations(string relativePath)
        {
            var lines = File.ReadAllLines(relativePath);
            var i = Util.Permutations(lines).ToList().Distinct();
            List<Rule> rules = new List<Rule>();
            foreach (var line in lines)
            {
                if (Rule.IsValidRule(line.Trim()))
                {
                    var rule = new Rule(line.Trim());
                    rules.Add(rule);
                }
            }
            return rules;
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

        public static Rule[] GenerateLeftSensibleMarginRules(int ruleLength)
        {
            var zeros = Enumerable.Repeat(0, ruleLength / 2);
            var ones = Enumerable.Repeat(1, ruleLength / 2);
            return new Rule[] {
                new Rule(Enumerable.Concat(zeros, ones).ToArray()),
                new Rule(Enumerable.Concat(ones, zeros).ToArray())
            };
        }

        public static Rule[] GenerateLeftSensibleMarginRulesForRadius(int radius)
        {
            int ruleLength = Rule.GetRuleLengthForRadius(radius);
            return GenerateLeftSensibleMarginRules(ruleLength);
        }
        
        public static Rule[] GenerateRightSensibleMarginRules(int ruleLength)
        {
            return new Rule[] {
                new Rule(String.Join("", Enumerable.Repeat("01", ruleLength / 2))),
                new Rule(String.Join("", Enumerable.Repeat("10", ruleLength / 2)))
            };
        }

        public static Rule[] GenerateRightSensibleMarginRulesForRadius(int radius)
        {
            int ruleLength = Rule.GetRuleLengthForRadius(radius);
            return GenerateRightSensibleMarginRules(ruleLength);
        }

        public static int GetRadiusForRuleLength(int ruleLength)
        {
            double ruleLengthLogDec = (Math.Log(ruleLength) / Math.Log(2));
            if (ruleLengthLogDec % 1 != 0)
                throw new Exception("Rule length must be a power of two");

            int ruleLengthLog = (int)ruleLengthLogDec;

            if (ruleLengthLog % 2 == 0)
                throw new Exception("Invalid rule length. No equivalent radius");

            return (ruleLengthLog - 1) / 2;
        }

        public static int GetRuleLengthForRadius(int radius)
        {
            return (int)Math.Pow(2, 2 * radius + 1);
        }

        public static int GetNucleiLengthForRadius(int radius)
        {
            return GetRuleLengthForRadius(radius) / 2;
        }

        public static int[] GetNucleiFromRule(Rule rule)
        {
            int nucleiLength = rule.Length / 2;
            int[] nuclei = new int[nucleiLength];
            if (rule.IsLeftSensible)
            {
                Array.Copy(rule.Bits, nuclei, nucleiLength);
                return nuclei;
            }
            else if (rule.IsRightSensible)
            {
                for (int idx = 0; idx < nucleiLength; ++idx)
                {
                    nuclei[idx] = rule.Bits[2 * idx];                    
                }
                return nuclei;
            }
            throw new Exception("Rule has no nuclei");
        }
    }
}