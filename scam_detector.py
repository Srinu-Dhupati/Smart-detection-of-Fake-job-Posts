import re
import logging

class ScamDetector:
    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        # 🚨 Scam Indicator Keywords
        self.red_flags = {
            'scam_promises': [
                'guaranteed', 'big money', 'easy money', 'quick money',
                'unlimited earning', 'high income', 'earn thousands',
                'investment opportunity', 'money making opportunity',
                'competitive pay', 'lucrative', 'earn from home',
                'weekly payment', 'earn up to'
            ],
            'recruitment_scam_phrases': [
                'came across your profile', 'profile caught my eye',
                'genuinely impressed', 'your background and achievements',
                'look forward to discussing', 'working together',
                'excited about possibly', 'caught my attention',
                'perfect candidate', 'perfect match'
            ],
            'suspicious_job_titles': [
                'data entry clerk', 'remote data entry', 'data entry specialist',
                'data entry operator', 'hr recruiter', 'remote position',
                'work from home position', 'online job', 'home based job',
                'typing job', 'form filling', 'email processing'
            ],
            'suspicious_requirements': [
                'no experience required', 'no qualification needed',
                'no degree required', 'zero experience', 'anyone can do',
                'no prior experience', 'no experience needed'
            ],
            'urgency_pressure': [
                'slots fill quickly', 'urgent opening', 'immediate hire',
                'join immediately', 'urgent hiring', 'limited positions',
                'hurry up', 'dont miss'
            ],
            'suspicious_terms': [
                'money laundering', 'confidential job', 'hidden opportunity',
                'exclusive offer', 'registration fee', 'processing fee',
                'security deposit', 'payment first', 'training fees',
                'simple typing', 'simple copy paste', 'simple data entry'
            ],
            'informal_words': [
                "love to invite", "super excited", "hurry up", "slots fill quickly",
                "amazing opportunity", "dream job", "life-changing", "don't miss out"
            ],
            'suspicious_offer_patterns' : [
                'find the attachment', 'confirm through mail', 'send confirmation',
                'urgent confirmation needed', 'immediate confirmation', 'confirm asap',
                'attachment in mail', 'check your mail', 'check attachment',
                'verify through email', 'confirm by email', 'reply with confirmation'
            ]
        }

        # ✅ Legitimate Job Indicators
        self.legitimate_indicators = {
            'professional_elements': [
                'job reference:', 'position code:', 'salary range:', 'benefits include:',
                'requirements:', 'qualifications:', 'job description:', 'position summary:'
            ],
            'contact_details': [
                'hr department', 'recruitment team', 'office address:', 'contact number:',
                'official email:', '@company.com', 'www.', 'headquarters'
            ],
            'experience_related': [
                'minimum years experience', 'years of experience required',
                'relevant experience required', 'proven track record'
            ],
            'qualification_details': [
                'qualifications required', 'educational requirements', 'degree required',
                'certification required', 'bachelor degree', 'master degree'
            ],
            'job_details': [
                'job responsibilities', 'key responsibilities', 'role overview',
                'position summary', 'full time', 'part time', 'shift timings:'
            ],
            'company_info': [
                'company profile', 'about us', 'about the company', 'company culture',
                'organization overview', 'established company', 'industry leader'
            ],
            'offer_letter_verification' : [
                'ref:', 'reference number:', 'appointment letter', 'staff interview',
                'joining date:', 'offer validity:', 'academic year', 'teaching staff',
                'principal signature', 'institution letterhead', 'appointment reference',
                'interview conducted', 'accredited by', 'affiliated to', 'iso certified'
            ],
            'specific_details': [
                'annual salary of', 'bi-weekly',
                'starting salary', 'payable',
                'employee benefits handbook',
                'medical, accommodation',
                'retirement benefits',
                'benefits offered by',
                'office headquarter',
                'face-to-face interview'
            ],
            'time_and_date': [
                'pm -', 'am -',
                'monday', 'tuesday', 'wednesday', 'thursday', 'friday',
                'january', 'february', 'march', 'april', 'may', 'june',
                'july', 'august', 'september', 'october', 'november', 'december'
            ],
            'address_elements': [
                'avenue,', 'street,', 'st.',
                'road,', 'rd.',
                'suite', 'floor',
                'building,', 'plaza,'
            ]
        }

        # 🚀 Template Placeholder Patterns
        self.template_patterns = [
            r"\[\[.*?\]\]",  # [[Job Title]]
            r"\[.*?\]",  # [Company Name]
            r"\{\{.*?\}\}",  # {{Location}}
            r"\{.*?\}",  # {Job Description}
            r"<.*?>",  # <Company Name>
            r"\(\(.*?\)\)",  # ((Responsibilities))
            r"{{\s*.+?\s*}}",  # Flexible spaces inside curly braces
            r"\[\s*.+?\s*\]",  # Flexible spaces inside square brackets
            r"\bDear\s+\[.*?\]",  # "Dear [Hiring Manager]"
            r"\bExcited to apply for\s+\[.*?\]",  # "Excited to apply for [Job Title]"
            r"We have an exciting opportunity open with the\s+\[.*?\]"  # "We have an exciting opportunity with [Department]"
        ]

       

        # Add weights for new categories
        self.category_weights = {
            'scam_promises': 0.8,
            'recruitment_scam_phrases': 0.7,
            'suspicious_job_titles': 0.6,
            'suspicious_requirements': 0.7,
            'urgency_pressure': 0.9,
            'suspicious_terms': 1.0,
            'informal_words': 0.5,
            'professional_elements': 0.8,
            'contact_details': 0.9,
            'experience_related': 0.7,
            'qualification_details': 0.8,
            'job_details': 0.7,
            'company_info': 0.6
        }

    def get_category_weight(self, category):
        weights = {
            'scam_promises': 0.8,
            'recruitment_scam_phrases': 0.7,
            'suspicious_job_titles': 0.6,
            'suspicious_requirements': 0.7,
            'urgency_pressure': 0.9,
            'suspicious_terms': 1.0,
            'informal_words': 0.5,
            'professional_elements': 0.8,
            'contact_details': 0.9,
            'experience_related': 0.7,
            'qualification_details': 0.8,
            'job_details': 0.7,
            'company_info': 0.6
        }
        return weights.get(category, 0.5)
    def extract_features(self, text):
        """Extracts scam-related features from a job post text."""
        if not text:
            return {}

        text = text.lower()
        features = {}

        # 🚨 Scam Indicator Counts
        for category, patterns in self.red_flags.items():
            features[f"{category}_count"] = sum(1 for pattern in patterns if pattern in text)

        # ✅ Legitimate Indicator Counts
        for category, patterns in self.legitimate_indicators.items():
            features[f"{category}_count"] = sum(1 for pattern in patterns if pattern in text)

        # 📄 Template Check
        features["is_template"] = int(self.is_template(text))

        return features


    def is_template(self, text):
        """Check if the text contains template patterns"""
        if not text:
            return False
            
        template_patterns = self.get_template_patterns(text)
        return len(template_patterns) >= 2

    def check_text(self, text):
        try:
            if not text:
                return None

            text = text.lower()
            flags_found = []
            flag_details = {}
            legitimate_indicators_found = []
            legitimate_details = {}
            
            # Check for templates first
            if self.is_template(text):
                template_patterns = self.get_template_patterns(text)
                return {
                    'result': 'TEMPLATE',
                    'flags_found': None,
                    'flag_details': None,
                    'template_patterns': template_patterns,
                    'explanation': "📄 Template Document\n\nThis is a template document for creating job postings.",
                    'confidence': "100%",
                    'is_template': True
                }

            # Check for offer letter specific validation
            if 'offer letter' in text:
                offer_verification_score = 0
                suspicious_offer_score = 0
                
                for pattern in self.legitimate_indicators['offer_letter_verification']:
                    if pattern in text:
                        offer_verification_score += 0.2
                
                for pattern in self.red_flags['suspicious_offer_patterns']:
                    if pattern in text:
                        suspicious_offer_score += 0.15
                
                if suspicious_offer_score > (offer_verification_score * 1.5):
                    return {
                        'result': 'FAKE',
                        'explanation': (
                            "❌ Suspicious Offer Letter Detected\n\n"
                            "• This message appears to be a potential scam attempting to:\n"
                            "  - Redirect to email communication\n"
                            "  - Request immediate action\n"
                            "  - Lacks proper offer letter elements\n\n"
                            "⚠️ Warning: Legitimate offer letters typically include:\n"
                            "  - Official letterhead\n"
                            "  - Reference numbers\n"
                            "  - Proper institutional details\n"
                            "  - Specific appointment details"
                        ),
                        'confidence': "85%"
                    }

            # Regular analysis
            suspicious_score = 0
            legitimate_score = 0
            
            for category, patterns in self.red_flags.items():
                matches = [pattern for pattern in patterns if pattern in text]
                if matches:
                    weight = self.get_category_weight(category)
                    flags_found.append(category)
                    flag_details[category] = matches
                    suspicious_score += (len(matches) / len(patterns)) * weight

            for category, patterns in self.legitimate_indicators.items():
                matches = [pattern for pattern in patterns if pattern in text]
                if matches:
                    weight = self.get_category_weight(category)
                    legitimate_indicators_found.append(category)
                    legitimate_details[category] = matches
                    legitimate_score += (len(matches) / len(patterns)) * weight

            total_checks = max(len(self.red_flags), len(self.legitimate_indicators))
            suspicious_score = min(suspicious_score / total_checks, 1.0)
            legitimate_score = min(legitimate_score / total_checks, 1.0)
            
            is_suspicious = suspicious_score > legitimate_score
            confidence = abs(suspicious_score - legitimate_score)
            
            explanation = self.generate_detailed_explanation(
                is_suspicious,
                suspicious_score,
                legitimate_score,
                flags_found,
                legitimate_indicators_found,
                confidence
            )
            
            return {
                'result': 'FAKE' if is_suspicious else 'REAL',
                'flags_found': flags_found,
                'flag_details': flag_details,
                'legitimate_indicators': legitimate_indicators_found,
                'legitimate_details': legitimate_details,
                'suspicious_score': suspicious_score,
                'legitimate_score': legitimate_score,
                'confidence': f"{confidence:.2%}",
                'explanation': explanation
            }

        except Exception as e:
            self.logger.error(f"Error in check_text: {e}")
            return None
        
    

    def generate_detailed_explanation(self, is_suspicious, suspicious_score, legitimate_score, flags, legitimate_indicators, confidence):
        """Generate comprehensive explanation for the analysis"""
        explanation = "🔍 Analysis Results\n\n"
        explanation += f"• Suspicious Score: {suspicious_score:.2%}\n"
        explanation += f"• Legitimate Score: {legitimate_score:.2%}\n"
        explanation += f"• Confidence: {confidence:.2%}\n\n"

        # Always show both legitimate and suspicious elements
        explanation += "✅ Legitimate Elements Found:\n"
        if legitimate_indicators:
            for indicator in legitimate_indicators:
                explanation += f"• {indicator.replace('_', ' ').title()}\n"
        else:
            explanation += "• No significant legitimate indicators found\n"

        explanation += "\n⚠️ Suspicious Elements Found:\n"
        if flags:
            for flag in flags:
                explanation += f"• {flag.replace('_', ' ').title()}\n"
        else:
            explanation += "• No significant suspicious patterns found\n"

        # Final classification
        explanation += f"\n{'❌' if is_suspicious else '✅'} Final Classification: "
        explanation += "FAKE\n" if is_suspicious else "REAL\n"
        
        if confidence < 0.3:
            explanation += "\n⚠️ Note: Low confidence prediction, manual review recommended."

        return explanation
    def get_ml_explanation(self, text, prediction, probability):
        try:
            # Get rule-based analysis
            rule_analysis = self.check_text(text)
            if not rule_analysis:
                return "Unable to generate detailed explanation."
        
            # Get rule-based scores
            rule_suspicious = float(rule_analysis.get('suspicious_score', 0))
            rule_legitimate = float(rule_analysis.get('legitimate_score', 0))
            
            # Format confidence score from ML
            ml_confidence = float(max(probability)) * 100
            
            # Combined decision logic
            is_suspicious = (
                prediction == 1 or  # ML predicts FAKE
                rule_suspicious > 0.3 or  # High suspicious score
                (rule_suspicious > rule_legitimate * 0.8 and len(rule_analysis.get('flags_found', [])) >= 2)  # Multiple red flags
            )
        
            # Generate combined explanation
            explanation = f"🤖 Combined Analysis Results\n\n"
            explanation += f"ML Model Confidence: {ml_confidence:.1f}%\n"
            explanation += f"Rule-Based Suspicious Score: {rule_suspicious:.1%}\n"
            explanation += f"Rule-Based Legitimate Score: {rule_legitimate:.1%}\n\n"
            
            # Add detailed findings
            if rule_analysis.get('flags_found'):
                explanation += "⚠️ Suspicious Elements Found:\n"
                for flag in rule_analysis['flags_found']:
                    explanation += f"• {flag.replace('_', ' ').title()}\n"
                    if flag in rule_analysis.get('flag_details', {}):
                        for detail in rule_analysis['flag_details'][flag][:3]:  # Show up to 3 examples
                            explanation += f"  - {detail}\n"
            
            # Final classification with combined logic
            explanation += f"\n{'❌' if is_suspicious else '✅'} Final Classification: "
            explanation += "FAKE" if is_suspicious else "REAL"
            
            # Add warning for conflicting results
            if prediction != (1 if rule_suspicious > rule_legitimate else 0):
                explanation += "\n\n⚠️ Note: ML and rule-based analyses show different results. Exercise caution."
            
            return explanation
        
        except Exception as e:
            self.logger.error(f"Error generating ML explanation: {e}")
            return "Error generating detailed explanation."


    def get_template_patterns(self, text):
        """Check and get template patterns from text"""
        if not text:
            return []
            
        text = text.lower()
        found_patterns = []
        
        placeholder_patterns = {
            r'\[.*?\]': 'Square bracket placeholder',
            r'\{.*?\}': 'Curly bracket placeholder',
            r'<.*?>': 'Angle bracket placeholder',
            r'\[\[.*?\]\]': 'Double square bracket',
            r'\{\{.*?\}\}': 'Double curly bracket',
            r'\(\(.*?\)\)': 'Double parenthesis',
            r'__.*?__': 'Underscore placeholder',
            r'\$\{.*?\}': 'Variable placeholder',
            r'%.*?%': 'Percent placeholder'
        }
        
        instruction_patterns = [
            r'how to write',
            r'steps? to write',
            r'guidelines? for',
            r'instructions? for',
            r'tips? for writing',
            r'example of',
            r'template for',
            r'before you send',
            r'make sure to',
            r'don\'t forget to',
            r'remember to',
            r'you should',
            r'you need to'
        ]
        
        template_indicators = [
            'insert', 'fill in', 'replace with',
            'your name', 'your company', 'your position',
            'company name', 'job title', 'position title',
            'this is a', 'this is an example',
            'sample letter', 'example letter'
        ]
        
        try:
            for pattern, description in placeholder_patterns.items():
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    found_patterns.extend([f"{description}: {match}" for match in matches])
            
            for pattern in instruction_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    found_patterns.extend([f"Instruction: {match}" for match in matches])
            
            for indicator in template_indicators:
                if indicator in text:
                    found_patterns.append(f"Indicator: {indicator}")
                    
        except Exception as e:
            self.logger.error(f"Error in get_template_patterns: {e}")
            
        return found_patterns
    