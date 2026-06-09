/**
 * AI Client Wrapper
 * Handles Groq API interactions for security analysis
 */

const Groq = require('groq-sdk');

class BedrockClient {
  constructor() {
    this.client = new Groq({
      apiKey: process.env.GROQ_API_KEY
    });
    this.model = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';
    this.maxTokens = parseInt(process.env.GROQ_MAX_TOKENS) || 2000;
    this.maxRetries = 3;
    this.retryDelay = 2000; // 2 seconds
  }

  detectPromptInjection(code) {
    if (!code) return false;
    const lowerCode = code.toLowerCase();
    const injectionPatterns = [
      'ignore previous instructions',
      'ignore all previous',
      'system prompt',
      'forget previous',
      'bypass rules',
      'jailbreak',
      'do not follow',
      'you are now',
      'disregard previous'
    ];
    return injectionPatterns.some(pattern => lowerCode.includes(pattern));
  }

  async analyzeCode({ code, language, filename }) {
    // 1. Detection: Detect injection attempts
    if (this.detectPromptInjection(code)) {
      console.warn(`[SECURITY] Prompt injection attempt detected in ${filename}`);
      return {
        risk_detected: true,
        risk_type: 'prompt_injection',
        severity: 'critical',
        explanation: 'A prompt injection attack was detected in the input code.',
        affected_lines: [],
        remediation_required: false
      };
    }

    // 2. Input: Validate and sanitize (prevent escaping the code block)
    const sanitizedCode = code.replace(/```/g, "'''");

    const prompt = this.buildAnalysisPrompt(sanitizedCode, language, filename);

    for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
      try {
        const response = await this.client.chat.completions.create({
          model: this.model,
          messages: [{ role: 'user', content: prompt }],
          temperature: 0.1,
          max_tokens: this.maxTokens,
          top_p: 0.9
        });

        const analysisText = response.choices[0].message.content;
        return this.parseAnalysisResponse(analysisText);

      } catch (error) {
        console.error(`Groq analysis error (attempt ${attempt}/${this.maxRetries}):`, error.message);
        
        // Check if it's a rate limit error
        if (error.status === 429 || error.message?.includes('429')) {
          if (attempt < this.maxRetries) {
            const delay = this.retryDelay * attempt; // Exponential backoff
            console.log(`Rate limit hit. Retrying in ${delay}ms...`);
            await this.sleep(delay);
            continue;
          }
        }
        
        // If not rate limit or last attempt, throw
        throw new Error(`Security analysis failed: ${error.message}`);
      }
    }
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  sanitizeFilename(filename) {
    // Strip everything except safe path characters to prevent prompt injection
    return filename.replace(/[^a-zA-Z0-9._\-/]/g, '_').slice(0, 100);
  }

  buildAnalysisPrompt(code, language, filename) {
    const safeFilename = this.sanitizeFilename(filename);
    return `You are a security analysis engine for GuardRail AI, a production SaaS platform.

CRITICAL SECURITY RULES TO DETECT:
1. Hardcoded secrets (API keys, passwords, tokens, private keys, JWT secrets, OAuth credentials)
2. SQL injection vulnerabilities (unsanitized user input in queries)
3. Command injection (unsanitized input in exec/spawn)
4. Path traversal (unsanitized file paths)
5. XSS vulnerabilities (innerHTML with user input)
6. Insecure cryptography (MD5, SHA1, weak algorithms)
7. Insecure random (Math.random for security)
8. Dangerous eval() usage
9. Insecure HTTP usage for sensitive data
10. Unsafe deserialization patterns

FILE INFORMATION:
- Filename: ${safeFilename}
- Language: ${language}
- Lines: ${code.split('\n').length}

CODE TO ANALYZE:
\`\`\`${language}
${code}
\`\`\`

ANALYSIS REQUIREMENTS:
- Detect ALL vulnerabilities in the code
- Return an array of ALL findings
- Extract actual secret values when found
- Identify exact line numbers for each issue
- Provide clear explanations
- Assign accurate severity levels

Return ONLY valid JSON in this exact format:
{
  "vulnerabilities": [
    {
      "risk_type": "hardcoded_secret|sql_injection|command_injection|path_traversal|xss|weak_crypto|insecure_random|eval_usage|insecure_http|unsafe_deserialization",
      "severity": "low|medium|high|critical",
      "explanation": "Clear explanation of the vulnerability",
      "affected_lines": [array of line numbers],
      "extracted_value": "the actual secret value if applicable, otherwise null"
    }
  ]
}`;
  }

  parseAnalysisResponse(text) {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      return { 
        risk_detected: false, 
        risk_type: 'none', 
        remediation_required: false 
      };
    }

    try {
      const parsed = JSON.parse(jsonMatch[0]);
      
      // Handle new array format
      if (parsed.vulnerabilities && Array.isArray(parsed.vulnerabilities)) {
        if (parsed.vulnerabilities.length === 0) {
          return { 
            risk_detected: false, 
            risk_type: 'none', 
            remediation_required: false 
          };
        }
        // Return first vulnerability for now (backward compatibility)
        const first = parsed.vulnerabilities[0];
        return {
          risk_detected: true,
          risk_type: first.risk_type,
          severity: first.severity,
          explanation: first.explanation,
          affected_lines: first.affected_lines,
          remediation_required: true,
          extracted_value: first.extracted_value,
          all_vulnerabilities: parsed.vulnerabilities
        };
      }
      
      // Handle old single format (backward compatibility)
      if (typeof parsed.risk_detected !== 'boolean') {
        throw new Error('Invalid analysis response format');
      }

      return this.filterUnsafeOutput(parsed);

    } catch (error) {
      console.error('Failed to parse AI response:', error);
      return { 
        risk_detected: false, 
        risk_type: 'none', 
        remediation_required: false 
      };
    }
  }

  redactPII(str) {
    if (typeof str !== 'string') return str;
    // Redact emails
    str = str.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]');
    // Redact standard US SSNs
    str = str.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]');
    // Redact credit cards (basic 16 digit pattern)
    str = str.replace(/\b(?:\d{4}[ -]?){3}\d{4}\b/g, '[REDACTED_CARD]');
    // Redact US phone numbers
    str = str.replace(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, '[REDACTED_PHONE]');
    return str;
  }

  sanitizeOutputString(str) {
    if (typeof str !== 'string') return str;
    // 3. Output: Filter unsafe output
    let sanitized = str.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    // Privacy protection: Detect and filter data leakage (PII)
    return this.redactPII(sanitized);
  }

  filterUnsafeOutput(parsed) {
    // 4. Rules: Enforce safety rules on output
    if (parsed.vulnerabilities && Array.isArray(parsed.vulnerabilities)) {
      parsed.vulnerabilities = parsed.vulnerabilities.map(v => ({
        ...v,
        risk_type: this.sanitizeOutputString(v.risk_type),
        severity: this.sanitizeOutputString(v.severity),
        explanation: this.sanitizeOutputString(v.explanation),
        extracted_value: this.sanitizeOutputString(v.extracted_value)
      }));
    }
    
    if (parsed.risk_type) parsed.risk_type = this.sanitizeOutputString(parsed.risk_type);
    if (parsed.severity) parsed.severity = this.sanitizeOutputString(parsed.severity);
    if (parsed.explanation) parsed.explanation = this.sanitizeOutputString(parsed.explanation);
    if (parsed.extracted_value) parsed.extracted_value = this.sanitizeOutputString(parsed.extracted_value);
    
    return parsed;
  }
}

module.exports = BedrockClient;
